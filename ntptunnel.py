"""
Based on: https://github.com/montag451/pytun/blob/master/test/test_tun.py
"""

import sys
import optparse
import socket
import select
import errno
import pytun
import math
import random
import hashlib
from time import sleep
from scapy.all import NTP, send, UDP, sniff, IP
from struct import pack, unpack
from Crypto.Cipher import AES


class TunnelServer(object):

    def __init__(self, taddr, tdstaddr, tmask, tmtu, laddr, lport, raddr,
                 rport, role, password):
        self._tun = pytun.TunTapDevice(flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
        self._tun.addr = taddr
        self._tun.dstaddr = tdstaddr
        self._tun.netmask = tmask
        self._tun.mtu = tmtu
        self._tun.up()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((laddr, lport))
        self._laddr = laddr
        self._raddr = raddr
        self._rport = rport
        self._role = role
        self._key = hashlib.sha256(password.encode('utf-8')).digest()

    def run(self):
        mtu = self._tun.mtu
        r = [self._tun, self._sock]
        w = []
        x = []
        to_tun = ''
        to_sock = ''

        # Role
        if self._role == "client":
            ntpFieldType = b'\x20\x00'
        else:
            ntpFieldType = b'\xA0\x00'

        # Set up (de)encryptors
        # FIXME use better encryption
        mode = AES.MODE_ECB
        encryptor = AES.new(self._key, mode)
        encryption = True

        while True:
            try:
                r, w, x = select.select(r, w, x)
                if self._tun in r:
                    to_sock = self._tun.read(mtu)
                if self._sock in r:
                    to_tun, addr = self._sock.recvfrom(65535)
                    if addr[0] != self._raddr or addr[1] != self._rport:
                        to_tun = ''  # drop packet
                    # Remove NTP Header and Extension Field header
                    to_tun = to_tun[52:]
                    # Get padding length
                    extensionFieldPaddingLength = unpack('!H', to_tun[:2])[0]
                    # Remove extensionFieldPaddingLength
                    to_tun = to_tun[2:]

                    if encryption:
                        # Get encryption padding length
                        encryptPaddingLength = unpack('!H', to_tun[:2])[0]
                        # Remove encryptPaddingField
                        to_tun = to_tun[2:]

                    # Remove padding
                    if extensionFieldPaddingLength > 0:
                        to_tun = to_tun[:-extensionFieldPaddingLength]

                    if encryption:
                        # Decrypt data
                        to_tun = encryptor.decrypt(to_tun)

                        # Remove encryption padding
                        if encryptPaddingLength > 0:
                            to_tun = to_tun[:-encryptPaddingLength]
                if self._tun in w:
                    self._tun.write(to_tun)
                    to_tun = ''
                if self._sock in w:
                    if encryption:
                        # Pad data until it is 16 bytes
                        encryptPaddingLength = math.ceil(len(to_sock)/16)*16 \
                                                        - len(to_sock)
                        encryptPaddingField = pack('!H', encryptPaddingLength)

                        # Encrypt data
                        to_sock = encryptor.encrypt(to_sock + b'\x00' *
                                                    encryptPaddingLength)
                    else:
                        encryptPaddingField = b''

                    # Lengths
                    extensionFieldHeaderLength = 4
                    extensionFieldHeaderPaddingLength = 2
                    payloadLength = (len(to_sock) +
                                     extensionFieldHeaderLength +
                                     extensionFieldHeaderPaddingLength)
                    extensionFieldPaddingLength = (math.ceil(payloadLength/4)
                                                   * 4 - payloadLength)
                    # Calculate padding length
                    fieldPaddingLength = pack('!H',
                                              extensionFieldPaddingLength)
                    # Random padding
                    padding = bytes([random.randint(0, 255) for i in
                                    range(0, extensionFieldPaddingLength)])
                    # NTP header extension field length
                    ntpFieldLength = pack('!H', payloadLength +
                                          extensionFieldPaddingLength)

                    # NTP header
                    if self._role == "client":
                        ntpHeader = bytes(NTP(leap=3,
                                              version=4,
                                              mode=3,
                                              stratum=0,
                                              poll=3,
                                              precision=250,
                                              delay=1,
                                              dispersion=1,
                                              id="",
                                              ref=0,
                                              orig=0,
                                              recv=0,
                                              sent=None))
                    else:
                        ntpHeader = bytes(NTP(leap=0,
                                              version=4,
                                              mode=4,
                                              stratum=2,
                                              poll=3,
                                              precision=236,
                                              delay=(0.1*random.random()),
                                              dispersion=(0.002 +
                                                          0.001 *
                                                          random.random()),
                                              id=self._laddr,
                                              ref=None,
                                              orig=None,
                                              recv=None,
                                              sent=None))

                    # Build encapsulated packet
                    encapsulatedPacket = (ntpHeader +
                                          ntpFieldType +
                                          ntpFieldLength +
                                          fieldPaddingLength +
                                          encryptPaddingField +
                                          to_sock +
                                          padding)
                    self._sock.sendto(encapsulatedPacket,
                                      (self._raddr, self._rport))
                    to_sock = ''
                r = []
                w = []
                if to_tun:
                    w.append(self._tun)
                else:
                    r.append(self._sock)
                if to_sock:
                    w.append(self._sock)
                else:
                    r.append(self._tun)
            except (select.error, socket.error, pytun.Error) as e:
                if e == errno.EINTR:
                    continue
                print(str(e))
                break


def main():
    parser = optparse.OptionParser()
    parser.add_option('--tun-addr', dest='taddr',
                      help='set tunnel local address')
    parser.add_option('--tun-dstaddr', dest='tdstaddr',
                      help='set tunnel destination address')
    parser.add_option('--tun-netmask', default='255.255.255.0', dest='tmask',
                      help='set tunnel netmask')
    parser.add_option('--tun-mtu', type='int', default=1500, dest='tmtu',
                      help='set tunnel MTU')
    parser.add_option('--local-addr', default='0.0.0.0', dest='laddr',
                      help='set local address [%default]')
    parser.add_option('--remote-addr', dest='raddr',
                      help='set remote address [%default]')
    parser.add_option('--role', default='client', dest='role',
                      help='set role client or server [%default]')
    parser.add_option('--password', default='password', dest='password',
                      help='set password used to encrypt [%default]')
    opt, args = parser.parse_args()
    ntpPort = 123
    if not (opt.taddr and opt.tdstaddr):
        parser.print_help()
        return 1
    # The client has to specify a remote address
    if opt.role == "client" and not opt.raddr:
        parser.print_help()
        return 1
    try:
        ntpFieldLength = b'\x00\x12'
        ntpFieldTypeRequest = b'\xFF\x00'
        ntpFieldTypeResponse = b'\x00\xFF'
        padding = b'\xFF' * 16

        if(opt.role == "client"):
            # Send tunnel request
            ntpHeader = bytes(NTP(leap=3,
                                  version=4,
                                  mode=3,
                                  stratum=0,
                                  poll=3,
                                  precision=250,
                                  delay=1,
                                  dispersion=1,
                                  id="",
                                  ref=0,
                                  orig=0,
                                  recv=0,
                                  sent=None))

            # Build encapsulated packet
            encapsulatedPacket = IP(dst=opt.raddr, src=opt.laddr)/UDP(sport=ntpPort,dport=ntpPort)/ \
                                  (ntpHeader +
                                  ntpFieldTypeRequest +
                                  ntpFieldLength +
                                  padding)
            print("Sending tunnel request to %s." % (opt.raddr))
            send(encapsulatedPacket)

            # Wait for tunnel response coming in
            print("Waiting for reply.")
            while True:
                # Wait for tunnel request coming in
                packet = sniff(filter="udp port 123", count=1)

                # Check if it is a tunnel request
                if packet[0]["IP"]["UDP"]["NTP"]["Raw"].load[:2] == ntpFieldTypeResponse:
                    break

            # Set up tunnel
            print("Set up tunnel.")
            server = TunnelServer(opt.taddr, opt.tdstaddr, opt.tmask, opt.tmtu,
                                  opt.laddr, ntpPort, opt.raddr, ntpPort, opt.role,
                                  opt.password)

        else:
            print("Waiting for request.")
            requestAddress = None
            while requestAddress == None:
                # Wait for tunnel request coming in
                packet = sniff(filter="udp port 123", count=1)

                # Check if it is a tunnel request
                if packet[0]["IP"]["UDP"]["NTP"]["Raw"].load[:2] == ntpFieldTypeRequest:
                    requestAddress = packet[0]["IP"].src
                    print("Got request from %s." % (requestAddress))
                    break

            # We need to sleep for a second here to wait for the sniffer 
            # to start at the client side.
            sleep(1)

            # Send response to requestAddress
            ntpHeader = bytes(NTP(leap=0,
                                  version=4,
                                  mode=4,
                                  stratum=2,
                                  poll=3,
                                  precision=236,
                                  delay=(0.1*random.random()),
                                  dispersion=(0.002 +
                                              0.001 *
                                              random.random()),
                                  id=opt.laddr,
                                  ref=None,
                                  orig=None,
                                  recv=None,
                                  sent=None))

            # Build encapsulated packet
            encapsulatedPacket = IP(dst=requestAddress, src=opt.laddr)/UDP(sport=ntpPort,dport=ntpPort)/(ntpHeader + ntpFieldTypeResponse + ntpFieldLength + padding)
            print("Sending response to %s." % (requestAddress))
            send(encapsulatedPacket)

            # Set up tunnel
            print("Set up tunnel.")
            server = TunnelServer(opt.taddr, opt.tdstaddr, opt.tmask, opt.tmtu,
                                  opt.laddr, ntpPort, requestAddress, ntpPort, opt.role,
                                  opt.password)
    except (pytun.Error, socket.error) as e:
        print >> sys.stderr, str(e)
        return 1
    server.run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
