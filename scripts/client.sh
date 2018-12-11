#!/bin/bash
. venv/bin/active
python ntptunnel.py --tun-addr=192.168.0.2 --tun-dstaddr=192.168.0.1 --local-addr=145.100.104.38 --remote-addr=145.100.104.39 --password=os3 --tun-mtu=65440
