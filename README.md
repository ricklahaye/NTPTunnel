# NTPTunnel

NTPTunnel is an IP over NTP based covert channel.

The current version is experimental, may contain bugs and broken features, see the 'Known Problems' section for more information.
Only Ubuntu LTS 16.04 and Ubuntu 17.04 are supported, other distributions might work also, but no guarantees are given.

## Installation
Install required packages.

```apt install python3 python3-pip python3-venv virtualenv```

Create virtual environment.

```python3 -m venv ./venv```

Activate the virtual environment.

```source ./venv/bin/activate```

Install required Python3 packages.

```pip install -r requirements.txt```

## Running
Note that super user rights are required to run NTPTunnel as it binds to port 123.

First start the server.
```--local--addr``` indicates the global IPv4 address on which this server can be reached. The ```--tun-addr``` and ```--tun-dstaddr``` indicate the IPv4 addresses used in the tunnel.

```venv/bin/python ntptunnel.py --tun-addr=192.168.0.1 --tun-dstaddr=192.168.0.2 --local-addr=145.100.104.39 --role=server --password=os3 --tun-mtu=65440```

Then connect the client. ```--remote-addr``` is the global IPv4 address of the server.

```venv/bin/python ntptunnel.py --tun-addr=192.168.0.2 --tun-dstaddr=192.168.0.1 --local-addr=145.100.104.38 --remote-addr=145.100.104.39 --password=os3 --tun-mtu=65440```

When you get the following message on both the client and the server, the tunnel is ready for use.

```Set up tunnel.```

Then you can try to ping the other end of the tunnel, for example in case from a client with ```--tun-addr 192.168.0.2``` and a server with ```--tun-addr 192.168.0.1```:

```ping 192.168.0.1```

## Known Problems
1. Server needs to be started before client.
1. Handshake only works the first time a client connects. If the client or server disconnects, both the client and server needs to be restarted in the correct order.
1. Only one client can connect to the server at a time.
1. If you want to disable encryption you need to set the ```encryption``` flag manually in the code.
1. When no password is provided using ```--password``` the default password is used, which is ```password```.

## Credits
I do not own this code as it was written with my project partner during a University course.
