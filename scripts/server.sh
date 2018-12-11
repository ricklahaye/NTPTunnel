#!/bin/bash
source venv/bin/activate
python ntptunnel.py --tun-addr=192.168.0.1 --tun-dstaddr=192.168.0.2 --local-addr=145.100.104.39 --role=server --password=os3 --tun-mtu=65440
