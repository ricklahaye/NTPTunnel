#!/bin/bash
tcpdump -Xn -i eno1 udp port 123 -w /home/kees/demo.pcap &
