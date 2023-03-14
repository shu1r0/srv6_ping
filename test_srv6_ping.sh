#!/usr/bin/env bash

if [[ $(id -u) -ne 0 ]] ; then echo "Please run with sudo" ; exit 1 ; fi

set -e

./tests/netns_network_examples/simple/linear_4hosts.sh -c 
ip netns exec ns4 ip -6 route add 2001:db8:10::1/128 encap seg6 mode inline segs 2001:db8:30::1,2001:db8:20::1 dev ns4_ns3
ip netns exec ns1 python3 -m unittest discover tests/
ip netns exec ns1 srv6ping -d 2001:db8:30::2 -s 2001:db8:10::2,2001:db8:20::2 -c 3
./tests/netns_network_examples/simple/linear_4hosts.sh -d