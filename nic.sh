#!/bin/bash
for i in rx tx gso gro; do ethtool -K eth0 $i off; done;
ifconfig eth0 promisc
ifconfig eth0 mtu 9000
exit 0