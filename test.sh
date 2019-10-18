#!/bin/bash
echo "
    This will setup two network namespaces: machine-1 & machine-2
    Machine-1 eth device will be setup to *encap* outgoing packets with a fixed MPLS header.
    Machine-2 eth device will be setup to *decap* incoming packets with a fixed MPLS header. 

    Make sure that you have tracing enabled so you'll see the debug if enabled.
    $ echo 1 > /sys/kernel/debug/tracing/tracing_on

    Once enabled you can do:
    $ sudo cat /sys/kernel/debug/tracing/trace_pipe  
"

echo "Tearing down previous net namespace machine-1"
sudo ip netns del machine-1
echo "Tearing down previous net namespace machine-2"
sudo ip netns del machine-2

echo "Creating netns for machine-1"
sudo ip netns add machine-1
echo "Creating netns for machine-2"
sudo ip netns add machine-2

echo "Creating a veth pair -- that links netns machine-1 and machine-2"
sudo ip -n machine-1 link add eth0 type veth peer name eth0 netns machine-2

echo "Turning on lo interface in machine-1"
sudo ip netns exec machine-1 ip link set lo up
echo "Turning on lo interface in machine-2"
sudo ip netns exec machine-2 ip link set lo up
echo "Adding ip 10.132.204.25/24 to eth0 in machine-1"
sudo ip netns exec machine-1 ip add add 10.132.204.25/24 dev eth0
echo "Adding ip 10.132.204.33/24 to eth0 in machine-2"
sudo ip netns exec machine-2 ip add add 10.132.204.33/24 dev eth0

echo "Turning on eth0 interface in machine-1"
sudo ip netns exec machine-1 ip link set eth0 up
echo "Turning on eth0 interface in machine-2"
sudo ip netns exec machine-2 ip link set eth0 up
echo "Turning on arp for eth0 in machine-1"
sudo ip netns exec machine-1 ip link set eth0 arp on
echo "Turning on arp for eth0 in machine-2"
sudo ip netns exec machine-2 ip link set eth0 arp on
echo "Adding default route for machine-1 via gateway which is really machine-2"
sudo ip netns exec machine-1 ip route add default via 10.132.204.33 dev eth0
echo "Adding default route for machine-2 via gateway which is really machine-1"
sudo ip netns exec machine-2 ip route add default via 10.132.204.25 dev eth0

echo "Adding default qdisc to machine-1"
sudo ip netns exec machine-1 tc qdisc add dev eth0 clsact

## Why do we use nsenter here ?
## if we did netns exec it creates a mount namespace and the bpf filesystem is unique per
## mount namespace.
## That means that when tc pins the BPF_MAP to a file in the bpf filesystem, its actually lost
## once the `netns exec` exits.
## by simply doing `nsenter` we avoid the mount namespace fiasco
echo "Adding encap filter to machine-1"
sudo nsenter --net=/var/run/netns/machine-1 tc filter add dev eth0 egress bpf da obj mpls.bpf sec mpls_encap verbose

echo "Adding default qdisc to machine-2"
sudo ip netns exec machine-2 tc qdisc add dev eth0 clsact
echo "Adding decap filter for machine-2"
sudo nsenter --net=/var/run/netns/machine-2 tc filter add dev eth0 ingress bpf da obj mpls.bpf sec mpls_decap verbose

echo "Pinging from machine-1 to machine-2"
sudo ip netns exec machine-1 ping -I 10.132.204.25 10.132.204.33