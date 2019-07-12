#!/bin/bash
#!/bin/sh

#close all offload function of network card
for i in enp1s0f0 enp1s0f2 enp1s0f3
do
	devName=$i
	tc qdisc del dev $devName root     2> /dev/null > /dev/null
	for j in gso gro #sg tso gso gro tx rx   #note: gro must be closed
	do
		option=$j
		ethtool -K $devName $option off
	done
done


make clean
make
rmmod sch_red.
insmod sch_red.ko

#parameters for network card
#devID=enp1s0f0
bw=1000mbit
portRate=2000mbit
portCeil=2000mbit


sysctl net.ipv4.tcp_ecn=1

iptables -F

sysctl net.ipv6.conf.all.forwarding=1

echo 1 > /proc/sys/net/ipv4/ip_forward

for devID in enp1s0f0 enp1s0f2 enp1s0f3
do
#clean existing down/up -link qdisc,hide errors  bandwidth 500000kbit probability 1.0
tc qdisc del dev $devID root     2> /dev/null > /dev/null
#tc qdisc del dev $devID ingress  2> /dev/null > /dev/null

tc qdisc add dev $devID root handle 1: red limit 64520 min 3000 max 6000 avpkt 1500 burst 5 ecn
tc qdisc add dev $devID parent 1:1 handle 10: htb default 1 r2q 140  # if rate=400M then r2q is about 300
tc class add dev $devID parent 10: classid 0:1 htb rate $portRate ceil $portCeil
done
#tc qdisc del dev enp1s0f1 root     2> /dev/null > /dev/null

echo "" > /var/log/messages
