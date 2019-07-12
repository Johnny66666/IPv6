ethtool -K enp1s0f1 gro off
ethtool -K enp1s0f1 gso off
ethtool -K enp1s0f1 tso off
ethtool -K enp1s0f0 gro off
ethtool -K enp1s0f0 gso off
ethtool -K enp1s0f0 tso off
sysctl net.ipv6.conf.all.forwarding=1
systemctl stop firewalld.service
