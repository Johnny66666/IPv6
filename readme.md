# Description: 
  
These are simple implementations of DECN on Linux.
We have tested TCP and DECN in the CentOS 7.5.1804 with Linux kernel 4.1.13

# Usage:

## 1.Prepare four hosts and download "CentOS 7.5.1804" and "linux-4.1.13.tar.gz"

## 2. Place all the files： 

Please put the following files or folders  ( 'sched_red.c',sched_red_mod.c','gso.sh', 'red.sh', 'Makefile')  in the same level directory.  
For example: put all the above files and folders in the folder: "DECN"

## 3.Patching the DECN
	Replace the host with the files you need to modify:
	cd DECN
	cp tcp_output.c ~/linux--4.1.13/net/ipv4/
	cp tcp_intput.c ~/linux-4.1.13/net/ipv4/
	cp tcp.h ~/linux-4.1.13/include/net/

	Replace the switch with the file you need to modify:
	cp sch_red.c ~/linux-4.1.13/net/sched/
	
## 4.Compile a new kernel for each host
	The steps to compile the new kernel are as follows:
	### 4.1 Configure the relevant library files:
		#### 4.1.1 Configuring the ncurses-devel library: yum install ncurses-devel. Otherwise, an error will be reported when executing the make menuconfig command.
		#### 4.1.2 Install gcc and make libraries: yum -y install gcc automake autoconf libtool make, otherwise execute the command: make mrproper, error: make: gcc: Command not found
		#### 4.1.3 Install bc:yum install bc, otherwise an error will be reported: bc: command not found
		#### 4.1.4 Install epel-release, otherwise an error will be reported when installing iperf.
			A. First check if the system installs epel-release:
				rpm -q epel-release, if package epel-release is not installed, it means that epel is not installed.
			B. Install epel:
				rpm-ivh http://dl.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm Install 32bit-epel or
				rpm–ivh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm Install 64bit-epel
note:
			C. rpm -q epel-release If epel-release-6-8.noarch is displayed, the epel installation is successful.
		#### 4.1.5 Installing iperf:yum install iperf
	### 4.2 Steps to compile the kernel:
		#### 4.2.1 Clean up the previous compilation traces and keep the clean source code:
				make mrproper
				make clean
				make menuconfig
		#### 4.2.2 Compiling the kernel and kernel modules:
				make clean
				make bzImage
				make modules
		#### 4.2.3 Installing the kernel module:
				make modules_install
		#### 4.2.4 Installing the Kernel:
				make install
		#### 4.2.5 Start a new kernel:
				reboot

## 5 Configure the topology:
	### 5.1 Client Configuration:
		The first client
		Ip address: 2001: db8:1::11
		Prefix: 64
		Gateway: 2001: db8:1::1
		The second client
		Ip address: 2001: db8:1::12
		Prefix: 64
		Gateway: 2001: db8:1::1
	### 5.2 Switch Configuration:
		Ens33 is the incoming network card, and ens37 is the outgoing network card.
		Ens33:
		Ip address: 2001: db8:1::1
		Prefix: 64
		Gateway: 2001: db8:1::1
		Ens37:
		Ip address: 2001: db8: 2::1
		Prefix: 64
		Gateway: 2001: db8: 2::1
	### 5.3 Server Configuration:
		Ip address: 2001: db8: 2:: 11
		Prefix: 64
		Gateway: 2001: db8: 2::1

## 6. Configuring related environment
	cd DECN
	sudo chmod gso.sh 777
	sudo ./gso.sh
	
## 7. Compile kernel module:
	cd DECN-master
	sudo chmod red.sh 777
	sudo ./red.sh
	make
    
## 8. Conduct the experiment:
	Client 1 and client 2 send the iperf stream to the server host at different times:
	Client 1: iperf -c 2001:db8:2::11 -t 60
	Client 2: iperf -c 2001:db8:2::11 -t 60
	Server: iperf –s
	The client that sent first occupies the bandwidth first, and as the incoming client joining, the bandwidth gradually converges to a fairness.
		
		
If you have any questions, please email to csu_jn@csu.edu.cn. 