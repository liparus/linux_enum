#! /bin/bash

#
#
# Linux Enumeration Script AKA printf & echo festival!
#


# Script Colors

NC='\033[0m'          # No color
GREEN='\033[1;32m'
BLUE='\033[1;34m'
GRAY='\033[0;36m'
RED='\033[0;31m'

OUTFILE=$1		# NOT IN USE


_KODINFO() {

	# Kernel, OS & Device Information
	
	echo ""
	printf "${GRAY}====================================================${NC}\n"
	echo ""

	printf "${GREEN}Kernel, OS & Device Information${NC}\n"
	
	echo ""
	echo ""	
	printf "${BLUE}All available system information:${NC}\n"
	uname -a 2>&1
	echo ""

	printf "${BLUE}Kernel release:${NC}\n"
	uname -r 2>&1
	echo ""

	printf "${BLUE}System hostname:${NC}\n"
	uname -n 2>&1
	echo ""

	printf "${BLUE}Linux kernel architecture:${NC}\n"
	uname -m 2>&1
	echo ""

	printf "${BLUE}Kernel information:${NC}\n"
	cat /proc/version 2>&1
	printf "\n\n"

	printf "${BLUE}Distribution information:${NC}\n"
	cat /etc/*-release 2>&1
	printf "\n\n"

	printf "${BLUE}CPU information:${NC}\n"
	cat /proc/cpuinfo 2>&1
	printf "\n\n"

	printf "${BLUE}Filesystem information:${NC}\n"
	df -ah 2>&1
	echo ""
	printf "${GRAY}====================================================${NC}\n"
	printf "\n\n"

} > 1_OUT.txt



_USRGRP() {

	# Users & Groups Informatioin
	
	printf "${GRAY}====================================================${NC}\n"
	echo ""

	printf "${GREEN} Users & Groups Information${NC}\n"
	printf "\n\n"
	printf "${BLUE}All users on the system & user hashes (privileged):${NC}\n"
	cat /etc/shadow 2>&1
	echo ""

	printf "${BLUE}All groups on the system:${NC}\n"
	cat /etc/group 2>&1
	echo ""

	printf "${BLUE}All uid's and respective group memberships:${NC}\n"
	for i in $(cat /etc/passwd 2>&1 | cut -d"." -f1 \
			2>&1); do id $i; done 2>&1
	echo ""

	printf "${BLUE}List all superuser accounts:${NC}\n"
	grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1 }' 2>&1
	echo ""

	printf "${BLUE}Users currently logged in:${NC}\n"
	users 2>&1
	echo ""

	printf "${BLUE}Who is currently logged in and what they're doing:${NC}\n"
	w 2>&1
	echo ""

	printf "${BLUE}List of last logged on users:${NC}\n"
	last 2>&1
	echo ""

	printf "${BLUE}Entire list of previously logged on users:${NC}\n"
	lastlog |grep -v "Never" 2>&1
	echo ""
	printf "${GRAY}==================================================:${NC}\n"
	printf "\n\n"

} > 2_OUT.txt


_USRPRIV() {

	# User & Privilege Information
	
	echo ""
	printf "${GRAY}====================================================${NC}\n"
	echo""

	printf "${GREEN}User & Privilege information${NC}\n"
	printf "\n\n"

	printf "${BLUE}Current username:${NC}\n"
	whoami 2>&1
	echo ""

	printf "${BLUE}Current user information:${NC}\n"
	id 2>&1
	echo ""

	printf "${BLUE}Can the current user perform anything as root:${NC}\n"
	sudo -l 2>&1
	echo ""

	printf "${BLUE}Can user run any interesting binaries as Root:${NC}\n"
	sudo -l 2>/dev/null |grep -w 'nmap|perl|'awk'|'find'|'bash'|'sh'|'man'|'more'|'less'|'vi'|'vim'|'nc'|'ncat'|'netcat'|python|ruby|lua|irb' | xargs -r ls -la 2>/dev/null
	echo ""

	printf "${GRAY}====================================================${NC}\n"
	printf "\n\n"

} > 3_OUT.txt


_ENVINFO() {

	# Environmental Information

	echo ""
	printf "${GRAY}====================================================${NC}\n"
	echo ""

	printf "${GREEN}Environmental Information${NC}\n"
	printf "\n\n"


	printf "${BLUE}Display environmental variables:${NC}\n"
	env 2>&1
	echo ""

	printf "${BLUE}Path information:${NC}\n"
	echo $PATH 2>&1
	echo ""

	printf "${BLUE}History of current user (${RED}saved in separate file output_history.txt${NC}):${NC}\n"
	history >> output_history.txt
	echo ""

	printf "${BLUE}Default system variables:${NC}\n"
	cat /etc/profile 2>&1
	echo ""

	printf "${BLUE}Available Shells:${NC}\n"
	cat /etc/shells 2>&1
	echo ""

	printf "${GRAY}====================================================${NC}\n"
	printf "\n\n"

} > 4_OUT.txt


_INTFILES() {

	# Interesting Files

	echo ""
	printf "${GRAY}====================================================${NC}\n"
	echo ""

	printf "${GREEN}List Interesting Files${NC}\n"
	printf "\n\n"

	printf "${BLUE}Find SUID files:${NC}\n"
	find / -perm -4000 -type f 2>&1
	echo ""

	printf "${BLUE}Find SUID files owned by root:${NC}\n"
	find / -uid 0 -perm -4000 -type f 2>&1
	echo ""

	printf "${BLUE}Find GUID files:${NC}\n"
	find / -perm -2000 -type f 2>&1
	echo ""

	printf "${BLUE}Find world-writeable files:${NC}\n"
	find / -perm -2 -type f 2>&1
	echo ""

	printf "${BLUE}Find world-writeable files excluding those in /proc:${NC}\n"
	find / ! -path "*/proc/*" -perm -2 -type f -print 2>&1
	echo ""

	printf "${BLUE}Find world-writeable directories:${NC}\n"
	find / -perm -2 -type d 2>&1
	echo ""

	printf "${BLUE}Find rhost config files:${NC}\n"
	find /home -name *.rhosts -print 2>&1
	echo ""

	printf "${BLUE}Find .plan files, list permissions, file ocntents:${NC}\n"
	find /home -iname *.plan -exec ls -la {} ; -exec cat {} 2>&1
	echo ""

	printf "${BLUE}Find hosts.equiv, list permissions, file contents:${NC}\n"
	find /etc -iname hosts.equiv -exec ls -la {} 2>&1
	echo ""

	printf "${BLUE}Possible access to other user directories:${NC}\n"
	ls -ahlR /root/ 2>&1
	echo ""

	printf "${BLUE}Current users command history:${NC}\n"
	cat ~/.bash_history 2>&1
	echo ""

	printf "${BLUE}Current users various history files:${NC}\n"
	ls -la ~/.*_history 2>&1
	echo ""

	printf "${BLUE}Possible root history files:${NC}\n"
	ls -la /root/.*_history 2>&1
	echo ""

	printf "${BLUE}Check ssh files in current users directory:${NC}\n"
	ls -la ~/.ssh/ 2>&1
	echo ""

	printf "${BLUE}SSH keys/host information:${NC}\n"
	find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls -la
	echo ""

	printf "${BLUE}Check configuration of inetd services:${NC}\n"
	ls -la /usr/sbin/in.* 2>&1
	echo ""

	printf "${BLUE}Check log files for kywords ('pass'):${NC}\n"
	grep -l -i pass /var/log/*.log 2>&1
	echo ""

	printf "${BLUE}List files in specified directory (/var/log/):${NC}\n"
	find /var/log -type f -exec ls -la {} ; 2>&1
	echo ""

	printf "${BLUE}List .log files in specified directory (/var/log):${NC}\n"
	find /var/log -name *.log -type f -exec ls -la {} ; 2>&1
	echo ""

	printf "${BLUE}List .conf files in /etc (recursive 1 level):${NC}\n"
	find /etc/ -maxdepth 1 -name  *.conf -type f -exec grep -Hn password {} ; 2>&1
	echo ""

	printf "${BLUE}List open files (${RED}output depends on privileges):${NC}\n"
	lsof -i -n 2>&1
	echo ""

	printf "${BLUE}Can we read root mail:${NC}\n"
	head /var/mail/root 2>&1
	echo ""

	printf "${GRAY}====================================================${NC}\n"
	printf "\n\n"

} > 5_OUT.txt

_SRVINFO() {

	# Servive Information

	echo ""
	printf "${GRAY}====================================================${NC}\n"
	echo ""

	printf "${GREEN}Service Information${NC}\n"
	printf "\n\n"

	printf "${BLUE}Services running as root:${NC}\n"
	ps aux |grep root 2>&1
	echo ""

	printf "${BLUE}Process binary path and permissions:${NC}\n"
	ps aux | awk '{print $11}' |xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>&1
	echo ""

	printf "${BLUE}Services managed by inetd:${NC}\n"
	cat /etc/inetd.conf 2>&1
	echo ""

	printf "${BLUE}Premissions and contents of /etc/exports(${RED}NFS):${NC}\n"
	ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>&1
	echo ""

	printf "${GRAY}====================================================${NC}\n"
	printf "\n\n"

} > 6_OUT.txt


_JOBTASK() {

	# Jobs / Tasks

	echo ""
	printf "${GRAY}====================================================${NC}\n"
	echo ""

	printf "${GREEN}Jobs and Tasks${NC}\n"
	printf "\n\n"

	printf "${BLUE}Cheduled jobs for the specified user (Privileged):${NC}\n"
	crontab -l -u %username% 2>&1
	echo ""

	printf "${BLUE}Cheduled jobs overview (hourly,daily,monthly etc):${NC}\n"
	ls -la /etc/cron* 2>&1
	echo ""

	printf "${BLUE}What can others write in /etc/cron directories:${NC}\n"
	ls -aRl /etc/cron* | awk '$1 ~ /w.$/' 2>&1
	echo ""

	printf "${GRAY}====================================================${NC}\n"
	printf "\n\n"

} > 7_OUT.txt


_ROUTING() {

	# Network, Routing & Communications

	echo ""
	printf "${GREEN}Networking, Routing & Communications${NC}\n"
	echo ""

	printf "${BLUE}List all network interfaces:${NC}\n"
	/sbin/ifconfig -a 2>&1
	cat /etc/network/interfaces 2>&1
	ip a 2>&1
	echo ""

	printf "${BLUE}ARP communications:${NC}\n"
	arp -a 2>&1
	echo ""

	printf "${BLUE}Route information:${NC}\n"
	route 2>&1 
	ip route 2>&1
	echo ""

	printf "${BLUE}Configured DNS server addresses:${NC}\n"
	cat /etc/resolv.conf 2>&1
	echo ""

	printf "${BLUE}All TCP sockets and related PIDs (-p privileged):${NC}\n"
	netstat -antp 2>&1
	ss -antp 2>&1
	echo ""

	printf "${BLUE}All UDP sockets and related PIDs (-p privileged:${NC}\n"
	netstat -anup 2>&1
	ss -anup 2>&1
	echo ""

	printf "${BLUE}List rules (Privileged):${NC}\n"
	iptables -L 2>&1
	echo ""

	#printf "${BLUE}Port numers / services mappings:${NC}\n"
	#cat /etc/services 2>&1
	#echo ""

	printf "${GRAY}====================================================${NC}\n"
	printf "\n\n"

} > 8_OUT.txt

_PROGS() {

	# Programs Installed

	echo ""
	printf "${GREEN}Programs Installed${NC}\n"
	echo ""

	printf "${BLUE}Installed packages:(${RED}DEBIAN${NC}):${NC}\n"
	dpkg -l 2>&1
	echo ""

	printf "${BLUE}Installed packages:(${RED}RED HAT${NC}):${NC}\n"
	rpm -ga 2>&1
	echo ""

	printf "${BLUE}Sudo version:${NC}\n"
	sudo -v 2>&1
	echo ""

	printf "${BLUE}Apache version:${NC}\n"
	httpd -v 2>&1
	echo ""

	printf "${BLUE}Loaded Apache modules:${NC}\n"
	apache2ctl -M && apachectl -M 2>&1
	echo ""

	printf "${BLUE}MYSQL version details:${NC}\n"
	mysql --version 2>&1
	echo ""

	printf "${BLUE}Installed POSTGRES version details:${NC}\n"
	psql -V 2>&1
	echo ""

	printf "${BLUE}Installed Perl version:${NC}\n"
	perl -v 2>&1
	echo ""

	printf "${BLUE}Installed Java version:${NC}\n"
	java --version 2>&1
	echo ""

	printf "${BLUE}Installed Python version:${NC}\n"
	python --version 2>&1
	echo ""

	printf "${BLUE}Installed Ruby version:${NC}\n"
	ruby -v 2>&1
	echo ""

	printf "${BLUE}List available compilers:${NC}\n"
	dpkg --list 2>&1 |grep compiler |grep -v decompiler 2>&1 && yum list installed 'gcc*' 2>&1 |grep gcc 2>&1
	echo ""

	printf "${BLUE}Which account is Apache running as:${NC}\n"
	cat /etc/apache2/envvars 2>&1 |grep -i 'user|group' |awk '{sub(/.*export /,"")}1'
	echo ""

	printf "${GRAY}====================================================${NC}\n"
	printf "$\n\n"

} > 9_OUT.txt

_CSES() {

	# Common Shell Escape Sequences

	echo ""
	printf "${GREEN}Common Shell Escape Sequences${NC}\n"
	echo ""

	printf ":!bash (${RED}vi, vim${NC})\n"
	printf ":set shell=/bin/bash:shell (${RED}vi, vim${NC})\n"
	printf "!bash (${RED}man, more, less${NC})\n"
	printf "find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}, ; (${RED}find${NC})\n"
	printf "perl -e 'exec "/bin/bash";' (${RED}perl${NC})\n"
	printf "python -c 'import pty; pty.spawn("/bin/bash")' (${RED}python${NC})\n"
	echo ""
} > 10_OUT.txt



# MAIN

printf "\n\n"
printf "${RED}**********************************************${NC}\n"
printf "${GREEN}UNSTABLE LINUX ENUMERATION MEGA FUN FESTIVAL!!${NC}\n"
printf "${RED}**********************************************${NC}\n"
printf "\n\n"

echo "YOU CAN DO IT ZEMBO!: "
echo "---------------------"
printf "\n"

echo "1) Kernel, OS & Device Information"
echo "2) Users & Groups Information"
echo "3) User & Privilege Information"
echo "4) Environmental Information"
printf "5) Interesting Files (${RED}NOTHING USEFUL WITHOUT PASSWD..${NC})\n"
echo "6) Service Information"
echo "7) Jobs & Tasks"
echo "8) Network, Routing & Communications"
echo "9) Installed Programs"
echo "10) Common Shell Escape Sequences"
echo "11) Exit"
echo ""
printf "${RED}!NOTE!${NC} If password is asked and you don't have it, just pres Enter as many times as needed, for the fat logs!\n\n"

echo "Selection: "

while :
do
	read SELECT
	case $SELECT in
		1)
			_KODINFO
			printf "${GREEN}File 1_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		2)
			_USRGRP
			printf "${GREEN}File 2_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		3)
			_USRPRIV
			printf "${GREEN}File 3_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		4)
			_ENVINFO
			printf "${GREEN}File 4_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		5)
			_INTFILES
			printf "${GREEN}File 5_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		6)
			_SRVINFO
			printf "${GREEN}File 6_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		7)
			_JOBTASK
			printf "${GREEN}File 7_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		8)
			_ROUTING
			printf "${GREEN}File 8_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		9)
			_PROGS
			printf "${GREEN}File 9_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		10)
			_CSES
			printf "${GREEN}File 10_OUT.txt created${NC}\n"
			echo ""
			echo "Selection:"
			;;
		11)
			break
			;;
		*)
			echo "DUDE! Numbers 1-11! Focus!"
			;;
	esac
done

printf "${GREEN}BYE!${NC}\n"
