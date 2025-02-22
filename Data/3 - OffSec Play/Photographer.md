1. nmap result shows web app running on port 80 and 8000 and SMB port 139, 445.
2.  With smbclient found non standard share *sambashare*.
3. From the share we found mail text file and a wrodpress webapp zip.
4. From mail text we got the username and password to login into the CMS admin portal on 8000 port.
5. Found koken 0.24.22 CMS is running on port 8000 from namp scan result.
6.  A quick search show that the koken CMS version is bulnerable to arbitrary file upload.
7. Exploiting the vulns we got the foothold shell.
8. Searching for the SUID shows us #php php2.7 has SUID bit set. #suid_privesc 
9. Exploiting the SUID we got the root access.