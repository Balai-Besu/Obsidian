#Linux 
- Nmap shows only port 22 & 80 is open.
- Running gobuster on port 80 found sites, admin, sys directories.
- Able to login with admin:admin credentials on /admin dir.
- Vulnerable to CVE-2022-31854 - https://www.exploit-db.com/exploits/50978
- Login to the admin panel and upload shell.php in Upload logo
- shell.php is uploaded at http://192.168.146.134/sites/default/assets/img/attachments/shell.php
- We have code execution as www-data.
- Found the mysql creds on config.php. 
- Reused the found cred for root and we are able to login.