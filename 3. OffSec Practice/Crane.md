#Linux 
- Found suite CRM is running at port 80.
- Able to login with default cred admin:admin.
- The suite crm version 7.12.3 is vulnerable to RCE.
	- GitHub exploit [link](https://github.com/manuelz120/CVE-2022-23940?tab=readme-ov-file).
- Running the exploit we got revshell as www-data.
- Running `sudo -l` shows that the user has sudo access on binary /usr/sbin/service.
- Checked on gtfobins for the priv esc command.
	- Found `sudo service ../../bin/sh` and excuted.
- Got the root shell.