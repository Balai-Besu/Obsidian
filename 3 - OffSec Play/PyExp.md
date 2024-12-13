1. nmap result shows port 3306 and 1337.
2. SSH is running on port 1337 from nmap script scan result.
3. Brute force mysql login using hydra.
	1. Got the username and pwd. root:prettywomen
4. After login with the cred we found fernet table.
5. Fernet is an symmetric encryption using cryptography algo in python.
6. Decrypting the string with the key we got the username and pwd.
7. Logged into server with SSH on port 1337 with the new cred.
8. Sudo -l provide us the command we can run as sudo.
9. We saw /opt/exp.py we can execute as root which execute the command we provide.
10. Exploiting the execute instruction we got the root shell.
	1. import pty; pty.spawn('/bin/bash')