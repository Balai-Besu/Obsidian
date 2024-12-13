1. Wordpress website hosted on port 80.
2. Tried to enumerate wp user, plugin, pwd brute force with admin account but no luck.
3. Found /secret.txt entry on robots.txt
4. On secret.txt found ssh key as base64 encoded.
5. Tried with admin but not able to login.
6. Tried with OSCP and able to login now.
7. After foothold got the **local.txt**
8. Checked for **sudo -l** but asking password
9. Checked for SUID file and found mount, #bash_privesc and others.
10. With bash SUID #suid_privesc got the root shell.