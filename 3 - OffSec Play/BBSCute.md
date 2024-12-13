1. We found CuteNews CMS 2.1.2 is running as the web app which is vulnerable to RCE.
2. Use searchsploit to get the exploit 48800.py
3. Got the foothold and local.txt by executing the exploit.
4. Then checked for #sudo_privesc permissions and found hping3 #hping3_privesc can be executed as root without password.
5. Got the command from GTFObins but when executed it was not working.
6. Its because #tty shell was not there. 
7. Used python import tty command to run the tty shell.
8.  Now executed the the command and it worked.
9. We got the root shell and the root.txt flag.