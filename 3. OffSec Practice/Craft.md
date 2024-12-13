#windows #macro_exp #seimpersonate
nmap shows port 80 is open.
Found ODT file upload in the webpage.
Uploaded malicious ODT file with reverse shell code.
Got the reverse shell then checked the privileges and it was all okay. no misconfiguration.
Then checked the user directory and found apache users.
Then we moved to the root directory and so java, xampp not deafult folders.
xampp>htdocs contains the web server content.
We uploaded a rev shell here and executed through the browser and we got the 2nd rev shell.
Then checked the privileges and found the SeImparsonate is enabled.
Uploaeded PrintSpoofer and executed it on the machine and we got the rev shell as administrator.


Reference - https://medium.com/@Dpsypher/proving-grounds-practice-craft-4a62baf140cc