1. Nmap scan shows web app running on port 80.
2. Got the username and pwd from the website.
	1. username from view source
	2. pwd from robots.txt
3. Though the decoded pwd seems odd but trying with the found username SSH is successful.
4. Running linpeas.sh shows that Linux kernel version is old and vulnerable.
5. Searching in searchsploit with the kernel version we got the exploit script. #vuln_kernel
6. Following the instructions on the exploit we are able to root the box.