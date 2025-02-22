- Nmap output
	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   2048 95:1d:82:8f:5e:de:9a:00:a8:07:39:bd:ac:ad:d3:44 (RSA)
	|   256 d7:b4:52:a2:c8:fa:b7:0e:d1:a8:d0:70:cd:6b:36:90 (ECDSA)
	|_  256 df:f2:4f:77:33:44:d5:93:d7:79:17:45:5a:a1:36:8b (ED25519)
	80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-server-header: Apache/2.4.18 (Ubuntu)
	|_http-title: Blogger | Home
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

- Gobuster directory search                        
	/.htaccess            (Status: 403) [Size: 280]
	/.hta                 (Status: 403) [Size: 280]
	/.htpasswd            (Status: 403) [Size: 280]
	/assets               (Status: 301) [Size: 319] [--> http://192.168.211.217/assets/]
	/css                  (Status: 301) [Size: 316] [--> http://192.168.211.217/css/]
	/images               (Status: 301) [Size: 319] [--> http://192.168.211.217/images/]
	/fonts                 (Status: 301) [Size: 316] [--> http://192.168.211.217/fonts/]
	/index.html           (Status: 200) [Size: 46199]
	/js                   (Status: 301) [Size: 315] [--> http://192.168.211.217/js/]
	/server-status        (Status: 403) [Size: 280]

- Checking further on /fonts directory found blog folder. Looking further into the blog folder it redirects the page into the url http://blogger.pg
- Updated the /etc/hosts file with the entry for the website dns
- Wapplyzer confirmed the CMS as WordPress.
- Using the WPscan we found the 2 user and 2 plugins.
- Tried to brute force the password for the users but it was not successful.
- Found the outdated plugin wpdiscuz 7.0.4 which vulnerable to arbitrary file upload.
- But the exploit was giving error hence tried manually into the comment section of the post.
- I had a php-reverse shell and tried to upload it but was expecting images. So I added the GIf signature GIF89a; and renamed the file php →gif. This did not give me a shell :(. I just added the GIF signature and left the file extension to .php.
- Once submitting the comment, I clicked on the shell.php (might be invisible!) and got the reverse shell. #wordpress