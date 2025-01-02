#Linux 

- Flatpress CMS is running at port 8089
- Searched for exploit and found this [link](https://github.com/flatpressblog/flatpress/issues/152).
- Followed the steps and we got the foothold.
- Then we checked for sudo privileges and found the user has apt-get sudo access.
- Checked on gtfobins and found this priv esc code
	- sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
- Executing the priv esc command we got the root shell.