#Linux 
- Nmap shows port 22 and 80 is open.
- On port 80 imagemagic is running which showing the image magic version upon uploading the image.
- Searched for the exploit for the image magic version and come across the github [link](https://github.com/ImageMagick/ImageMagick/issues/6339)
- Followed the steps and we got the foothold.
- Checked for SUID and found starce.
- Searched on gtfobins and got the prv esc command
	- `strace -o /dev/null /bin/sh -p`
- Executing the command we got root shell.