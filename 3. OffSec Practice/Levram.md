#Linux 
- Gerapy is running at port 8000.
- Able to login with admin:admin cred.
- Gerapy version 0.9.7 is vulnerable [Link](https://www.exploit-db.com/exploits/50640)
- Executing thr exploit we got the foothold.
- Found python with cap_setuid=ep. Searched in gtfobins and got the priv esc command.
	- `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'`
- Executing the above command we become root.