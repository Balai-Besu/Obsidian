```bash
nmap -p 25 --script="*smtp*" 192.168.202.42

smtp-user-enum -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t 192.168.202.42

telnet IP port
> then helo anything to check response

nc -vv 192.168.120.81 25
> HELO test

# iSMTP is the Kali Linux tool which is used for testing SMTP user enumeration (RCPT TO and VRFY), internal spoofing, and relay.
ismtp -h 192.168.1.107:25 -e /root/Desktop/emails.txt
# -h <host>       The target IP and port (IP:port)
# -e <file>   Enable SMTP user enumeration testing and imports email list.
```