#Linux 

- Nmap shows ZeroMQ ZMTP 2.0 is running at port `4505`
- After searching and trying couple of exploit we have found this is not working. 
- Further enumerating we found the response contains an interesting header, revealing that a SaltStack Rest API is listening on that port:
```
 X-Upstream: salt-api/3000-1
```
- Searching for salt stack api exploit we found https://github.com/dozernz/cve-2020-11651
- Following the steps as written by the author we were able to get the foothold with the root access. 