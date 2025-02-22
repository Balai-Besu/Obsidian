# FTP (File Transfer Protocol)
## At a Glance

**Default Port:** 21

FTP is a standard network protocol used for the transfer of files between a client and a server on a computer network. FTP is built on a client-server architecture using separate control and data connections between the client and the server. FTP authenticates users with a clear-text sign-in protocol, normally in the form of a username and password, but can connect anonymously if the server is configured to allow it. [1](https://0xffsec.com/handbook/services/ftp/#fn:1)

## Banner Grabbing 
#### Telnet 
```sh
telnet 10.0.0.3 21
```

#### Netcat

```sh
nc -n 10.0.0.3 21
```

#### banner

```sh
nmap -sV -script banner -p21 -Pn 10.0.0.3
```

#### FTP

```sh
ftp 10.0.0.3
```

## FTP Exploits Search

Refer to [Exploits Search](https://0xffsec.com/handbook/exploits-search/)

## Anonymous Login

**Note:** During the [port scanning](https://0xffsec.com/handbook/discovery-and-scanning/port-scanning/) phase Nmap’s script scan (`-sC`), can be enabled to check for [FTP Bounce](https://nmap.org/nsedoc/scripts/ftp-bounce.html) and [Anonymous Login](https://nmap.org/nsedoc/scripts/ftp-anon.html).

Try anonymous login using `anonymous:anonymous` credentials.

```sh
ftp 10.0.0.3
…
Name (10.0.0.3:kali): anonymous
331 Please specify the password.
Password: [anonymous]
230 Login successful.
```

List **all** files in order.

```sh
ftp> ls -lat
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
…
226 Directory send OK.
```

## FTP Browser Client [#](https://0xffsec.com/handbook/services/ftp/#ftp-browser-client)

**Note:** Due to its insecure nature, FTP support is being dropped by [Firefox](https://bugzilla.mozilla.org/show_bug.cgi?id=1574475) and [Google Chrome](https://chromestatus.com/feature/6246151319715840).

Try accessing `ftp://user:pass@10.0.0.3` from your browser. If not credentials provided `anonymous:anonymous` is assumed.

## Brute Forcing [#](https://0xffsec.com/handbook/services/ftp/#brute-forcing)

Refer to [FTP Brute Forcing](https://0xffsec.com/handbook/brute-forcing/#ftp)

**Note:** [SecLists](https://github.com/danielmiessler/SecLists) includes a handy list of [FTP default credentials](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt).

## Configuration files [#](https://0xffsec.com/handbook/services/ftp/#configuration-files)

Examine configuration files.[2](https://0xffsec.com/handbook/services/ftp/#fn:2)

```
ftpusers
ftp.conf
proftpd.conf
```

### Recursively Download [#](https://0xffsec.com/handbook/services/ftp/#recursively-download)
Recursively download FTP folder content.[4](https://0xffsec.com/handbook/services/ftp/#fn:4)

```sh
wget -m ftp://user:pass@10.0.0.3/
```