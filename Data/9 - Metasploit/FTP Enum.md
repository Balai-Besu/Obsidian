
```
use auxiliary/scanner/ftp/ftp_version
use auxiliary/scanner/ftp/ftp_login

set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt

use auxiliary/scanner/ftp/anonymous
```