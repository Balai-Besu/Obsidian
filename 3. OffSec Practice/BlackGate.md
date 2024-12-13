#Linux 

- Nmap scan shows only port 22 and 6379 (redis) is open.
- After searching and trying some exploit we found this one working https://github.com/n0b0dyCN/redis-rogue-server
- Got the foothold by following the steps as described by the author.
- Priv esc is reverse engineering with buffer overflow hence ignored.