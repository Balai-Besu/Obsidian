```bash
nmap -sV -p 5432 <target-ip>
nmap --script=postgres-info -p 5432 <target-ip>

nmap --script=postgres-brute -p 5432 <target-ip>

nmap --script=postgres-empty-password -p 5432 <target-ip>

nmap -sV --script=postgres* -p 5432 <target-ip>

psql -h <target-ip> -U postgres
# default creds postgres:postgres

# list db
\l

# switch db
\c <database_name>

# list tables
\dt

```