# ban-them
Find the most banned IPs from fail2ban on your server and ban them forever with IPTables.

Usage : (as root) python3 ban-them.py [-h, --help] [-v, --verbose] [-s /path/to/fail2ban.log, --source /path/to/fail2ban.log] [-n 10, --number 10]

You should run this file as root, otherwise it won't be able to access the fail2ban logs.

In order to protect your server, you should run a cron on this file (every 1 hour or more if you get a lot of attacks on your server).
