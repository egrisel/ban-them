#!/usr/bin/python3
# coding: utf-8
"""
Check the fail2ban.log and block with Iptables all IPs with too many bans
"""

import os
import sys
import stat
import subprocess
import sqlite3
import getopt
import inspect


def usage():
    """Print how to use this script."""
    print("""
BAN-THEM

Definitely ban the IPs that has been banned a lot of time by fail2ban

Usage : {} [-v --verbose] [-h --help]


OPTIONS

-v, --verbose   Verbose, let you know what the script is doing

-h, --help      Help, show you this message ;-)

-n int
--number int    The number of time an IP has been banned before being banned forever. Default is 10.

-s str
--source str    The fail2ban.log file to analyse. Default is /var/log/fail2ban.log
""".format(sys.argv[0]))


def get_script_dir(follow_symlinks=True):
    """ Get the dir of the script (found on http://stackoverflow.com/questions/3718657/how-to-properly-determine-current-script-directory-in-python). """
    if getattr(sys, 'frozen', False):
        path = os.path.abspath(sys.executable)
    else:
        path = inspect.getabsfile(get_script_dir)
    if follow_symlinks:
        path = os.path.realpath(path)
    return os.path.dirname(path)


def main(argv):
    verbose = False
    log_file = "/var/log/fail2ban.log" # the file that contain fail2ban logs
    sh_file = "{0}{1}sort-fail2ban-log.sh".format(get_script_dir(), os.path.sep) # name of the bash file to get the sorted list of banned IPs
    min_banned = 10 # minimum times the IPs has been banned
    db = "{0}{1}data.db".format(get_script_dir(), os.path.sep) # name of the sqlite3 database to keep the list of banned IPs

    try:
        opts, args = getopt.getopt(argv, "hvs:n:", ["help", "verbose", "source=", "number="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-v", "--verbose"):
            verbose = True
        elif opt in ("-s", "--source"):
            log_file = arg
            try:
                with open(log_file) as lf:
                    pass
            except IOError:
                print("ERROR: Unable to find or open the log file.")
                sys.exit(1)
        elif opt in ("-n", "--number"):
            try:
                min_banned = int(arg)
            except ValueError:
                print("Option -n, --number must be an integer.")
                usage()
                sys.exit(1)

    ips = [] # list that will contain all the IPs to ban

    # Check if the bash file to sort the fail2ban.log exists, otherwise create it
    try:
        with open(sh_file) as file:
            pass
    except IOError:
        with open(sh_file, 'w') as file:
            file.write("#!/bin/bash\n\ncat $1|grep Ban|awk '{print $5\" \"$7}'|sort|uniq -c|sort -nr\n")
            os.chmod(sh_file, stat.S_IEXEC)

    # Get the logs sorted
    try:
        logs = subprocess.check_output([sh_file, log_file])
    except subprocess.CalledProcessError:
        print("ERROR: Unable to find or open the log file.")
        sys.exit(1)
    logs = logs.decode() # decode the logs from binary to string
    logs = logs.split("\n") # split the logs in array (each line is a new field)

    for line in logs:
        l = line.strip() # remove the blanks before and after each line
        if l != "": # if line is not empty
            l = l.split() # split line in list
            l[1] = l[1].strip("[]") # remove [ and ] from the second field
            if int(l[0]) > min_banned: # if the IP has been banned more than "min_banned" time, we add the IP to our list
                ips.append([l[2], l[1], l[0]])

    # Connect to sqlite3 DB
    conn = sqlite3.connect(db)

    # Create table if not exists
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ips(
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
        ip TEXT,
        attack_type TEXT,
        quantity INTEGER
    )
    """)
    conn.commit()

    list_ip = []
    for ip in ips:
        # Verify if the IP is already registered
        cursor.execute("""SELECT id FROM ips WHERE ip=?""", (ip[0],))
        response = cursor.fetchone()
        if response is None: # IP is not registered, we register it in a temporary list
            list_ip.append((ip[0], ip[1], ip[2]))
            if verbose:
                print("Added IP : {}".format(ip[0]))

    # Insert all IPs previously selected in DB
    cursor.executemany("""
    INSERT INTO ips(ip, attack_type, quantity) VALUES(?, ?, ?)""", list_ip) # add the IPs to the database
    conn.commit()

    # Get the actual iptables rules
    ipt_list = subprocess.check_output(["/sbin/iptables", "-L", "-n"])
    ipt_list = ipt_list.decode()

    # If the Chain name doesn't already exists in IPTables, we create it
    if not 'ban-them' in ipt_list:
        subprocess.check_output(["/sbin/iptables", "-N", "ban-them"])
        subprocess.check_output(["/sbin/iptables", "-I", "INPUT", "-p", "tcp", "-m", "multiport", "--dport", "20,21,22,25,53,80,110,143,443,465,993,995,3306,8080,8081", "-j", "ban-them"])

    # Get all registered  IPs to ban all that are not already banned
    cursor.execute("""SELECT * FROM ips""")
    rows = cursor.fetchall()
    for row in rows:
        if row[1] in ipt_list: # check if the IP is already banned
            if verbose:
                print("IP {} already banned.".format(row[1]))
        else: # the IP is not banned, we ban it
            ipt_result = subprocess.check_output(["/sbin/iptables", "-A", "ban-them", "-s", row[1], "-j", "DROP"])
            if verbose:
                print("The IP {} has been banned.".format(row[1]))

    conn.close() # Close the connection to sqlite3 DB


if __name__ == "__main__":
    main(sys.argv[1:])
