#!/usr/bin/env python3
# ============================================================
#  Project      : LOG ANALYZER
#  Description  : Parses /var/log/auth.log to extract command
#                 usage and monitor authentication changes
#                 (new/deleted users, password changes, su,
#                 sudo usage and failed sudo attempts).
#  Student      : Ariel Serfaty (s15)
#  Class / Unit : TMagen773639
#  Program Code : XE105
#  Lecturer     : Tzach Azoalis
# ============================================================

import os
import sys
import subprocess

# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

# Path of the file auth.log
LOG_PATHS = ["/var/log/auth.log"]

#The Output is put in the same directory than the script in the text folder lightlogs.txt
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lightlogs.txt")


# ------------------------------------------------------------
# Display helpers
# ------------------------------------------------------------

 #Print a section header to make the report readable
def section_title(name):
    print("")
    print("=" * 70)
    print("  " + name)
    print("=" * 70)


# ------------------------------------------------------------
# Preliminary checks and log reading
#-------------------------------------------------------------


# Check the environment and return the path of a readable auth log exits with a clear message if something is wrong.
def find_log():

    # auth.log only exists on Linux systems
    if not sys.platform.startswith("linux"):
        print("[!] This script must run on Linux (detected: " + sys.platform + ").")
        sys.exit(1)

    # Return the first log file that exists and is readable
    for path in LOG_PATHS:
        if os.path.isfile(path):
            if not os.access(path, os.R_OK):
                print("[!] " + path + " exists but is not readable. Run the script with sudo.")
                sys.exit(1)
            return path

    print("[!] No authentication log found. Checked: " + ", ".join(LOG_PATHS))
    sys.exit(1)

 # Read the log once and return its lines as a list errors='ignore' protects against corrupted characters in the log.
def read_log(path):
    with open(path, "r", errors="ignore") as log_file:
        return log_file.readlines()


# ------------------------------------------------------------
# Parsing helpers
# ------------------------------------------------------------

 # Return a readable time stamp
def get_timestamp(line):
    fields = line.split()
    if fields[0][0].isdigit():
        # Keep "2026-10-15T10:28:33" and replace the T by a space
        return fields[0][:19].replace("T", " ")
    return " ".join(fields[0:3])

 # Return the user who ran the sudo command
def get_sudo_user(line):
    return line.split("sudo:", 1)[1].split(":")[0].strip()

 # Return the clean commend without the binary path
def clean_command(line):
    raw = line.split("COMMAND=", 1)[1].strip()
    parts = raw.split()
    if not parts:
        return ""
    parts[0] = os.path.basename(parts[0])
    return " ".join(parts)

# A sudo line that was REFUSED (wrong password or not in sudoers)
def is_failed_sudo(line):
    return "COMMAND=" in line and ("incorrect password attempt" in line or "NOT in sudoers" in line)

# A sudo line that was really EXECUTED.
def is_executed_command(line):
    return "COMMAND=" in line and " sudo:" in line and not is_failed_sudo(line)


# ------------------------------------------------------------
# PART 1 - Command usage
# ------------------------------------------------------------

def extract_commands(lines):
    """1.1 timestamp, 1.2 executing user, 1.3 command."""
    section_title("1. COMMAND USAGE (timestamp / executing user / command)")
    total = 0
    for line in lines:
        if is_executed_command(line):
            print("[" + get_timestamp(line) + "] " + get_sudo_user(line)
                  + " executed: " + clean_command(line))
            total += 1
    if total == 0:
        print("No command found.")
    return total


# ------------------------------------------------------------
# PART 2 - Authentication changes
# ------------------------------------------------------------

def new_users(lines):
    """2.1 Newly added users.
    We look for the SYSTEM trace 'new user:' (written by useradd),
    not for the adduser command: the trace proves the user exists."""
    section_title("2.1 NEWLY ADDED USERS")
    total = 0
    for line in lines:
        if "new user:" in line:
            # example: "name=yael, UID=1004, GID=1004, home=/home/yael, shell=/bin/bash, ..."
            info = {}
            for element in line.split("new user:", 1)[1].split(","):
                if "=" in element:
                    key, value = element.strip().split("=", 1)
                    info[key] = value
            print("[" + get_timestamp(line) + "] New user created: " + info.get("name", "?")
                  + " (UID=" + info.get("UID", "?")
                  + ", home=" + info.get("home", "?")
                  + ", shell=" + info.get("shell", "?") + ")")
            total += 1
    if total == 0:
        print("No new user found.")
    return total


def deleted_users(lines):
    """2.2 Deleted users."""
    section_title("2.2 DELETED USERS")
    total = 0
    for line in lines:
        if "delete user" in line:
            name = line.split("'")[1] if "'" in line else "?"
            print("[" + get_timestamp(line) + "] User deleted: " + name)
            total += 1
    if total == 0:
        print("No deleted user found.")
    return total


def password_changes(lines):
    """2.3 Password changes."""
    section_title("2.3 PASSWORD CHANGES")
    total = 0
    for line in lines:
        if "password changed for" in line:
            name = line.split("password changed for", 1)[1].strip()
            print("[" + get_timestamp(line) + "] Password changed for: " + name)
            total += 1
    if total == 0:
        print("No password change found.")
    return total


def su_usage(lines):
    """2.4 Use of the su command."""
    section_title("2.4 SU USAGE")
    total = 0
    for line in lines:
        if "su[" in line and "(to " in line:
            after = line.split("(to ", 1)[1]          
            target = after.split(")")[0]              
            source = after.split(")")[1].split()[0]   
            if "FAILED SU" in line:
                action = "[FAILED] [" + get_timestamp(line) + "] " + source + " tried to switch to user: "
            else:
                action = "[OK]     [" + get_timestamp(line) + "] " + source + " switched to user: "
            print(action + target)
            total += 1
    if total == 0:
        print("No su usage found.")
    return total


def sudo_usage(lines):
    """2.5 Users who used sudo, with their commands."""
    section_title("2.5 SUDO USAGE BY USER")
    by_user = {}
    for line in lines:
        if is_executed_command(line):
            user = get_sudo_user(line)
            if user not in by_user:
                by_user[user] = []
            by_user[user].append((get_timestamp(line), clean_command(line)))

    if not by_user:
        print("No sudo usage found.")
    for user, commands in by_user.items():
        print(user + " used sudo " + str(len(commands)) + " time(s):")
        for timestamp, command in commands:
            print("    [" + timestamp + "] " + command)
    return len(by_user)


def failed_sudo_alerts(lines):
    """2.6 ALERT on failed sudo attempts."""
    section_title("2.6 FAILED SUDO ATTEMPTS")
    total = 0
    for line in lines:
        if is_failed_sudo(line):
            # Reason = text between 'user :' and the first ';'
            reason = line.split("sudo:", 1)[1].split(";")[0].split(":", 1)[1].strip()
            print("ALERT! [" + get_timestamp(line) + "] " + get_sudo_user(line)
                  + " failed to use sudo (" + reason + ") - command: "
                  + clean_command(line))
            total += 1
    if total == 0:
        print("No failed sudo attempt found.")
    return total


# ------------------------------------------------------------
# Main program
# ------------------------------------------------------------

def main():
    log_path = find_log()
    lines = read_log(log_path)

    print("LOG ANALYZER - XE105")
    print("Analysed file : " + log_path + " (" + str(len(lines)) + " lines)")

    # Each function prints its section and returns how many events it found
    summary = [
        ("Commands executed with sudo", extract_commands(lines)),
        ("New users",                   new_users(lines)),
        ("Deleted users",               deleted_users(lines)),
        ("Password changes",            password_changes(lines)),
        ("su usages",                   su_usage(lines)),
        ("Users who used sudo",         sudo_usage(lines)),
        ("Failed sudo attempts",        failed_sudo_alerts(lines)),
    ]

    # Summary at the end of the report
    section_title("SUMMARY")
    for name, count in summary:
        print(name.ljust(30) + ": " + str(count))


# Runs main() only when the file is executed, not when it is imported
if __name__ == "__main__":
    # Pipe all the output into tee: shown on screen AND saved in lightlogs.txt
    tee = subprocess.Popen(["tee", OUTPUT_FILE], stdin=subprocess.PIPE, text=True)
    sys.stdout = tee.stdin
    try:
        main()
    finally:
        sys.stdout.close()
        sys.stdout = sys.__stdout__
        tee.wait()
    print("\n[+] Report saved in: " + OUTPUT_FILE)
