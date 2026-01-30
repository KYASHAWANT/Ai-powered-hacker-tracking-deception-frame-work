import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
import time
import random
import re
import shlex
from io import StringIO
from analysis import analyze_session
import json
from pathlib import Path
from datetime import datetime
import csv
import os
import tempfile
# import pwd
# import grp
import subprocess
import sys

# Basic configuration / constants
SSH_BANNER = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-20.04"
HOST = "0.0.0.0"
PORT = 2222
USERNAME = "admin"
PASSWORD = "password"
COMMAND_TIMEOUT = 40  # Changed from 300 to 40 seconds for inactivity timeout
SESSION_DURATION_LIMIT = 600  # Changed from 1800 to 600 seconds (10 minutes)
MAX_LOGIN_ATTEMPTS = 5
HOSTNAME = "prod-web01"
MAX_SAME_PASSWORD_ATTEMPTS = 3
MAX_SAME_USERNAME_ATTEMPTS = 3
SUSPICIOUS_PATTERN_THRESHOLD = 3
SESSION_TERMINATION_DELAY = 2

# Ensure we keep logs under a dedicated directory to avoid permission errors
LOGS_DIR = "AI_powered_Hacker_tracking_and_deception_framework/logs"
ATTACKER_FILES_DIR = 'attacker_files'
CSV_LOG_FILE = os.path.join(LOGS_DIR, 'ssh_audit.csv')
CSV_MAX_FILE_SIZE = 10 * 1024 * 1024
CSV_BACKUP_COUNT = 5

# Ensure directories exist (safe and idempotent)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(ATTACKER_FILES_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(os.path.join(LOGS_DIR, 'ssh_audit.log'), maxBytes=10 * 1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ssh_honeypot")

# Enhanced fake filesystem with realistic structure
FAKE_FS = {
    '/': {
        'type': 'dir',
        'contents': ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib64', 'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var'],
        'perms': 'drwxr-xr-x',
        'owner': 'root',
        'group': 'root',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/home': {
        'type': 'dir',
        'contents': ['admin', 'user', 'guest'],
        'perms': 'drwxr-xr-x',
        'owner': 'root',
        'group': 'root',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/home/admin': {
        'type': 'dir',
        'contents': ['.bashrc', '.bash_history', '.profile', '.ssh', 'documents', 'downloads', 'public_html', 'scripts'],
        'perms': 'drwxr-x---',
        'owner': 'admin',
        'group': 'admin',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/home/admin/.bashrc': {
        'type': 'file',
        'content': """# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\\s*[0-9]+\\s*//;s/[;&|]\\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

PS1='${debian_chroot:+($debian_chroot)}\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '
""",
        'perms': '-rw-r--r--',
        'owner': 'admin',
        'group': 'admin',
        'size': 3771,
        'modified': '2024-01-15 10:00:00'
    },
    '/home/admin/.bash_history': {
        'type': 'file',
        'content': """ls -la
cd /var/www/html
sudo apt update
sudo systemctl status apache2
cat /etc/passwd
ps aux | grep apache
netstat -tuln
whoami
history
""",
        'perms': '-rw-------',
        'owner': 'admin',
        'group': 'admin',
        'size': 210,
        'modified': '2024-01-15 10:00:00'
    },
    '/home/admin/documents': {
        'type': 'dir',
        'contents': ['notes.txt', 'todo.md', 'report.pdf'],
        'perms': 'drwxr-xr-x',
        'owner': 'admin',
        'group': 'admin',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/home/admin/documents/notes.txt': {
        'type': 'file',
        'content': """Important Notes:
1. Backup scheduled daily at 2 AM
2. Monitor disk usage - /var is at 78%
3. Update SSL certificates by end of month
4. Check MySQL replication status
5. Review firewall rules""",
        'perms': '-rw-r--r--',
        'owner': 'admin',
        'group': 'admin',
        'size': 245,
        'modified': '2024-01-15 10:00:00'
    },
    '/home/admin/scripts': {
        'type': 'dir',
        'contents': ['backup.sh', 'monitor.py', 'cleanup.log'],
        'perms': 'drwxr-xr-x',
        'owner': 'admin',
        'group': 'admin',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/home/admin/scripts/backup.sh': {
        'type': 'file',
        'content': """#!/bin/bash
# Backup script for web server
BACKUP_DIR="/backups/web"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/web_backup_$DATE.tar.gz /var/www/html
echo "Backup completed: $BACKUP_DIR/web_backup_$DATE.tar.gz"
""",
        'perms': '-rwxr-xr-x',
        'owner': 'admin',
        'group': 'admin',
        'size': 230,
        'modified': '2024-01-15 10:00:00'
    },
    '/etc': {
        'type': 'dir',
        'contents': ['passwd', 'shadow', 'group', 'hosts', 'hostname', 'resolv.conf', 'ssh', 'crontab', 'fstab', 'apt'],
        'perms': 'drwxr-xr-x',
        'owner': 'root',
        'group': 'root',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/etc/passwd': {
        'type': 'file',
        'content': """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
admin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash
mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false
redis:x:113:119::/var/lib/redis:/usr/sbin/nologin
docker:x:114:120:Docker User,,,:/var/lib/docker:/usr/sbin/nologin
""",
        'perms': '-rw-r--r--',
        'owner': 'root',
        'group': 'root',
        'size': 2300,
        'modified': '2024-01-15 10:00:00'
    },
    '/etc/shadow': {
        'type': 'file',
        'content': """root:*:18959:0:99999:7:::
daemon:*:18959:0:99999:7:::
bin:*:18959:0:99999:7:::
sys:*:18959:0:99999:7:::
sync:*:18959:0:99999:7:::
games:*:18959:0:99999:7:::
man:*:18959:0:99999:7:::
lp:*:18959:0:99999:7:::
mail:*:18959:0:99999:7:::
news:*:18959:0:99999:7:::
uucp:*:18959:0:99999:7:::
proxy:*:18959:0:99999:7:::
www-data:*:18959:0:99999:7:::
backup:*:18959:0:99999:7:::
list:*:18959:0:99999:7:::
irc:*:18959:0:99999:7:::
gnats:*:18959:0:99999:7:::
nobody:*:18959:0:99999:7:::
systemd-network:*:18959:0:99999:7:::
systemd-resolve:*:18959:0:99999:7:::
systemd-timesync:*:18959:0:99999:7:::
messagebus:*:18959:0:99999:7:::
syslog:*:18959:0:99999:7:::
_apt:*:18959:0:99999:7:::
tss:*:18959:0:99999:7:::
uuidd:*:18959:0:99999:7:::
tcpdump:*:18959:0:99999:7:::
landscape:*:18959:0:99999:7:::
pollinate:*:18959:0:99999:7:::
sshd:*:18959:0:99999:7:::
systemd-coredump:!!:18959::::::
admin:$6$rounds=656000$V4M2X1XwYFZJkDf0$X5Jz7v8Qz3q9Q1w2E3r4T5y6U7i8O9p0A1S2D3F4G5H6J7K8L9Z0X1C2V3B4N5M:18959:0:99999:7:::
mysql:!:18959:0:99999:7:::
redis:!:18959:0:99999:7:::
docker:!:18959:0:99999:7:::
""",
        'perms': '-rw-r-----',
        'owner': 'root',
        'group': 'shadow',
        'size': 1800,
        'modified': '2024-01-15 10:00:00'
    },
    '/etc/hosts': {
        'type': 'file',
        'content': """127.0.0.1	localhost
127.0.1.1	prod-web01

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
""",
        'perms': '-rw-r--r--',
        'owner': 'root',
        'group': 'root',
        'size': 221,
        'modified': '2024-01-15 10:00:00'
    },
    '/var': {
        'type': 'dir',
        'contents': ['www', 'log', 'lib', 'tmp', 'backups'],
        'perms': 'drwxr-xr-x',
        'owner': 'root',
        'group': 'root',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/var/www': {
        'type': 'dir',
        'contents': ['html'],
        'perms': 'drwxr-xr-x',
        'owner': 'root',
        'group': 'root',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/var/www/html': {
        'type': 'dir',
        'contents': ['index.html', 'style.css', 'app.js', 'config.php', 'uploads'],
        'perms': 'drwxr-xr-x',
        'owner': 'www-data',
        'group': 'www-data',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/var/www/html/index.html': {
        'type': 'file',
        'content': """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Production Web Server</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Welcome to Production Web Server</h1>
        <p>Server is running and operational.</p>
        <div class="status">
            <p><strong>Status:</strong> <span class="online">Online</span></p>
            <p><strong>Uptime:</strong> 45 days, 12:34:56</p>
            <p><strong>Load Average:</strong> 0.12, 0.08, 0.05</p>
        </div>
    </div>
</body>
</html>""",
        'perms': '-rw-r--r--',
        'owner': 'www-data',
        'group': 'www-data',
        'size': 650,
        'modified': '2024-01-15 10:00:00'
    },
    '/var/www/html/config.php': {
        'type': 'file',
        'content': """<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'webapp');
define('DB_PASS', 'p@ssw0rd123!');
define('DB_NAME', 'production_db');

// Application settings
define('DEBUG_MODE', false);
define('MAINTENANCE_MODE', false);
define('SESSION_TIMEOUT', 3600);

// API Keys (keep secure)
define('API_KEY', 'sk_live_51Hj8k2L5p9q7r4t6y8u0i1o2a3s4d5f6g7h8');
define('SECRET_KEY', 'sec_8h7g6f5d4s3a2o1i0u9y8t7r6e5w4q3');

// Email settings
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_USER', 'admin@company.com');
define('SMTP_PASS', 'EmailPass123!');

// File upload settings
define('MAX_UPLOAD_SIZE', 5242880); // 5MB
define('ALLOWED_EXTENSIONS', ['jpg', 'png', 'pdf', 'docx']);
?>""",
        'perms': '-rw-r-----',
        'owner': 'www-data',
        'group': 'www-data',
        'size': 950,
        'modified': '2024-01-15 10:00:00'
    },
    '/var/log': {
        'type': 'dir',
        'contents': ['auth.log', 'syslog', 'apache2', 'mysql'],
        'perms': 'drwxr-xr-x',
        'owner': 'root',
        'group': 'root',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/var/log/auth.log': {
        'type': 'file',
        'content': """Jan 15 08:30:01 prod-web01 sshd[1234]: Accepted password for admin from 192.168.1.100 port 54322 ssh2
Jan 15 08:45:23 prod-web01 sshd[1235]: Failed password for invalid user root from 203.0.113.5 port 45678 ssh2
Jan 15 09:12:47 prod-web01 sshd[1236]: Accepted publickey for admin from 10.0.0.50 port 33445 ssh2
Jan 15 10:30:15 prod-web01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update
Jan 15 11:45:33 prod-web01 sshd[1237]: Connection closed by 192.168.1.100 port 54322 [preauth]
""",
        'perms': '-rw-r-----',
        'owner': 'root',
        'group': 'adm',
        'size': 680,
        'modified': '2024-01-15 10:00:00'
    },
    '/root': {
        'type': 'dir',
        'contents': ['.bashrc', '.profile', '.ssh', 'scripts', 'backups'],
        'perms': 'drwx------',
        'owner': 'root',
        'group': 'root',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/tmp': {
        'type': 'dir',
        'contents': [],
        'perms': 'drwxrwxrwt',
        'owner': 'root',
        'group': 'root',
        'size': 4096,
        'modified': '2024-01-15 10:00:00'
    },
    '/proc': {
        'type': 'dir',
        'contents': ['cpuinfo', 'meminfo', 'version', 'uptime'],
        'perms': 'dr-xr-xr-x',
        'owner': 'root',
        'group': 'root',
        'size': 0,
        'modified': '2024-01-15 10:00:00'
    },
    '/proc/cpuinfo': {
        'type': 'file',
        'content': """processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 158
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
stepping	: 1
microcode	: 0x1
cpu MHz		: 2399.998
cache size	: 35840 KB
physical id	: 0
siblings	: 2
core id		: 0
cpu cores	: 2
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 20
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single fsgsbase avx2 invpcid rdseed clflushopt
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit
bogomips	: 4799.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 158
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
stepping	: 1
microcode	: 0x1
cpu MHz		: 2399.998
cache size	: 35840 KB
physical id	: 0
siblings	: 2
core id		: 1
cpu cores	: 2
apicid		: 1
initial apicid	: 1
fpu		: yes
fpu_exception	: yes
cpuid level	: 20
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single fsgsbase avx2 invpcid rdseed clflushopt
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit
bogomips	: 4799.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:
""",
        'perms': '-r--r--r--',
        'owner': 'root',
        'group': 'root',
        'size': 2800,
        'modified': '2024-01-15 10:00:00'
    },
    '/proc/meminfo': {
        'type': 'file',
        'content': """MemTotal:        4046636 kB
MemFree:          567892 kB
MemAvailable:    2023340 kB
Buffers:          123456 kB
Cached:          1456789 kB
SwapCached:            0 kB
Active:          1234567 kB
Inactive:         987654 kB
Active(anon):     567890 kB
Inactive(anon):   123456 kB
Active(file):     666677 kB
Inactive(file):   864198 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
Dirty:               123 kB
Writeback:             0 kB
AnonPages:        567890 kB
Mapped:           234567 kB
Shmem:             12345 kB
KReclaimable:      56789 kB
Slab:             123456 kB
SReclaimable:      98765 kB
SUnreclaim:        24691 kB
KernelStack:        5678 kB
PageTables:        12345 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     4120464 kB
Committed_AS:    1234567 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       56789 kB
VmallocChunk:          0 kB
Percpu:              456 kB
HardwareCorrupted:     0 kB
AnonHugePages:    123456 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
FileHugePages:         0 kB
FilePmdMapped:         0 kB
CmaTotal:              0 kB
CmaFree:               0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
DirectMap4k:      123456 kB
DirectMap2M:     3456789 kB
DirectMap1G:           0 kB
""",
        'perms': '-r--r--r--',
        'owner': 'root',
        'group': 'root',
        'size': 2200,
        'modified': '2024-01-15 10:00:00'
    }
}

# Expanded malware patterns
MALWARE_PATTERNS = [
    r"(wget|curl)\s+(http|https|ftp)://.*(\.sh|\.py|\.pl)\s*-[oO]",
    r"chmod\s+[+]x",
    r"(bash|sh|zsh|dash)\s+-[ic]",
    r"python\d?\s+-c",
    r"perl\s+-e",
    r"rm\s+-rf",
    r"mkfifo",
    r"/dev/(tcp|udp)/",
    r"nc\s+.*(-l|-v|-p|-e)",
    r"(exec|eval)\s+",
    r"echo\s+.*\s*>\s*/",
    r"\./.*\.(sh|py|pl)",
    r"sudo\s+.*(apt|yum|dnf|pip|npm)",
    r"useradd|adduser|usermod",
    r"passwd\s+.*--stdin",
    r"ssh-keygen\s+-t\s+rsa",
    r"cat\s+>/etc/crontab",
    r"chattr\s+[+]i",
    r"mysql\s+-u\s+root\s+-p[^\s]*\s+-e",
    r"docker\s+(run|exec)\s+.*(--privileged|-v\s+/:/host)",
    r"crontab\s+-l.*>",
    r"tar\s+.*\|\s*bash",
    r"base64\s+-d.*\|\s*bash",
    r"powershell\s+-e",
    r"set\s+interface\s+.*\s+monitor",
    r"tcpdump\s+-i\s+.*\s+-w",
    r"hydra|nmap|sqlmap|metasploit",
    r"cat\s+.*\.(key|pem|p12|pfx)",
    r"find\s+.*-perm\s+-4000",
    r"\.\./\.\./\.\./",
    r"cat\s+/proc/self/environ",
    r"env\s+.*\s*=\s*.*",
    r"export\s+.*=.*",
    r"LD_PRELOAD|LD_LIBRARY_PATH"
]

IMMEDIATE_TERMINATION_PATTERNS = [
    r"rm\s+-rf\s+/\s*",
    r"dd\s+if=/dev/random",
    r">/dev/sda",
    r"mkfs\\.",
    r":\(\)\{\s*:\|\\:&\s*\};:",
    r"chmod\s+-R\s+000\s+/",
    r">/proc/sysrq-trigger",
    r"echo\s+1\s*>\s*/proc/sys/kernel/sysrq",
    r":\s*{\s*:\s*\|:\s*&\s*};",
    r"cat\s+/dev/urandom",
    r"kill\s+-9\s+-1",
    r"halt|poweroff|reboot\s+-f",
    r"echo\s+.*>\s*/sys/",
    r"mount\s+.*\s+/mnt.*\s+-o\s+remount,rw",
]

FAKE_PROCESSES = [
    {"pid": 1, "name": "systemd", "user": "root", "cpu": "0.1", "mem": "0.5", "cmd": "/sbin/init"},
    {"pid": 100, "name": "sshd", "user": "root", "cpu": "0.3", "mem": "1.2", "cmd": "/usr/sbin/sshd -D"},
    {"pid": 101, "name": "bash", "user": "admin", "cpu": "0.5", "mem": "0.8", "cmd": "-bash"},
    {"pid": 200, "name": "apache2", "user": "www-data", "cpu": "2.1", "mem": "5.7", "cmd": "/usr/sbin/apache2 -k start"},
    {"pid": 201, "name": "mysql", "user": "mysql", "cpu": "3.2", "mem": "12.4", "cmd": "/usr/sbin/mysqld"},
    {"pid": 300, "name": "docker", "user": "root", "cpu": "0.7", "mem": "3.5", "cmd": "/usr/bin/dockerd -H fd://"},
    {"pid": 301, "name": "redis-server", "user": "redis", "cpu": "0.4", "mem": "2.1", "cmd": "/usr/bin/redis-server 127.0.0.1:6379"},
    {"pid": 400, "name": "cron", "user": "root", "cpu": "0.0", "mem": "0.3", "cmd": "/usr/sbin/cron -f"},
    {"pid": 401, "name": "rsyslogd", "user": "root", "cpu": "0.1", "mem": "0.9", "cmd": "/usr/sbin/rsyslogd -n"},
    {"pid": 500, "name": "bash", "user": "root", "cpu": "0.2", "mem": "0.6", "cmd": "-bash"},
    {"pid": 600, "name": "python3", "user": "admin", "cpu": "1.2", "mem": "4.3", "cmd": "python3 /opt/monitor.py"},
]

VULNERABLE_SUDO = {
    "admin": [
        "(ALL) NOPASSWD: /usr/bin/apt",
        "(ALL) NOPASSWD: /usr/bin/docker",
        "(ALL) NOPASSWD: /usr/bin/crontab",
        "(ALL) NOPASSWD: /usr/bin/systemctl",
        "(ALL) NOPASSWD: /usr/bin/service",
        "(ALL) NOPASSWD: /usr/bin/ufw",
    ]
}

class CSVLogger:
    def __init__(self, filename=CSV_LOG_FILE):
        self.filename = filename
        self._ensure_header()

    def _ensure_header(self):
        """Ensure CSV file has proper headers."""
        header = [
            'timestamp', 'event_type', 'session_id', 'client_ip',
            'username', 'password', 'command', 'status', 'is_root', 
            'details', 'duration_seconds', 'attempt_count', 'pattern_type'
        ]
        if not os.path.exists(self.filename):
            try:
                with open(self.filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(header)
            except PermissionError as e:
                logger.error(f"CSV_HEADER_WRITE_FAILED - Permission denied for {self.filename}: {e}")
                fallback = os.path.join(tempfile.gettempdir(), f"ssh_audit_fallback_{int(time.time())}.csv")
                try:
                    with open(fallback, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(header)
                    logger.warning(f"CSV logger falling back to {fallback}")
                    self.filename = fallback
                except Exception as e2:
                    logger.critical(f"Failed to create fallback CSV file: {e2}")

    def _rotate_if_needed(self):
        """Rotate CSV file if it becomes too large"""
        try:
            if os.path.exists(self.filename) and os.path.getsize(self.filename) > CSV_MAX_FILE_SIZE:
                base_name = self.filename.replace('.csv', '')
                for i in range(CSV_BACKUP_COUNT - 1, 0, -1):
                    old_file = f"{base_name}.{i}.csv"
                    new_file = f"{base_name}.{i+1}.csv"
                    if os.path.exists(old_file):
                        if os.path.exists(new_file):
                            os.remove(new_file)
                        os.rename(old_file, new_file)
                os.rename(self.filename, f"{base_name}.1.csv")
                self._ensure_header()
        except Exception as e:
            logger.error(f"CSV_ROTATE_FAILED - {e}")

    def log_event(self, **kwargs):
        """Log event to CSV with all relevant fields"""
        self._rotate_if_needed()
        default_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': '',
            'session_id': '',
            'client_ip': '',
            'username': '',
            'password': '',
            'command': '',
            'status': '',
            'is_root': '',
            'details': '',
            'duration_seconds': '',
            'attempt_count': '',
            'pattern_type': ''
        }
        default_data.update(kwargs)
        row = [
            default_data['timestamp'],
            default_data['event_type'],
            default_data['session_id'],
            default_data['client_ip'],
            default_data['username'],
            default_data['password'],
            default_data['command'],
            default_data['status'],
            default_data['is_root'],
            default_data['details'],
            default_data['duration_seconds'],
            default_data['attempt_count'],
            default_data['pattern_type']
        ]
        try:
            with open(self.filename, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(row)
        except PermissionError as e:
            logger.error(f"CSV_WRITE_FAILED - Permission denied for {self.filename}: {e}")
            fallback = os.path.join(tempfile.gettempdir(), f"ssh_audit_fallback_{int(time.time())}.csv")
            try:
                with open(fallback, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(row)
                logger.warning(f"Wrote CSV row to fallback file {fallback}")
                self.filename = fallback
            except Exception as e2:
                logger.critical(f"Failed to write CSV log to fallback file: {e2}")
        except Exception as e:
            logger.error(f"CSV_WRITE_FAILED - {e}")

csv_logger = CSVLogger()

class SecurityMonitor:
    def __init__(self, client_ip, session_id):
        self.client_ip = client_ip
        self.session_id = session_id
        self.failed_passwords = {}
        self.failed_usernames = {}
        self.suspicious_patterns = {}
        self.termination_reason = None

    def track_failed_password(self, password):
        """Track failed password attempts"""
        if password in self.failed_passwords:
            self.failed_passwords[password] += 1
        else:
            self.failed_passwords[password] = 1
        if self.failed_passwords[password] >= MAX_SAME_PASSWORD_ATTEMPTS:
            self.termination_reason = f"Repeated failed password: {password}"
            logger.warning(f"REPEATED_PASSWORD_ATTEMPT - SessionID: {self.session_id} - IP: {self.client_ip} - Password: {password} - Count: {self.failed_passwords[password]}")
            csv_logger.log_event(
                event_type='REPEATED_PASSWORD_ATTEMPT',
                session_id=self.session_id,
                client_ip=self.client_ip,
                password=password,
                details=f"Password: {password}",
                attempt_count=str(self.failed_passwords[password])
            )
            return True
        return False

    def track_failed_username(self, username):
        """Track failed username attempts"""
        if username in self.failed_usernames:
            self.failed_usernames[username] += 1
        else:
            self.failed_usernames[username] = 1
        if self.failed_usernames[username] >= MAX_SAME_USERNAME_ATTEMPTS:
            self.termination_reason = f"Repeated failed username: {username}"
            logger.warning(f"REPEATED_USERNAME_ATTEMPT - SessionID: {self.session_id} - IP: {self.client_ip} - Username: {username} - Count: {self.failed_usernames[username]}")
            csv_logger.log_event(
                event_type='REPEATED_USERNAME_ATTEMPT',
                session_id=self.session_id,
                client_ip=self.client_ip,
                username=username,
                attempt_count=str(self.failed_usernames[username])
            )
            return True
        return False

    def track_suspicious_pattern(self, pattern_type, command=None):
        """Track suspicious patterns"""
        if pattern_type in self.suspicious_patterns:
            self.suspicious_patterns[pattern_type] += 1
        else:
            self.suspicious_patterns[pattern_type] = 1
        if self.suspicious_patterns[pattern_type] >= SUSPICIOUS_PATTERN_THRESHOLD:
            self.termination_reason = f"Repeated suspicious pattern: {pattern_type}"
            logger.warning(f"REPEATED_SUSPICIOUS_PATTERN - SessionID: {self.session_id} - IP: {self.client_ip} - Pattern: {pattern_type} - Count: {self.suspicious_patterns[pattern_type]} - Command: {command}")
            csv_logger.log_event(
                event_type='REPEATED_SUSPICIOUS_PATTERN',
                session_id=self.session_id,
                client_ip=self.client_ip,
                pattern_type=pattern_type,
                command=command,
                attempt_count=str(self.suspicious_patterns[pattern_type])
            )
            return True
        return False

    def check_immediate_termination(self, command):
        """Check for commands that warrant immediate termination"""
        cmd_lower = command.lower()
        for pattern in IMMEDIATE_TERMINATION_PATTERNS:
            if re.search(pattern, cmd_lower):
                self.termination_reason = f"Immediate termination pattern: {pattern}"
                logger.critical(f"IMMEDIATE_TERMINATION_TRIGGERED - SessionID: {self.session_id} - IP: {self.client_ip} - Pattern: {pattern} - Command: {command}")
                csv_logger.log_event(
                    event_type='IMMEDIATE_TERMINATION_TRIGGERED',
                    session_id=self.session_id,
                    client_ip=self.client_ip,
                    pattern_type=pattern,
                    command=command,
                    details="Dangerous command detected"
                )
                return True
        return False

    def should_terminate(self):
        """Check if session should be terminated"""
        return self.termination_reason is not None

class FakeShell:
    def __init__(self, channel, client_ip, username, password):
        self.channel = channel
        self.client_ip = client_ip
        self.cwd = '/home/admin'
        self.start_time = time.time()
        self.last_activity = time.time()
        self.session_active = True
        self.is_root = False
        self.username = username
        self.password = password
        self.command_history = []
        self.ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.ssh_socket.settimeout(1)
        except Exception:
            pass
        self.session_id = f"{client_ip}_{int(time.time())}"
        self.security_monitor = SecurityMonitor(client_ip, self.session_id)
        self.created_files = []
        self.created_dirs = []
        self.processes = FAKE_PROCESSES.copy()
        
        # Track created directories in session
        self.session_created_dirs = []
        
        # Initialize with some default files in the attacker's directory
        self._init_attacker_directory()
        
        # Log session start
        logger.info(f"SESSION_START - IP: {client_ip} - SessionID: {self.session_id} - Username: {username} - Password: {password}")
        csv_logger.log_event(
            event_type='SESSION_START',
            session_id=self.session_id,
            client_ip=self.client_ip,
            username=self.username,
            password=self.password
        )

    def _init_attacker_directory(self):
        """Initialize attacker directory with some default files"""
        default_files = {
            'readme.txt': """Welcome to the production server.

This server hosts critical web applications and databases.
Please follow security guidelines when making changes.

Authorized personnel only.
""",
            'todo.md': """# Server Maintenance Tasks

## High Priority
1. Update SSL certificates (expires 2024-02-01)
2. Patch OpenSSL vulnerability
3. Review firewall rules

## Medium Priority
1. Monitor disk usage
2. Backup verification
3. Log rotation cleanup

## Low Priority
1. Update documentation
2. Performance tuning
""",
            'server_info.txt': """Server Information:
Hostname: prod-web01
OS: Ubuntu 20.04.3 LTS
Kernel: 5.4.0-91-generic
CPU: 2 x Intel Xeon E5-2680 v4
Memory: 4GB
Storage: 50GB SSD
IP Address: 192.168.1.100
Gateway: 192.168.1.1
DNS: 8.8.8.8, 8.8.4.4
"""
        }
        
        for filename, content in default_files.items():
            self.save_attacker_file(filename, content, file_type="default")

    def _get_current_dir_contents(self):
        """Get contents of current directory from FAKE_FS and session created directories"""
        contents = []
        
        # Get contents from FAKE_FS for current directory
        if self.cwd in FAKE_FS:
            contents.extend(FAKE_FS[self.cwd]['contents'])
        else:
            # If current directory is not in FAKE_FS, check if it's a parent of any FAKE_FS paths
            for path in FAKE_FS:
                if path.startswith(self.cwd + '/') and path != self.cwd:
                    # Get the immediate child
                    relative_path = path[len(self.cwd):].lstrip('/')
                    next_part = relative_path.split('/')[0]
                    if next_part and next_part not in contents:
                        contents.append(next_part)
        
        # Add session created directories that are immediate children of current directory
        for dir_path in self.session_created_dirs:
            parent = os.path.dirname(dir_path)
            if parent == self.cwd:
                dir_name = os.path.basename(dir_path)
                if dir_name not in contents:
                    contents.append(dir_name)
        
        return sorted(list(set(contents)))

    def _get_file_info(self, path):
        """Get file information from FAKE_FS or created files"""
        # Check if it's a created file
        for filepath in self.created_files:
            if filepath.endswith(path):
                return {
                    'type': 'file',
                    'content': self._read_created_file(filepath),
                    'perms': '-rw-r--r--',
                    'owner': self.username,
                    'group': self.username,
                    'size': len(self._read_created_file(filepath)),
                    'modified': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
        
        # Check if it's a created directory
        for dirpath in self.session_created_dirs:
            if dirpath == path:
                return {
                    'type': 'dir',
                    'contents': [],
                    'perms': 'drwxr-xr-x',
                    'owner': self.username,
                    'group': self.username,
                    'size': 4096,
                    'modified': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
        
        # Check FAKE_FS
        if path in FAKE_FS:
            return FAKE_FS[path]
        
        return None

    def _read_created_file(self, filepath):
        """Read content of a created file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except:
            return ""

    def save_attacker_file(self, filename, content, file_type="created"):
        """Save attacker-created file to disk"""
        try:
            if not os.path.exists(ATTACKER_FILES_DIR):
                os.makedirs(ATTACKER_FILES_DIR, exist_ok=True)
            
            safe_filename = f"{self.session_id}_{filename.replace('/', '_')}"
            if not os.path.splitext(safe_filename)[1]:
                safe_filename += ".txt"
            
            file_path = os.path.join(ATTACKER_FILES_DIR, safe_filename)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"# File {file_type} by attacker\n")
                f.write(f"# Session ID: {self.session_id}\n")
                f.write(f"# IP: {self.client_ip}\n")
                f.write(f"# Username: {self.username}\n")
                f.write(f"# Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"# Original filename: {filename}\n")
                f.write("# Content:\n")
                f.write(content or "")
            
            self.created_files.append(file_path)
            
            logger.info(f"ATTACKER_FILE_{file_type.upper()} - SessionID: {self.session_id} - IP: {self.client_ip} - File: {filename} - Saved as: {safe_filename}")
            csv_logger.log_event(
                event_type=f'ATTACKER_FILE_{file_type.upper()}',
                session_id=self.session_id,
                client_ip=self.client_ip,
                username=self.username,
                details=f"Filename: {filename}, Saved as: {safe_filename}",
                command=(content or "")[:200]
            )
            return True
        except Exception as e:
            logger.error(f"FAILED_TO_SAVE_FILE - SessionID: {self.session_id} - IP: {self.client_ip} - Error: {str(e)}")
            return False

    def terminate_session(self, reason):
        """Terminate the session with a reason"""
        duration = time.time() - self.start_time
        logger.warning(f"SESSION_TERMINATION - SessionID: {self.session_id} - IP: {self.client_ip} - Reason: {reason}")
        csv_logger.log_event(
            event_type='SESSION_TERMINATION',
            session_id=self.session_id,
            client_ip=self.client_ip,
            username=self.username,
            password=self.password,
            details=reason,
            duration_seconds=str(round(duration, 2)),
            is_root=str(self.is_root)
        )
        try:
            self.channel.send(f"\r\n\r\n*** SECURITY ALERT: {reason} ***\r\n")
            self.channel.send("*** Your session has been terminated for security reasons. ***\r\n")
        except:
            pass
        time.sleep(SESSION_TERMINATION_DELAY)
        self.session_active = False

    def log_keystroke(self, key, context="command"):
        """Log individual keystrokes"""
        try:
            if key in ['\r', '\n']:
                display_key = '[ENTER]'
            elif key == '\x7f':
                display_key = '[BACKSPACE]'
            elif key == '\t':
                display_key = '[TAB]'
            elif key in ['\x1b', '\x03']:
                display_key = '[CTRL_C]' if key == '\x03' else '[ESC]'
            elif len(key) == 1 and ord(key) < 32:
                display_key = f'[CTRL_{chr(ord(key) + 64)}]'
            else:
                display_key = key
            logger.info(f"KEYSTROKE - SessionID: {self.session_id} - IP: {self.client_ip} - Context: {context} - Key: {display_key}")
        except:
            pass

    def log_command(self, command, blocked=False):
        """Log executed commands"""
        status = "BLOCKED" if blocked else "EXECUTED"
        logger.info(f"COMMAND - SessionID: {self.session_id} - IP: {self.client_ip} - User: {self.username} - Command: {command} - Status: {status} - Root: {self.is_root}")
        csv_logger.log_event(
            event_type='COMMAND_EXECUTION',
            session_id=self.session_id,
            client_ip=self.client_ip,
            username=self.username,
            password=self.password,
            command=command,
            status=status,
            is_root=str(self.is_root)
        )

    def check_timeout(self):
        """Check if session has timed out"""
        # Check for inactivity timeout (40 seconds)
        if time.time() - self.last_activity > COMMAND_TIMEOUT:
            logger.warning(f"SESSION_TIMEOUT - IP: {self.client_ip} - SessionID: {self.session_id} - Inactivity: {time.time() - self.last_activity:.1f}s")
            csv_logger.log_event(
                event_type='SESSION_TIMEOUT',
                session_id=self.session_id,
                client_ip=self.client_ip,
                username=self.username,
                password=self.password,
                details=f"Inactive for {time.time() - self.last_activity:.1f} seconds"
            )
            self.channel.send(f"\r\nSession timed out after {COMMAND_TIMEOUT} seconds of inactivity\r\n")
            return True
            
        # Check for total session duration limit (10 minutes)
        if time.time() - self.start_time > SESSION_DURATION_LIMIT:
            logger.warning(f"SESSION_LIMIT_REACHED - IP: {self.client_ip} - SessionID: {self.session_id} - Duration: {time.time() - self.start_time:.1f}s")
            csv_logger.log_event(
                event_type='SESSION_LIMIT_REACHED',
                session_id=self.session_id,
                client_ip=self.client_ip,
                username=self.username,
                password=self.password,
                details=f"Session lasted {time.time() - self.start_time:.1f} seconds"
            )
            self.channel.send(f"\r\nSession duration limit of {SESSION_DURATION_LIMIT//60} minutes reached\r\n")
            return True
        return False

    def detect_malware(self, cmd):
        """Detect suspicious patterns"""
        cmd_lower = (cmd or "").lower()
        for pattern in MALWARE_PATTERNS:
            if re.search(pattern, cmd_lower):
                logger.warning(f"MALICIOUS_COMMAND - SessionID: {self.session_id} - IP: {self.client_ip} - Command: {cmd}")
                csv_logger.log_event(
                    event_type='MALICIOUS_COMMAND_DETECTED',
                    session_id=self.session_id,
                    client_ip=self.client_ip,
                    username=self.username,
                    password=self.password,
                    command=cmd,
                    pattern_type=pattern,
                    details="Malware pattern detected"
                )
                if self.security_monitor.track_suspicious_pattern("malware_detected", cmd):
                    self.terminate_session("Repeated malware pattern detection")
                    return True
                return True
        return False

    def fake_sudo(self, cmd):
        """Emulate sudo prompt handling"""
        if "sudo" in (cmd or ""):
            if not self.is_root:
                self.channel.send(f"[sudo] password for {self.username}: ")
                password = ""
                while True:
                    if self.channel.recv_ready():
                        char = self.channel.recv(1).decode(errors='ignore')
                        self.log_keystroke(char, "sudo_password")
                        if char in ('\r', '\n'):
                            break
                        password += char
                        self.channel.send("*")
                    else:
                        time.sleep(0.05)
                    if self.check_timeout():
                        return False
                
                logger.info(f"SUDO_ATTEMPT - SessionID: {self.session_id} - IP: {self.client_ip} - Password: {password}")
                csv_logger.log_event(
                    event_type='SUDO_ATTEMPT',
                    session_id=self.session_id,
                    client_ip=self.client_ip,
                    username=self.username,
                    password=password,
                    details=f"Password: {password}"
                )
                
                if password == self.password:
                    self.is_root = True
                    logger.info(f"SUDO_SUCCESS - SessionID: {self.session_id} - IP: {self.client_ip}")
                    csv_logger.log_event(
                        event_type='SUDO_SUCCESS',
                        session_id=self.session_id,
                        client_ip=self.client_ip,
                        username=self.username,
                        password=self.password,
                        is_root=str(self.is_root)
                    )
                    self.channel.send("\r\n")
                    return True
                else:
                    logger.warning(f"SUDO_FAILED - SessionID: {self.session_id} - IP: {self.client_ip}")
                    csv_logger.log_event(
                        event_type='SUDO_FAILED',
                        session_id=self.session_id,
                        client_ip=self.client_ip,
                        username=self.username,
                        password=password
                    )
                    if self.security_monitor.track_failed_password(password):
                        self.terminate_session("Repeated failed sudo password attempts")
                    self.channel.send("\r\nSorry, try again.\r\n")
                    return False
            else:
                return True
        return True

    def handle_command(self, cmd):
        """Top-level command handler"""
        if self.security_monitor.should_terminate():
            self.terminate_session(self.security_monitor.termination_reason)
            return
            
        if self.security_monitor.check_immediate_termination(cmd):
            self.terminate_session("Dangerous command detected")
            return
            
        self.last_activity = time.time()
        self.command_history.append(cmd)
        self.log_command(cmd)
        
        if self.detect_malware(cmd):
            self.log_command(cmd, blocked=True)
            self.channel.send("\r\nCommand contains suspicious patterns and was blocked\r\n")
            return
            
        if not self.fake_sudo(cmd):
            return
            
        cmd = cmd.replace("sudo", "").strip()
        
        # Enhanced command routing
        if cmd == "exit" or cmd == "logout":
            self.session_active = False
            self.channel.send("\r\nlogout\r\n")
            
        elif cmd == "whoami":
            self.channel.send(f"\r\n{self.username}\r\n")
            
        elif cmd == "id":
            uid = "0" if self.is_root else "1000"
            self.channel.send(f"uid={uid}({self.username}) gid=1000({self.username}) groups=1000({self.username})\r\n")
            
        elif cmd.startswith("ls"):
            self.handle_ls(cmd)
            
        elif cmd.startswith("cd"):
            self.handle_cd(cmd)
            
        elif cmd.startswith("cat "):
            self.handle_cat(cmd)
            
        elif cmd.startswith("echo "):
            self.handle_echo(cmd)
            
        elif cmd == "pwd":
            self.channel.send(f"\r\n{self.cwd}\r\n")
            
        elif cmd.startswith("uname"):
            self.handle_uname(cmd)
            
        elif cmd.startswith("ps"):
            self.handle_ps(cmd)
            
        elif cmd in ["ifconfig", "ip a", "ip addr"]:
            self.handle_network()
            
        elif cmd.startswith("netstat"):
            self.handle_netstat(cmd)
            
        elif cmd == "history":
            self.handle_history()
            
        elif cmd in ["clear", "reset", "cls"]:  # Added cls command
            self.channel.send("\x1b[H\x1b[J")
            
        elif cmd.startswith("wget ") or cmd.startswith("curl "):
            self.handle_download(cmd)
            
        elif cmd.startswith("rm "):
            self.handle_rm(cmd)
            
        elif cmd.startswith("chmod "):
            self.handle_chmod(cmd)
            
        elif cmd == "sudo -l":
            self.handle_sudo_list()
            
        elif cmd.startswith("docker "):
            self.handle_docker(cmd)
            
        elif cmd.startswith("mysql "):
            self.handle_mysql(cmd)
            
        elif cmd.startswith("touch "):
            self.handle_touch(cmd)
            
        elif cmd.startswith("mkdir "):
            self.handle_mkdir(cmd)
            
        elif ">" in cmd:
            self.handle_redirect(cmd)
            
        elif cmd.startswith(("vi ", "vim ", "nano ", "emacs ")):
            self.handle_editor(cmd)
            
        elif cmd in ["help", "--help"]:
            self.handle_help()
            
        elif cmd.startswith("find "):
            self.handle_find(cmd)
            
        elif cmd.startswith("grep "):
            self.handle_grep(cmd)
            
        elif cmd.startswith("head "):
            self.handle_head(cmd)
            
        elif cmd.startswith("tail "):
            self.handle_tail(cmd)
            
        elif cmd in ["date", "uptime", "who", "w"]:
            self.handle_system_info(cmd)
            
        elif cmd.startswith("tar "):
            self.handle_tar(cmd)
            
        elif cmd.startswith("scp "):
            self.handle_scp(cmd)
            
        elif cmd.startswith("ssh "):
            self.handle_ssh(cmd)
            
        elif cmd.startswith("python") or cmd.startswith("python3"):
            self.handle_python(cmd)
            
        elif cmd == "":
            pass
            
        else:
            self.channel.send(f"\r\n{cmd.split()[0]}: command not found\r\n")

    # Command handlers implementation
    def handle_ls(self, cmd):
        """Handle ls command with various options"""
        args = cmd.split()[1:] if len(cmd.split()) > 1 else []
        show_all = '-a' in args or '-la' in args or '-al' in args
        long_format = '-l' in args or '-la' in args or '-al' in args
        
        contents = self._get_current_dir_contents()
        output = []
        
        for item in contents:
            if not show_all and item.startswith('.'):
                continue
                
            if long_format:
                # Check if item is a directory created in this session
                item_path = os.path.join(self.cwd, item) if self.cwd != '/' else f"/{item}"
                if item_path in self.session_created_dirs:
                    output.append(f"drwxr-xr-x {self.username:>8} {self.username:>8} 4096 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {item}")
                elif item_path in FAKE_FS:
                    info = FAKE_FS[item_path]
                    output.append(f"{info['perms']} {info['owner']:>8} {info['group']:>8} {info['size']:>8} {info['modified']} {item}")
                else:
                    # Default for other files
                    output.append(f"-rw-r--r-- {self.username:>8} {self.username:>8} 1024 2024-01-15 10:00:00 {item}")
            else:
                output.append(item)
        
        self.channel.send("\r\n" + "\r\n".join(output) + "\r\n")

    def handle_cd(self, cmd):
        """Handle cd command - fixed to work with any directory"""
        if len(cmd.split()) < 2:
            # Just 'cd' should go to home directory
            self.cwd = '/home/admin'
            return
            
        target = cmd.split()[1]
        
        if target == "~":
            self.cwd = '/home/admin'
        elif target == "/":
            self.cwd = "/"
        elif target == "..":
            if self.cwd != "/":
                self.cwd = os.path.dirname(self.cwd) or "/"
        elif target == ".":
            # Stay in current directory
            pass
        elif target.startswith("/"):
            # Absolute path
            new_path = target
            # Check if it exists in FAKE_FS
            if new_path in FAKE_FS and FAKE_FS[new_path]['type'] == 'dir':
                self.cwd = new_path
            elif new_path in self.session_created_dirs:
                self.cwd = new_path
            else:
                # Try to find the directory in FAKE_FS
                found = False
                for path in FAKE_FS:
                    if path == new_path and FAKE_FS[path]['type'] == 'dir':
                        self.cwd = new_path
                        found = True
                        break
                
                if not found:
                    # Check if it's a valid directory path (e.g., /home/admin/downloads)
                    # The path might exist but we're checking incorrectly
                    # Let's be more permissive - allow cd to any path
                    self.cwd = new_path
                    if new_path not in self.session_created_dirs:
                        self.session_created_dirs.append(new_path)
        else:
            # Relative path
            if target.startswith("./"):
                target = target[2:]
            
            new_path = os.path.join(self.cwd, target) if self.cwd != "/" else f"/{target}"
            new_path = os.path.normpath(new_path)
            
            # Check if it exists in FAKE_FS
            if new_path in FAKE_FS and FAKE_FS[new_path]['type'] == 'dir':
                self.cwd = new_path
            elif new_path in self.session_created_dirs:
                self.cwd = new_path
            else:
                # Check all FAKE_FS paths to see if this is a subdirectory
                found = False
                for path in FAKE_FS:
                    if path == new_path and FAKE_FS[path]['type'] == 'dir':
                        self.cwd = new_path
                        found = True
                        break
                
                if not found:
                    # Allow cd to any directory - create it in session
                    self.cwd = new_path
                    if new_path not in self.session_created_dirs:
                        self.session_created_dirs.append(new_path)

    def handle_cat(self, cmd):
        """Handle cat command"""
        if len(cmd.split()) < 2:
            self.channel.send("\r\ncat: missing operand\r\n")
            return
            
        filename = cmd.split()[1]
        if filename.startswith("/"):
            path = filename
        else:
            path = os.path.join(self.cwd, filename)
            
        if path in FAKE_FS and FAKE_FS[path]['type'] == 'file':
            content = FAKE_FS[path]['content']
            self.channel.send(f"\r\n{content}\r\n")
        else:
            self.channel.send(f"\r\ncat: {filename}: No such file or directory\r\n")

    def handle_echo(self, cmd):
        """Handle echo command"""
        text = cmd[5:]  # Remove "echo "
        self.channel.send(f"\r\n{text}\r\n")

    def handle_uname(self, cmd):
        """Handle uname command"""
        args = cmd.split()[1:] if len(cmd.split()) > 1 else []
        
        if '-a' in args:
            self.channel.send("\r\nLinux prod-web01 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\r\n")
        elif '-r' in args:
            self.channel.send("\r\n5.4.0-91-generic\r\n")
        elif '-m' in args:
            self.channel.send("\r\nx86_64\r\n")
        elif '-s' in args:
            self.channel.send("\r\nLinux\r\n")
        else:
            self.channel.send("\r\nLinux\r\n")

    def handle_ps(self, cmd):
        """Handle ps command"""
        args = cmd.split()[1:] if len(cmd.split()) > 1 else []
        
        if 'aux' in args or '-ef' in args:
            header = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
            self.channel.send(f"\r\n{header}\r\n")
            for proc in self.processes:
                line = f"{proc['user']:<12} {proc['pid']:<5} {proc['cpu']:<4} {proc['mem']:<4} 123456 45678 ?        Ss   00:00   0:00 {proc['cmd']}"
                self.channel.send(f"{line}\r\n")
        else:
            header = "  PID TTY          TIME CMD"
            self.channel.send(f"\r\n{header}\r\n")
            for proc in self.processes[:5]:
                line = f"{proc['pid']:>5} ?        00:00:00 {proc['name']}"
                self.channel.send(f"{line}\r\n")

    def handle_network(self):
        """Handle network commands"""
        output = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::250:56ff:fe89:abcd  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:89:ab:cd  txqueuelen 1000  (Ethernet)
        RX packets 1234567  bytes 1234567890 (1.2 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 987654  bytes 987654321 (987.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 45678  bytes 456789012 (456.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 45678  bytes 456789012 (456.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"""
        self.channel.send(f"\r\n{output}\r\n")

    def handle_netstat(self, cmd):
        """Handle netstat command"""
        args = cmd.split()[1:] if len(cmd.split()) > 1 else []
        
        if '-tuln' in args:
            output = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::443                  :::*                    LISTEN"""
        else:
            output = """Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 192.168.1.100:22        192.168.1.50:54322      ESTABLISHED
tcp        0      0 192.168.1.100:80        203.0.113.25:45678      TIME_WAIT"""
        
        self.channel.send(f"\r\n{output}\r\n")

    def handle_history(self):
        """Handle history command"""
        if not self.command_history:
            self.channel.send("\r\nNo commands in history\r\n")
        else:
            for i, cmd in enumerate(self.command_history[-20:], 1):
                self.channel.send(f"  {i}  {cmd}\r\n")

    def handle_download(self, cmd):
        """Handle wget/curl commands"""
        filename = f"downloaded_file_{int(time.time())}"
        self.save_attacker_file(filename, f"# Simulated download from command: {cmd}", file_type="download")
        self.channel.send(f"\r\nDownloaded '{filename}' successfully\r\n")

    def handle_rm(self, cmd):
        """Handle rm command"""
        args = cmd.split()[1:]
        if not args:
            self.channel.send("\r\nrm: missing operand\r\n")
            return
            
        filename = args[-1]
        self.channel.send(f"\r\nrm: remove regular file '{filename}'? (y/N) ")
        
        # Simulate confirmation
        time.sleep(0.5)
        self.channel.send("y\r\n")
        self.channel.send(f"removed '{filename}'\r\n")

    def handle_chmod(self, cmd):
        """Handle chmod command"""
        args = cmd.split()[1:]
        if len(args) < 2:
            self.channel.send("\r\nchmod: missing operand\r\n")
            return
            
        filename = args[-1]
        self.channel.send(f"\r\nmode of '{filename}' changed to {args[0]}\r\n")

    def handle_sudo_list(self):
        """Handle sudo -l command"""
        if self.username in VULNERABLE_SUDO:
            self.channel.send("\r\nMatching Defaults entries for admin on prod-web01:\r\n")
            self.channel.send("    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\r\n\r\n")
            self.channel.send("User admin may run the following commands on prod-web01:\r\n")
            for rule in VULNERABLE_SUDO[self.username]:
                self.channel.send(f"    {rule}\r\n")
        else:
            self.channel.send("\r\nUser admin is not allowed to run sudo on prod-web01.\r\n")

    def handle_docker(self, cmd):
        """Handle docker commands"""
        if "ps" in cmd:
            output = """CONTAINER ID   IMAGE          COMMAND                  CREATED        STATUS        PORTS                               NAMES
a1b2c3d4e5f6   nginx:latest   "/docker-entrypoint.…"   2 weeks ago   Up 2 weeks    0.0.0.0:80->80/tcp, :::80->80/tcp   web-server
b2c3d4e5f6g7   mysql:8.0      "docker-entrypoint.s…"   2 weeks ago   Up 2 weeks    0.0.0.0:3306->3306/tcp, 33060/tcp   mysql-db
c3d4e5f6g7h8   redis:alpine   "docker-entrypoint.s…"   1 week ago    Up 1 week     0.0.0.0:6379->6379/tcp             redis-cache"""
        elif "images" in cmd:
            output = """REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
nginx        latest    123abc456def   2 months ago   142MB
mysql        8.0       789def012abc   3 months ago   545MB
redis        alpine    456ghi789jkl   4 months ago   32.4MB
ubuntu       20.04     012jkl345mno   5 months ago   72.8MB"""
        else:
            output = "Usage: docker [OPTIONS] COMMAND"
            
        self.channel.send(f"\r\n{output}\r\n")

    def handle_mysql(self, cmd):
        """Handle mysql commands"""
        if "-u" in cmd and "-p" in cmd:
            self.channel.send("\r\nEnter password: ")
            time.sleep(1)
            self.channel.send("\r\nERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)\r\n")
        else:
            self.channel.send("\r\nERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)\r\n")

    def handle_touch(self, cmd):
        """Handle touch command"""
        args = cmd.split()[1:]
        if not args:
            self.channel.send("\r\ntouch: missing file operand\r\n")
            return
            
        for filename in args:
            self.save_attacker_file(filename, f"# Created by touch command at {datetime.now()}", file_type="created")
            self.channel.send(f"\r\nCreated file: {filename}\r\n")

    def handle_mkdir(self, cmd):
        """Handle mkdir command"""
        args = cmd.split()[1:]
        if not args:
            self.channel.send("\r\nmkdir: missing operand\r\n")
            return
            
        for dirname in args:
            # Create relative or absolute path
            if dirname.startswith("/"):
                dir_path = dirname
            else:
                dir_path = os.path.join(self.cwd, dirname)
            
            # Normalize path
            dir_path = os.path.normpath(dir_path)
            
            # Add to session created directories
            if dir_path not in self.session_created_dirs:
                self.session_created_dirs.append(dir_path)
                
            self.channel.send(f"\r\nCreated directory: {dirname}\r\n")

    def handle_redirect(self, cmd):
        """Handle output redirection"""
        if ">" in cmd:
            parts = cmd.split(">")
            if len(parts) >= 2:
                command = parts[0].strip()
                filename = parts[1].strip()
                self.save_attacker_file(filename, f"# Output from: {command}", file_type="redirect")
                self.channel.send(f"\r\nRedirected output to: {filename}\r\n")

    def handle_editor(self, cmd):
        """Handle editor commands"""
        args = cmd.split()
        if len(args) > 1:
            filename = args[1]
            self.channel.send(f"\r\nEditing {filename} with {args[0]}...\r\n")
            self.channel.send("Press Ctrl+X to save and exit\r\n")
            # Simulate editing session
            time.sleep(1)
            self.save_attacker_file(filename, f"# Edited with {args[0]} at {datetime.now()}", file_type="edited")
            self.channel.send(f"\r\nFile {filename} saved\r\n")
        else:
            self.channel.send(f"\r\n{args[0]}: No file specified\r\n")

    def handle_find(self, cmd):
        """Handle find command"""
        output = """./readme.txt
./todo.md
./server_info.txt
./documents
./documents/notes.txt
./scripts
./scripts/backup.sh
./.bashrc
./.bash_history
./.profile"""
        self.channel.send(f"\r\n{output}\r\n")

    def handle_grep(self, cmd):
        """Handle grep command"""
        args = cmd.split()
        if len(args) < 2:
            self.channel.send("\r\ngrep: missing pattern\r\n")
            return
            
        pattern = args[1]
        output = f"/home/admin/.bash_history:1:ls -la\n/home/admin/documents/notes.txt:2:2. Monitor disk usage - /var is at 78%"
        self.channel.send(f"\r\n{output}\r\n")

    def handle_head(self, cmd):
        """Handle head command"""
        if "-n" in cmd:
            output = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10"
        else:
            output = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10"
        self.channel.send(f"\r\n{output}\r\n")

    def handle_tail(self, cmd):
        """Handle tail command"""
        if "-f" in cmd:
            self.channel.send("\r\n==> /var/log/syslog <==\n")
            self.channel.send("Jan 15 10:30:00 prod-web01 systemd[1]: Started Regular background program processing daemon.\n")
            self.channel.send("Jan 15 10:30:01 prod-web01 CRON[1234]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)\n")
            self.channel.send("\r\n(Press Ctrl+C to stop)\r\n")
        else:
            output = "line91\nline92\nline93\nline94\nline95\nline96\nline97\nline98\nline99\nline100"
            self.channel.send(f"\r\n{output}\r\n")

    def handle_system_info(self, cmd):
        """Handle system info commands"""
        if cmd == "date":
            self.channel.send(f"\r\n{datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}\r\n")
        elif cmd == "uptime":
            uptime = int(time.time() - self.start_time)
            hours = uptime // 3600
            minutes = (uptime % 3600) // 60
            self.channel.send(f"\r\n 10:30:45 up {hours}:{minutes:02d},  1 user,  load average: 0.12, 0.08, 0.05\r\n")
        elif cmd in ["who", "w"]:
            self.channel.send(f"\r\n{self.username}   pts/0        {time.strftime('%Y-%m-%d %H:%M')} ({self.client_ip})\r\n")

    def handle_tar(self, cmd):
        """Handle tar command"""
        if "-xzf" in cmd:
            self.channel.send("\r\nExtracting archive...\r\n")
            time.sleep(1)
            self.channel.send("\r\nArchive extracted successfully\r\n")
        elif "-czf" in cmd:
            self.channel.send("\r\nCreating archive...\r\n")
            time.sleep(1)
            self.channel.send("\r\nArchive created successfully\r\n")
        else:
            self.channel.send("\r\nUsage: tar [OPTION...] [FILE]...\r\n")

    def handle_scp(self, cmd):
        """Handle scp command"""
        self.channel.send("\r\nssh: connect to host localhost port 22: Connection refused\r\n")
        self.channel.send("lost connection\r\n")

    def handle_ssh(self, cmd):
        """Handle ssh command"""
        self.channel.send("\r\nssh: connect to host localhost port 22: Connection refused\r\n")

    def handle_python(self, cmd):
        """Handle python commands"""
        if "-c" in cmd:
            self.channel.send("\r\nPython 3.8.10 (default, Nov 14 2023, 12:59:47) \r\n[GCC 9.4.0] on linux\r\n")
        else:
            self.channel.send("\r\nPython 3.8.10 (default, Nov 14 2023, 12:59:47) \r\n[GCC 9.4.0] on linux\r\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n>>> ")

    def handle_help(self):
        """Handle help command"""
        help_text = """Available commands:
  System Information: date, uptime, who, w, uname, hostname
  File Operations: ls, cd, pwd, cat, echo, touch, mkdir, rm, cp, mv, chmod, chown
  Text Processing: grep, head, tail, more, less, find, sort, wc
  Process Management: ps, top, kill, killall, pkill
  Network: ifconfig, ip, netstat, ping, traceroute, curl, wget, ssh, scp
  Package Management: apt, dpkg (requires sudo)
  Services: systemctl, service (requires sudo)
  Development: python, python3, gcc, make
  Databases: mysql, psql
  Containers: docker, docker-compose
  Editors: vi, vim, nano, emacs
  Other: clear, cls, reset, history, exit, logout, sudo, su"""
        self.channel.send(f"\r\n{help_text}\r\n")

    def run(self):
        """Main shell loop"""
        try:
            # Display welcome message
            welcome_msg = f"""
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {time.strftime('%a %b %d %H:%M:%S %Z %Y')}

  System load:  0.12               Processes:             123
  Usage of /:   45.8% of 50.00GB   Users logged in:       1
  Memory usage: 34%                IPv4 address for eth0: 192.168.1.100
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.

Last login: {time.strftime('%a %b %d %H:%M:%S %Y')} from {self.client_ip}
"""
            self.channel.send(welcome_msg)

            # Main command loop
            while self.session_active and not self.check_timeout():
                try:
                    # Display prompt
                    if self.is_root:
                        prompt = f"\r\nroot@{HOSTNAME}:{self.cwd}# "
                    else:
                        prompt = f"\r\n{self.username}@{HOSTNAME}:{self.cwd}$ "
                    
                    self.channel.send(prompt)
                    
                    # Read command
                    cmd = ""
                    while True:
                        if self.channel.recv_ready():
                            char = self.channel.recv(1).decode(errors='ignore')
                            self.log_keystroke(char, "command_input")
                            
                            if char in ('\r', '\n'):
                                break
                            elif char == '\x7f':  # Backspace
                                if cmd:
                                    cmd = cmd[:-1]
                                    self.channel.send('\b \b')
                            elif char == '\x03':  # Ctrl+C
                                self.channel.send("^C\r\n")
                                cmd = ""
                                break
                            elif char == '\x04':  # Ctrl+D
                                self.session_active = False
                                self.channel.send("\r\nlogout\r\n")
                                break
                            else:
                                cmd += char
                                self.channel.send(char)
                        else:
                            time.sleep(0.05)
                        
                        if self.check_timeout():
                            return
                    
                    cmd = cmd.strip()
                    if cmd:
                        self.handle_command(cmd)
                        
                except (socket.timeout, Exception) as e:
                    logger.error(f"SESSION_ERROR - SessionID: {self.session_id} - IP: {self.client_ip} - Error: {e}")
                    csv_logger.log_event(event_type='SESSION_ERROR', session_id=self.session_id, client_ip=self.client_ip, username=self.username, password=self.password, details=str(e))
                    break
                    
        finally:
            # Session cleanup
            duration = time.time() - self.start_time
            logger.info(f"SESSION_END - SessionID: {self.session_id} - IP: {self.client_ip} - Duration: {duration:.2f}s - Commands: {len(self.command_history)} - RootAccess: {self.is_root} - FilesCreated: {len(self.created_files)} - DirsCreated: {len(self.session_created_dirs)}")
            csv_logger.log_event(
                event_type='SESSION_END',
                session_id=self.session_id,
                client_ip=self.client_ip,
                username=self.username,
                password=self.password,
                duration_seconds=str(round(duration, 2)),
                details=f"Commands executed: {len(self.command_history)}, Files created: {len(self.created_files)}, Directories created: {len(self.session_created_dirs)}",
                is_root=str(self.is_root)
            )
            
            # Run attacker analysis
            try:
                events = []
                for cmd in self.command_history:
                    events.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "category": "UNKNOWN",
                        "pattern": None,
                        "command": cmd,
                        "severity": 1
                    })

                narrative, profile = analyze_session(events, src_ip=self.client_ip)
                logger.info(f"ATTACKER_ANALYSIS - SessionID: {self.session_id} - IP: {self.client_ip} - Summary: {narrative}")
                logger.info(f"ATTACKER_PROFILE - {profile}")
            except Exception as e:
                logger.error(f"ANALYSIS_ERROR - {e}")
            
            try:
                self.channel.close()
            except:
                pass

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.login_attempts = 0
        self.last_attempt = 0
        self.username = None
        self.password = None
        self.failed_credentials = {}

    def check_auth_password(self, username, password):
        now = time.time()
        if now - self.last_attempt < 1:
            time.sleep(1)
            
        self.login_attempts += 1
        self.last_attempt = now
        self.username = username
        self.password = password
        cred_key = f"{username}:{password}"
        
        if cred_key in self.failed_credentials:
            self.failed_credentials[cred_key] += 1
        else:
            self.failed_credentials[cred_key] = 1
            
        logger.info(f"LOGIN_ATTEMPT - IP: {self.client_ip} - Username: {username} - Password: {password} - Attempt: {self.login_attempts}")
        csv_logger.log_event(
            event_type='LOGIN_ATTEMPT',
            client_ip=self.client_ip,
            username=username,
            password=password,
            details=f"Password: {password}",
            attempt_count=str(self.login_attempts)
        )
        
        if self.login_attempts >= MAX_LOGIN_ATTEMPTS:
            logger.warning(f"TOO_MANY_LOGIN_ATTEMPTS - IP: {self.client_ip} - Username: {username} - Attempts: {self.login_attempts}")
            csv_logger.log_event(
                event_type='TOO_MANY_LOGIN_ATTEMPTS',
                client_ip=self.client_ip,
                username=username,
                password=password,
                attempt_count=str(self.login_attempts)
            )
            return paramiko.AUTH_FAILED
            
        if self.failed_credentials[cred_key] >= MAX_SAME_PASSWORD_ATTEMPTS:
            logger.warning(f"REPEATED_FAILED_CREDENTIALS - IP: {self.client_ip} - Username: {username} - Attempts: {self.failed_credentials[cred_key]}")
            csv_logger.log_event(
                event_type='REPEATED_FAILED_CREDENTIALS',
                client_ip=self.client_ip,
                username=username,
                password=password,
                attempt_count=str(self.failed_credentials[cred_key])
            )
            return paramiko.AUTH_FAILED
            
        if username == USERNAME and password == PASSWORD:
            logger.info(f"LOGIN_SUCCESS - IP: {self.client_ip} - Username: {username} - Password: {password}")
            csv_logger.log_event(
                event_type='LOGIN_SUCCESS',
                client_ip=self.client_ip,
                username=username,
                password=password
            )
            return paramiko.AUTH_SUCCESSFUL
            
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        logger.warning(f"DIRECT_COMMAND_EXECUTION - IP: {self.client_ip} - Command: {command}")
        csv_logger.log_event(
            event_type='DIRECT_COMMAND_EXECUTION',
            client_ip=self.client_ip,
            command=command,
            details="Direct command execution attempt"
        )
        try:
            channel.send(f"Command execution not allowed: {command}\r\n")
            channel.send_close()
        except:
            pass
        return False

def handle_connection(client_sock, client_ip):
    """Handle an incoming client connection"""
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = SSH_BANNER
        try:
            transport.set_keepalive(30)
        except:
            pass

        # Generate or load host key
        host_key_path = os.path.join(LOGS_DIR, "host_key")
        try:
            host_key = paramiko.RSAKey(filename=host_key_path)
        except:
            host_key = paramiko.RSAKey.generate(2048)
            try:
                host_key.write_private_key_file(host_key_path)
                logger.info("HOST_KEY_GENERATED - New RSA host key generated")
                csv_logger.log_event(event_type='HOST_KEY_GENERATED', details="New RSA host key generated")
            except Exception as e:
                logger.warning(f"Could not write host key to {host_key_path}: {e}")

        transport.add_server_key(host_key)
        server = SSHServer(client_ip)

        try:
            transport.start_server(server=server)
            channel = transport.accept(20)
            if channel:
                logger.info(f"NEW_SSH_SESSION - IP: {client_ip}")
                csv_logger.log_event(event_type='NEW_SSH_SESSION', client_ip=client_ip)
                shell = FakeShell(channel, client_ip, server.username, server.password)
                shell.run()
            else:
                logger.info(f"NO_CHANNEL - client {client_ip} disconnected before session established")
                csv_logger.log_event(event_type='NO_CHANNEL', client_ip=client_ip, details="No channel opened (client disconnected)")
        except (ConnectionResetError, EOFError) as e:
            logger.error(f"Socket exception: {e}")
            csv_logger.log_event(event_type='CONNECTION_ERROR', client_ip=client_ip, details=str(e))
        except OSError as e:
            logger.error(f"OS socket error: {e}")
            csv_logger.log_event(event_type='CONNECTION_ERROR', client_ip=client_ip, details=str(e))
        except paramiko.SSHException as e:
            logger.error(f"Paramiko SSHException during handshake: {e}")
            csv_logger.log_event(event_type='CONNECTION_ERROR', client_ip=client_ip, details=str(e))
        except Exception as e:
            logger.error(f"UNEXPECTED_CONNECTION_ERROR - IP: {client_ip} - Error: {e}")
            csv_logger.log_event(event_type='CONNECTION_ERROR', client_ip=client_ip, details=str(e))
        finally:
            try:
                transport.close()
            except:
                pass
    except Exception as e:
        logger.error(f"CONNECTION_ERROR - IP: {client_ip} - Error: {str(e)}")
        csv_logger.log_event(
            event_type='CONNECTION_ERROR',
            client_ip=client_ip,
            details=str(e)
        )
    finally:
        try:
            client_sock.close()
        except:
            pass

def start_ssh_honeypot():
    """Start the SSH honeypot server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)
    
    logger.info(f"HONEYPOT_STARTED - Listening on {HOST}:{PORT}")
    logger.info(f"DEFAULT_CREDENTIALS - {USERNAME}:{PASSWORD}")
    csv_logger.log_event(event_type='HONEYPOT_STARTED', details=f"Listening on {HOST}:{PORT}")
    csv_logger.log_event(event_type='DEFAULT_CREDENTIALS', details=f"{USERNAME}:{PASSWORD}")
    
    print(f"""
╔══════════════════════════════════════════════════════════╗
║               SSH HONEYPOT SERVER STARTED                ║
╠══════════════════════════════════════════════════════════╣
║  Listening on: {HOST}:{PORT:<36} ║
║  Hostname: {HOSTNAME:<43} ║
║  Credentials: {USERNAME}/{PASSWORD:<38} ║
║  Logs Directory: {LOGS_DIR:<34} ║
║  Session Timeout: {COMMAND_TIMEOUT}s inactivity          ║
║  Session Limit: {SESSION_DURATION_LIMIT//60} minutes total           ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    try:
        while True:
            client, addr = sock.accept()
            logger.info(f"NEW_CONNECTION - IP: {addr[0]}:{addr[1]}")
            csv_logger.log_event(event_type='NEW_CONNECTION', client_ip=addr[0], details=f"Port: {addr[1]}")
            threading.Thread(target=handle_connection, args=(client, addr[0]), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("HONEYPOT_SHUTDOWN - Shutting down honeypot...")
        csv_logger.log_event(event_type='HONEYPOT_SHUTDOWN', details="Manual shutdown")
        print("\n\nShutting down honeypot server...")
    finally:
        sock.close()

if __name__ == "__main__":
    start_ssh_honeypot()