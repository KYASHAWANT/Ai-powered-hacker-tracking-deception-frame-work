PRIV_ESC_PATTERNS = [
    r"sudo\s+su",
    r"sudo\s+-i",
    r"su\s+root",
    r"chmod\s+777",
    r"pkexec",
]

DESTRUCTIVE_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+\*",
    r"dd\s+if=/dev/zero",
    r"mkfs\.",
    r"shutdown\s+-h",
    r"reboot",
]

RECON_PATTERNS = [
    r"nmap",
    r"ifconfig",
    r"ip\s+a",
    r"netstat",
    r"whoami",
    r"uname\s+-a",
]

TYPOS_PATTERN = [
    r"sl\s+-la",
    r"ifconfigg",
    r"pwdd",
    r"ls\s+-ll",
]
