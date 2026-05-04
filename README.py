# CVE-2026-41940 - cPanel/WHM Authentication Bypass

CVSS 9.8 | Unauthenticated root access via CRLF injection

## Usage
python3 cp.py -t cpanel.target.com           # detect
python3 cp.py -t cpanel.target.com --exploit # exploit

@nickpaulsec