# Scripts

## nmap script

`nerd.nse` script in LUA for nmap (www.nmap.org), which
allows users to look up a scanned target in NERD.
The script requires API token stored in a file called `nerdapifile`
in the current working directory or it is possible to specify path
to the file using `--script-args` (`nerd.apifile=`).

## nerd2misp.py

Synchronizes a single MISP event with NERD's most active malicious IPs
(categories `scan` and `login`, high confidence), queried from the NERD API
(`search/ip` endpoint; needs a NERD API token). Attributes are added/removed
on each run to match the current data.

Configuration: see `etc/nerd2misp.yml` (default path `/etc/nerd/nerd2misp.yml`,
override with `-c`). Meant to be run periodically via cron, not as a daemon.

Requires `requests`, `pyyaml` and `pymisp` >= 2.4.184 (listed in
`install/pip_requirements_nerdd.txt`).

Use `-n` (dry run) to see what would change without modifying MISP, add `-v`
to list the individual IPs.


