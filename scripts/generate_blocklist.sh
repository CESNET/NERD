#!/bin/bash
# Generate list of all IPs in NERD with reputation score higher than a given
# threshold (also filter out IPs with "research_scanner" tag)
# Intended use is to generate a blocklist/TI feed for download.
#
# Takes one parameter - rep. score threshold (default = 0.5)
#
# Output a plain-text file with one IP per line (and a comment in the beginning)
# Output goes to stdout.

if [[ -z "$1" ]]; then
  thr=0.5 # no/emtpy parameter, use default
elif [[ "$1" =~ ^0[.][0-9]+$ ]]; then
  thr="$1"
else
  echo "ERROR" # This will be content of the generated blocklist
  echo "ERROR: Threshold must be a number between 0 and 1" >&2 # Error message to stderr
  exit 1
fi

echo "# IP addresses in NERD database with reputation score over ${thr} (excluding whitelisted ones). Generated at $(date -u '+%Y-%m-%d %H:%M UTC')"

mongo nerd --quiet --eval '
function int2ip (ipInt) {
  return ( (ipInt>>>24) + "." + (ipInt>>16 & 255) + "." + (ipInt>>8 & 255) + "." + (ipInt & 255) );
}
db.ip.find({rep: {$gt: '"$thr"'}, "tags.whitelist": {$exists: false}}, {_id: 1}).sort({rep: -1}).forEach( function(rec) { print(int2ip(rec._id)); } );
'
