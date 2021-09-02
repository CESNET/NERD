#!/bin/sh
# Generate list of all IPs in NERD's database with their reputation scores
# (only those with non-zero reputation are listed)
# Output a plain-text file with "<ip>,<rep>" per line
# Output goes to stdout.

echo "# All IP addresses and their reputation scores in NERD database. Generated at $(date -u '+%Y-%m-%d %H:%M UTC')"

# grep is used because mongosh puts an empty line at the end that we don't want there
mongosh nerd --quiet --eval '
function int2ip (ipInt) {
  return ( (ipInt>>>24) + "." + (ipInt>>16 & 255) + "." + (ipInt>>8 & 255) + "." + (ipInt & 255) );
}
db.ip.find({rep: {$gt: 0}}, {rep: 1}).sort({rep: -1}).forEach( function(rec) { print(int2ip(rec._id) + "," + rec.rep.toFixed(3)); } );
' | grep -v "^$"

