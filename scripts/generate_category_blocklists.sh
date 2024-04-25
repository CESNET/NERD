#!/bin/bash
# Generate blocklists for each threat category (IPs with confidence higher than a given threshold)
# Intended use is to generate a blocklist/TI feed for download.
#
# Takes two parameters - confidence threshold (default = 0.5) and output directory
#
# Output a plain-text file with one IP per line (and a comment in the beginning)

if [[ -z "$1" ]]; then
  thr=0.5 # no/emtpy parameter, use default
elif [[ "$1" =~ ^0[.][0-9]+$ ]]; then
  thr="$1"
else
  echo "ERROR" # This will be content of the generated blocklist
  echo "ERROR: Threshold must be a number between 0 and 1" >&2 # Error message to stderr
  exit 1
fi

out_dir="${2%/}"
if [[ -z "$out_dir" ]]; then
  out_dir=/data/web-data # no/emtpy parameter, use default
elif [ ! -d "$out_dir" ]; then
  # Create the output directory if it doesn't exist
  mkdir -p "$out_dir"
fi

# List of category IDs
# TODO load category ids dynamically from categorization config
declare -a categories=(
  "botnet_drone"
  "bruteforce"
  "cc"
  "ddos"
  "ddos-amplifier"
  "exploit"
  "malware_distribution"
  "phishing_site"
  "scan"
  "spam"
)

for category in "${categories[@]}"; do
  echo "# Generated at $(date -u '+%Y-%m-%d %H:%M UTC')" > "$out_dir/bl_$category.txt"
  mongosh nerd --quiet --eval '
    function int2ip (ipInt) {
      return ( (ipInt>>>24) + "." + (ipInt>>16 & 255) + "." + (ipInt>>8 & 255) + "." + (ipInt & 255) );
  }
  db.ip.find({"_threat_category_summary": {$elemMatch: {"c": "'$category'", "conf": {$gt: '$thr'}}}, "tags.whitelist": {$exists: false}}, {_id: 1}).sort({"_threat_category_summary.conf": -1}).forEach( function(rec) { print(int2ip(rec._id)); } );
  ' | grep -v "^$" | sort -n >> "$out_dir/bl_$category.txt.tmp"
  mv "$out_dir/bl_$category.txt"{.tmp,}
done
