#!/usr/bin/env python3
"""
Generate list of all IPs in NERD's database with their categories
Parameters - path to config directory
           - path to output directory
           - blacklist confidence threshold
"""
import os
import sys
import subprocess
import argparse

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.config import read_config


# parse arguments
parser = argparse.ArgumentParser(
    prog="generate_ip_category_files.py",
    description="Generate list of all IPs in NERD's database with their categories"
)
parser.add_argument("-c", '--config', dest='cfg_file', default="/etc/nerd/threat_categorization.yml",
                    help="Path to configuration file (default: /etc/nerd/threat_categorization.yml)")
parser.add_argument("-o", '--output', dest='out_dir', default="/data/web_data/",
                    help="Path to output directory (default: /data/web_data/)")
parser.add_argument("-t", '--threshold', dest='conf_thr', default="0.5",
                    help="Blacklist confidence threshold (default: 0.5)")
parser.add_argument("-v", '--verbose', dest="verbose", action="store_true", help="Verbose mode")
args = parser.parse_args()

# read categorization config
config = read_config(args.cfg_file)
categories = [cat for cat in config.get('threat_categories')]
categories.remove("unknown")

# bash script used to execute the DB query
script = """
    echo \"# generated at $(date -u '+%Y-%m-%d %H:%M UTC')\" > {out_file}.tmp &&
    echo \"# {header}\" >> {out_file}.tmp &&
    mongosh \"$(cat /etc/nerd/mongodb_credentials)\" --quiet --eval '{query}' | grep -v \"^$\" | sort -n >> {out_file}.tmp &&
    mv {out_file}{{.tmp,}}
"""

def fstr(template):
    return eval(f"f'''{template}'''")

########################################################################################################################

# full list - line format (ip,category,confidence)
if args.verbose:
    print("Generating full IP list (line format)")

out_file = f"{args.out_dir}/ip_category.csv"
header = "ip,category,confidence"
query = '''
function int2ip (ipInt) {
  return ( (ipInt>>>24) + "." + (ipInt>>16 & 255) + "." + (ipInt>>8 & 255) + "." + (ipInt & 255) );
}
db.ip.aggregate([
  { $unwind: "$_threat_category_summary" },
  { $set: { category: "$_threat_category_summary.c", confidence: { $toString: "$_threat_category_summary.conf" } } },
  { $project: { _id: 1, category: 1, confidence: 1 } }
]).forEach(function(rec) { print(int2ip(rec._id) + "," + rec.category + "," + rec.confidence); })
'''
subprocess.run(fstr(script), shell=True)

########################################################################################################################

# full list - table format (ip,conf_scan,conf_bruteforce,...)
if args.verbose:
    print("Generating full IP list (table format)")

out_file = f"{args.out_dir}/ip_category_table.csv"
header = f"ip,conf_{',conf_'.join(categories)}"
query = '''
function int2ip (ipInt) {
  return ( (ipInt>>>24) + "." + (ipInt>>16 & 255) + "." + (ipInt>>8 & 255) + "." + (ipInt & 255) );
}
db.ip.aggregate([
  { $project: { _id: 1, _threat_category_summary: 1 } },
  { $set: { categories: { $arrayToObject: { $map: { input: "$_threat_category_summary", as: "cat", in: { k: "$$cat.c", v: { $toString: "$$cat.conf" } } } } } } },
  { $replaceWith: { $mergeObjects: ["$$ROOT", "$categories"] } },
  { $project: {
    "_id": 1,
'''
for category in categories:
    query += f'"{category}": {{ $ifNull: ["${category}", "0"] }},\n'
query += '''
}}]).forEach(function(rec) {
  var categories = Object.keys(rec).filter(key => key !== "_id");
  print(
    int2ip(rec._id) + "," +
    categories.map(key => rec[key]).join(",")
  );
})
'''
subprocess.run(fstr(script), shell=True)

########################################################################################################################

# blacklists
if args.verbose:
    print("Generating blacklists")

for category in categories:
    out_file = f"{args.out_dir}/bl_{category}.txt"
    header = f"All IP addresses in NERD with threat category '{category}' with confidence (threat level) > {args.conf_thr}"
    query = f'''
    function int2ip (ipInt) {{
      return ( (ipInt>>>24) + "." + (ipInt>>16 & 255) + "." + (ipInt>>8 & 255) + "." + (ipInt & 255) );
    }}
    db.ip.find({{"_threat_category_summary": {{$elemMatch: {{"c": "{category}", "conf": {{$gt: {args.conf_thr}}}}}}}, "tags.whitelist": {{$exists: false}}}}, {{_id: 1}}).sort({{"_threat_category_summary.conf": -1}}).forEach( function(rec) {{ print(int2ip(rec._id)); }} );
    '''
    subprocess.run(fstr(script), shell=True)

if args.verbose:
    print("Done")
