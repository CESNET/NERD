#!/bin/sh
# Generate list of all IPs in NERD's database with their categories
# Takes one parameter - output directory

out_dir="${1%/}"
if [[ -z "$out_dir" ]]; then
  out_dir=/data/web-data # no/emtpy parameter, use default
elif [ ! -d "$out_dir" ]; then
  # Create the output directory if it doesn't exist
  mkdir -p "$out_dir"
fi

# Line format
out_file="$out_dir/ip_category.csv"
echo "# Generated at $(date -u '+%Y-%m-%d %H:%M UTC')" > "$out_file.tmp"
echo "# IP,Category,Confidence" >> "$out_file.tmp"
mongosh nerd --quiet --eval '
function int2ip (ipInt) {
  return ( (ipInt>>>24) + "." + (ipInt>>16 & 255) + "." + (ipInt>>8 & 255) + "." + (ipInt & 255) );
}
db.ip.aggregate([
  { $unwind: "$_threat_category_summary" },
  { $set: { category: "$_threat_category_summary.c", confidence: { $toString: "$_threat_category_summary.conf" } } },
  { $project: { _id: 1, category: 1, confidence: 1 } }
]).forEach(function(rec) { print(int2ip(rec._id) + "," + rec.category + "," + rec.confidence); })' | grep -v "^$" | sort -n >> "$out_file.tmp"
mv "$out_file"{.tmp,}

# Table format
# TODO load category ids dynamically from categorization config
out_file="$out_dir/ip_category_table.csv"
echo "# Generated at $(date -u '+%Y-%m-%d %H:%M UTC')" > "$out_file.tmp"
echo "# IP,botnet_drone,bruteforce,cc,ddos,ddos-amplifier,exploit,malware_distribution,phishing_site,scan,spam" >> "$out_file.tmp"
mongosh nerd --quiet --eval '
function int2ip (ipInt) {
  return ( (ipInt>>>24) + "." + (ipInt>>16 & 255) + "." + (ipInt>>8 & 255) + "." + (ipInt & 255) );
}
db.ip.aggregate([
  { $project: { _id: 1, _threat_category_summary: 1 } },
  { $set: { categories: { $arrayToObject: { $map: { input: "$_threat_category_summary", as: "cat", in: { k: "$$cat.c", v: { $toString: "$$cat.conf" } } } } } } },
  { $replaceWith: { $mergeObjects: ["$$ROOT", "$categories"] } },
  { $project: {
    "_id": 1,
    "botnet_drone": { $ifNull: ["$botnet_drone", "0"] },
    "bruteforce": { $ifNull: ["$bruteforce", "0"] },
    "cc": { $ifNull: ["$cc", "0"] },
    "ddos": { $ifNull: ["$ddos", "0"] },
    "ddos-amplifier": { $ifNull: ["$ddos-amplifier", "0"] },
    "exploit": { $ifNull: ["$exploit", "0"] },
    "malware_distribution": { $ifNull: ["$malware_distribution", "0"] },
    "phishing_site": { $ifNull: ["$phishing_site", "0"] },
    "scan": { $ifNull: ["$scan", "0"] },
    "spam": { $ifNull: ["$spam", "0"] }
  }}
]).forEach(function(rec) {
  var categories = Object.keys(rec).filter(key => key !== "_id");
  print(
    int2ip(rec._id) + "," +
    categories.map(key => rec[key]).join(",")
  );
})' | grep -v "^$" | sort -n >> "$out_file.tmp"
mv "$out_file"{.tmp,}
