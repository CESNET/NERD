#!/bin/bash

#author: Adam.Stefanides@cesnet.cz
#descr: Donwloads proxy servers lists from geonode,
#       convert_geonode.py HAS to be in the same file!

base_url_part1="https://proxylist.geonode.com/api/proxy-list?limit=500&page="
base_url_part2="&sort_by=lastChecked&sort_type=desc"

# Folder to store downloaded files
download_dir=/data/blacklists/temp

# Maximum number of pages to download
N=14

mkdir -p "$download_dir"

for i in $(seq 0 $N); do
  # Construct the URL using the base URL and current number
  url="${base_url_part1}${i}${base_url_part2}" 
  #echo "Downloading $url..."
  wget -q -P "$download_dir" "$url"
done

#echo "All downloads complete!"
#echo "Running convert_geonode.py ..."

python3 convert_geonode.py

#echo "Removing temp folder"
rm -r "$download_dir"
