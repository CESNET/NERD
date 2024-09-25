'''
author: Adam.Stefanides@cesnet.cz
descr: Iterates through all files containing proxy servers data from geonode,
       extracts ip adresses and writes them into a new file,
       this script HAS to be in the same folder as fetch_geonode.sh!
'''

import json
from pathlib import Path

folder_path = Path('/data/blacklists/temp')

# Get all files in the folder
files = [f.name for f in folder_path.iterdir() if f.is_file()]

output = ""
for file in files:
    try:
        with open('/data/blacklists/temp/' + file, "r") as f:
            obj = json.loads(f.readline())
            for rec in obj["data"]:
                # extracting ip
                output += rec["ip"] + "\n"
            # removing extra '\n'
            output = output[:-1]
    except Exception as e: 
        print(f"Exception occured while opening and reading file: {e}")
        exit(-1)
        
# creating output file
with open(f"/data/blacklists/geonode_proxy_list.txt", "w") as f:
    f.write(output)
    
#print("convert_geonode.py: Lists merged and converted!")
            
            