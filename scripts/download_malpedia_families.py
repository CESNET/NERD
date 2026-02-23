#!/usr/bin/env python3

# Download Malpedia's list of malware families to /data/malpedia/malware_families.yml

import requests
import yaml
import json
import os

url = "https://malpedia.caad.fkie.fraunhofer.de/api/get/families"
response = requests.get(url)
data = json.loads(response.content)
output = {}
output_dir = "/data/malpedia/"

for family_id, family_data in data.items():
    name = family_data.get("common_name", "")
    if name == "":
        try:
            name = family_id.split('.')[1]
        except Exception:
            name = family_id
    output[family_id] = {
        "common_name": name,
        "description": family_data.get("description", ""),
        "url": f"https://malpedia.caad.fkie.fraunhofer.de/details/{family_id}"
    }

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

with open(f"{output_dir}/malware_families.yml", "w+") as outfile:
    yaml.dump(output, outfile, default_flow_style=False)
