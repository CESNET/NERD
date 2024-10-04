#Author: Adam.Stefanides@cesnet.cz

import requests
import math
import sys

MAX_N_OF_REQUESTS = 100

def get_page(n: int) -> dict:
    '''
    Descr: Sends GET request to an url with a specified page and returns it as json obj
    :param n: page number
    :return: json obj [dict]
    '''
    url = "https://proxylist.geonode.com/api/proxy-list?limit=500&page="
    response = requests.get(url + str(n))

    return response.json()

def get_file(n: int) -> str:
    '''
    Descr: Donwloads N pages from an url, extracts ip adresses and returns them
    :param n: number of pages
    :return: string of ip adresses 
    '''
    output = ""
    for i in range(1, n + 1):
        obj = get_page(i)
        for rec in obj["data"]:
            # extracting ip
            output += rec["ip"] + "\n"
    return output[:-1]

#Calculating number of pages of API to download
obj = get_page(1)
pages = math.ceil(obj["total"] / obj["limit"])
if pages > MAX_N_OF_REQUESTS:
    print("ERROR: number of pages exceeds the number of allowed requests!", file=sys.stderr)
    sys.exit(1)

#Write the ip aresses into a file
with open("geonode_proxy_list.txt", "w") as file:
    file.write(get_file(pages))