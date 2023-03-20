from itertools import count
import os
import requests
from requests.auth import HTTPBasicAuth
import json
import time

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "x-apikey":"<Place api key here>"
    }

with open("<place input text file here>") as file:
    dump=file.read()
    dump=dump.splitlines()
for i in dump:
    ip=i.split()[1]
    host=i.split()[0]
    #print(host)
    #print(ip)
    url =f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    #print(url)
    resour=str(url)
    #print(resour)
    response = requests.request(
        "GET",
        resour,
        headers=headers,
        verify = False
    ).json()
    
    print(f"This ip {ip} has number of hits= \n")
    print(response["data"]["attributes"]["last_analysis_stats"]["malicious"])
    hits=response["data"]["attributes"]["last_analysis_stats"]["malicious"]
    country=response["data"]["attributes"]["country"]
    print(country)
    f=open("<place output text file here>", "a")
    f.write(str(host)+ '\t' + str(ip) +'\t' + str(hits) + '\t' + str(country) + '\n')
    f.close()
    time.sleep(20)
    
       
    
     
