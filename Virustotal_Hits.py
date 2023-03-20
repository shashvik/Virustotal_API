from itertools import count
import os
import requests
from requests.auth import HTTPBasicAuth
import json
import time

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "x-apikey":"<place api key here>"
    }

with open("<place input text file here>") as file:
    dump=file.read()
    dump=dump.splitlines()
for i in dump:
    ip=i.split()[1]
    host=i.split()[0]
    #print(host)
    #print(ip)
    url =f"https://www.virustotal.com/api/v3/search?query={ip}"
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
    try:
        #print(response["data"][0]["attributes"]["last_analysis_stats"]["malicious"])
        #print(response["data"][0]["attributes"]["tags"])
        hits=response["data"][0]["attributes"]["last_analysis_stats"]["malicious"]
        owner=response["data"][0]["attributes"]["as_owner"]
        tags=response["data"][0]["attributes"]["tags"]
        country=response["data"][0]["attributes"]["country"]
        print(str(host)+ '\t' + str(ip) +'\t' + str(hits) + '\t' + str(tags) + '\t' + str(country) + '\t' + str(owner) + '\n')
        f=open("<place output text file here>", "a")
        f.write(str(host)+ '\t' + str(ip) +'\t' + str(hits) + '\t' + str(tags) + '\t' + str(country) + '\t' + str(owner) + '\n')
        f.close()
        #time.sleep(20)
    except:
        f=open("<place output text file here>", "a")
        f.write(str(host)+ '\t' + str(ip) +'\t' + '\t' + '\n')
        f.close()

       
    
     
