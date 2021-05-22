import json
import csv
import time
from datetime import *
import os
import requests
path="C:\\Users\\xyzabc\\Documents\\Scripting_Stuff\\Intel_feeds\\reverse-it\\" #add correct path
url="https://hybrid-analysis.com/feed?json"
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'
    }
now=datetime.now()
todays_date=now.strftime("%Y%m%d")
csv_file="reverse_it_"+todays_date+".csv"
with open(csv_file,"w") as csvfile:
    csvfile.write("Hash"+","+"Malware"+","+"AV Detection"+","+"File name"+","+"Threat Score"+","+"Domains""\n")


r=requests.get(url,headers=headers)
data_text=r.text
data = json.loads(data_text)
for i in range(0, len(data['data'])):
        threat_score=data['data'][i]['threatscore']
        if threat_score >= 50:
            md5 = data['data'][i]['md5']
            try:
                vx_family= data['data'][i]['vxfamily']
            except KeyError:
                vx_family = "<unknown>"
            try:
                file_name = data['data'][i]['submitname']
            except KeyError:
                file_name = "<unknown>"
            try:
                av_count = data['data'][i]['avdetect']
            except KeyError:
                av_count = "<unknown>"
            try:
                domains=data['data'][i]['domains']
            except KeyError:
                domains = "<unknown>"
            with open(csv_file, 'a',encoding= 'utf-8') as csvfile:
                    csvfile.write(str(md5)+","+str(vx_family)+","+str(av_count)+","+str(file_name)+","+str(threat_score)+","+str(domains)+",""\n")




    
    
