#!/usr/bin/env python3
#
#
# 	author:  	https://github.com/m0nkeyplay/
# 	file Date: 	2019-10-15
#   Update:     2021-06-17
#               Added HTML and chapters option
#
# 	purpose: 	Queue Up and download scan data from the lastest scan based on scan name
#
#	structure: 	Get the latest history and queue up the nessus file

#
#   usage:      python3 npScanExport.py -scan ScanNametoSearch -o nessus|csv|html
#
#   switchs:    -s       Search this specific scan
#               -o       Output Type options:  nessus, csv
#
#   notes:      fill in the following variables as needed per environment
#               npURL           <-- Base URL for the Nessus Professional instance no trailing /
#               put_files       <-- Where do you want the exports to download
#                                   default is inside the downloads folder attached to this repo
#               ak              <-- Access Key
#               sk              <-- Secret Key
#               proxies         <-- If you use a proxy, set it here.
#

import requests
import json
import os
import time
import datetime
import argparse
from datetime import timedelta
import urllib3
urllib3.disable_warnings()

ap = argparse.ArgumentParser()
ap.add_argument("-s", "--scan", required=True, help="Scan Name: whole or partial")
ap.add_argument("-o", "--output", required=True, help="Output Type:  csv,nessus,html")
args = vars(ap.parse_args())

# I don't think we need this - but every time I remove it I find out I needed it
def file_date(udate):
  cdate = datetime.datetime.fromtimestamp(udate)
  return cdate.strftime('%Y-%m-%d %H:%M:%S')

#   Chatter

hello = '##########################################################################\n'
hello +='#                                                                        #\n'
hello +='#                          Nessus Professional                           #\n'
hello +='#                      Vulnerability Scan Download                       #\n'
hello +='#                                  v.02                                  #\n'
hello +='#                                                                 |      #\n'
hello +='#                                                                /|\ ~es #\n'
hello +='##########################################################################\n'

holdOnCowboy = '''++++ It looks like the environment isn\'t set up yet.'
Please set up the environmental variables first. (npURL, put_files, ak, and sk)
Once those are set you should be on your way.'''

intermission ='Requests sent.\nNo errors received.\nExport of results is queued up.\nInitiating download...'

usage = '''\n usage% python3 npScsanExport.py'- ScanNametoSearch -o nessus|csv
switchs:
            -s          Search this specific scan *see below 
            -o          Output Type options:  nessus, csv
            *anything with a space needs to be quoted - double quotes if running on Windows'''



#       Variables

outputTypes = ['csv','nessus','html']
timecode = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
cwd = os.getcwd()
workingFile = timecode+'.txt'
#   These need to be uncommented and completed before first run
#npURL = '' # Base URL and port if using one -- no trailing /
#put_files = cwd+'/downloads/' # Change or keep
#ak = '' # Fill me in
#sk = ''# Fill me in

# Leave this one alone Please
pickUp_file = open(cwd+'/'+workingFile, 'w')

# Environment check
try:
    ak
    sk
    put_files
    npURL
except:
    print(holdOnCowboy)
    exit()

sscan = args['scan'].strip()
stype = args['output'].strip().lower()
if stype not in outputTypes:
    print(stype+' is not a supported output type.  Please use a supported output type.')
    for x in outputTypes:
        print('        -o'+x)
        exit()
    
h_key_data = 'accessKey='+ak+'; secretKey='+sk
check_url = npURL+'/scans'

proxies = {}
proxies['http']= ''
proxies['https']= ''

headers = {}
headers['content-type']= 'application/json'
headers['x-apikeys']= h_key_data

#	report filter info
if stype == 'html':
  # added thanks to @AshDee
  # Can change to different chapter type here
  # vuln_hosts_summary, vuln_by_host, compliance_exec, remediations, vuln_by_plugin, compliance
  report_data = '{"filter.search_type":"or","format":"'+stype+'","chapters":"vuln_hosts_summary"}'
else:
  report_data = '{"filter.search_type":"or","format":"'+stype+'"}'

#   Set up the scans to queue based on the search criteria
def scan_history(url,s_name,scan_id):
  r = requests.get(url, proxies=proxies, headers=headers, verify=False)
  data = r.json()
  history_list = []
  try:
    data["history"] is not None
    for d in data["history"]:
      history_list.append(int(d['history_id']))
    if len(history_list) != 0:
      latest_history = max(history_list)
      for h in data["history"]:
        # Thanks to https://github.com/A-Kod we get the lastest, not the first
        if  h["status"] == 'completed' and h["history_id"] == latest_history:
          h_id = str(h["history_id"])
          s_start = file_date(h["creation_date"])
          s_end = file_date(h["last_modification_date"])
          s_status = h["status"]
          post_url = url+'/export?history_id='+h_id
          p = requests.post(post_url, proxies=proxies, headers=headers, data=report_data, verify=False)
          if p.status_code == 200:
              file_data = p.json()
              report_file = str(file_data["file"])
              pickUp_file.write(s_name+','+scan_id+','+report_file+','+stype+'\n')
              break
          else:
              print('Something went wrong with the request for '+post_url)
              print(p.status_code)
              break
    else:
      print('...')
    except:
      print("We can't find any history. Here is the raw data received to look through\n%s")%str(data)

# 	Status Check
def status_check(scan,file):
  url = npURL+'/scans/'+scan+'/export/'+file+'/status'
  r = requests.get(url, proxies=proxies, headers=headers, verify=False)
  data = r.json()
  if r.status_code == 200:
        if data["status"] == 'loading':
            return 'loading'
        else:
            return 'gtg'
  else:
        print('Error code: '+str(r.status_code))
        exit()

#	Download the files
def download_report(url,report,con):
  r = requests.get(url, proxies=proxies, headers=headers, verify=False)
  local_filename = put_files+timecode+'-'+report+'.'+con
  open(local_filename, 'wb').write(r.content)
  print('Downloading and putting together the pieces of your report.')
  print('Report Name: '+report)

def parse_json(url,scan):
  r = requests.get(url, proxies=proxies, headers=headers, verify=False)
  if r.status_code != 200:
    print('Error - if the code below is 401 - there was a login issue.\nCheck your keys.')
    print(url)
    print(str(r.status_code))
    exit()

  data = r.json()
  for d in data["scans"]:
    if scan in d["name"]:
      s_name = d["name"].strip()
      s_id = str(d["id"])
      scan_url = npURL+'/scans/'+s_id
      scan_history(scan_url,s_name,s_id)


# All the above for this...

print(hello)
print('Searching for scans: "'+sscan+ '".\nOutput will be: '+stype+'\nPlease be patient while results are queued up.')
parse_json(check_url,sscan)
pickUp_file.close()
print(intermission)
time.sleep(5)
# end queying up the data for export
# begin downloading it

get_files = open(cwd+'/'+workingFile, 'r')

for line in get_files:
    line = line.strip()
    params = line.split(",")
    r_name = params[0].replace(' ','-').replace('\\','-').replace('\/','-').lower()
    scan = params[1]
    file = params[2]
    ftype = params[3]
    download = npURL+'/scans/'+scan+'/export/'+file+'/download'
    while True:
         downloadStatus = status_check(scan,file)
         if downloadStatus == 'gtg':
            print('File is ready for download. Calling interweb monkeys to download.\n')
            download_report(download,r_name,ftype)
            break
         else:
            print('The scan is still loading...  We will check again in 2 minutes.\n')
            time.sleep(120)

print('Files are downloaded and pieced together. Pick them up in '+put_files)
# Clean Up
get_files.close()
os.remove(cwd+'/'+workingFile)
