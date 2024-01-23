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
#               -o       Output Type options:  nessus, csv, pdf, html
#               -f       Folder to output the nessus files
#               -n       Nessus full URL (Protocol + IP|Domain + Port)
#
#   notes:      fill in the following variables as needed per environment
#               npURLdefault    <-- Nessus full URL (Protocol + IP|Domain + Port)
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
ap.add_argument("-f", "--folder", required=False, help="Output Folder")
ap.add_argument("-n", "--nessusurl", required=False, help="Full Nessus URL")
ap.add_argument("-t", "--type", metavar="REPORT_TYPE", required=False, choices=['vuln_hosts_summary','vuln_by_host','compliance_exec','remediations','vuln_by_plugin','compliance'], help="Type of report to generate.  Options are: vuln_hosts_summary, vuln_by_host, compliance_exec, remediations, vuln_by_plugin, compliance.  Defaults to vuln_hosts_summary")
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

usage = '''\n usage% python3 npScsanExport.py'- ScanNametoSearch -o nessus|csv|html|pdf
switchs:
            -s          Search this specific scan *see below 
            -o          Output Type options:  nessus, csv, html, pdf
            -f          Output Folder
            -n          Nessus Full URL
            *anything with a space needs to be quoted - double quotes if running on Windows'''



#       Variables
outputTypes = ['csv','nessus','html','pdf']
timecode = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
cwd = os.getcwd()
workingFile = timecode+'.txt'

# These are grabbed from the shell environment.
# Undefined vars are empty-string, and they will cause a failure below
npURLdefault = os.getenv('npURLdefault')
ak = os.getenv('ak')
sk = os.getenv('sk')

npURL = args['nessusurl'].rstrip('/') if args['nessusurl'] else npURLdefault
put_files = args['folder'] if args['folder'] else cwd

# Leave this one alone Please
pickUp_file = open(os.path.join(cwd, workingFile), 'w')

# Environment check
if not ak or not sk or not npURL:
  print(holdOnCowboy)
  exit()

sscan = args['scan'].strip()
stype = args['output'].strip().lower()
if stype not in outputTypes:
    print(stype+' is not a supported output type.  Please use a supported output type.')
    for x in outputTypes:
        print('        -o'+x)
        exit()

reportType = "vuln_hosts_summary"
if args['type']:
    reportType = args['type']


h_key_data = 'accessKey='+ak+'; secretKey='+sk
check_url = npURL+'/scans'

proxies = {}
proxies['http']= ''
proxies['https']= ''

headers = {}
headers['content-type']= 'application/json'
headers['x-apikeys']= h_key_data

#	report filter info
if stype == 'html' or stype == 'pdf':
  # added thanks to @AshDee
  # Can change to different chapter type here
  # vuln_hosts_summary, vuln_by_host, compliance_exec, remediations, vuln_by_plugin, compliance
  report_data = '{"filter.search_type":"or","format":"'+stype+'","chapters":"'+reportType+'"}'
else:
  report_data = '{"filter.search_type":"or","format":"'+stype+'"}'

#   Set up the scans to queue based on the search criteria
def scan_history(url,s_name,scan_id):
  r = requests.get(url, proxies=proxies, headers=headers, verify=False)
  data = r.json()
  try:
    if data["history"]:
      # If the latest scan did not completed (run by mistake and stopped or failed for some reason) it won't download it
      # simple solution would be to invert the history so it starts from the most recent and checks wether it was succesfull
      rev_scan_history = data["history"][::-1]
      for h in rev_scan_history:
        if  h["status"] == 'completed':
          h_id = str(h["history_id"])
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
    print(f"We can't find any history. Here is the raw data received to look through\n{data}")

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
  local_filename = os.path.join(put_files, f'{timecode}-{report}.{con}')
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

get_files = open(os.path.join(cwd, workingFile), 'r')

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
os.remove(os.path.join(cwd, workingFile))
