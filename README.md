# NessusPro
scripts to use against the Nessus Professional API

> npScanExport.py

**This script will pull down all vulnerability data from a scan in csv or nessus format based on a scan name**

*usage* `python3 npScanExport.py -scan ScanNametoSearch -o nessus|csv`

******switchs:******    

               -s       Search this specific scan : If using widows and space is in the name, use double quotes
               -o       Output Type options:  nessus, csv
 
******notes:******      fill in the following variables as needed per environment

               npURL           <-- Base URL for the Nessus Professional instance no trailing /
               pickup_file     <-- Where the export data goes to be picked up
               ak              <-- Access Key
               sk              <-- Secret Key
               proxies         <-- If you use a proxy, set it here.
