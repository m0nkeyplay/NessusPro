# NessusPro
scripts to use against the Nessus Professional API

> npScanExport.py

**This script will pull down all vulnerability data from a scan in csv or nessus format based on a scan name**

*usage* `python3 npScanExport.py -s ScanNametoSearch -o nessus|csv|html|pdf`

******switchs:******    

               -s       Search this specific scan : If using widows and space is in the name, use double quotes
               -o       Output Type options:  nessus, csv, html, pdf
               -f       Folder to output the nessus files (Optional)
               -n       Nessus full URL (Protocol + IP|Domain + Port) (Optional if hardcoded - check next note)
 
******notes:******      fill in the following variables as needed per environment

               npURLdefault    <-- Base URL for the Nessus Professional instance no trailing /
               ak              <-- Access Key
               sk              <-- Secret Key
               proxies         <-- If you use a proxy, set it here.
