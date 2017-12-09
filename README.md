# pcap-visualizer
Python script to produce json based on a PCAP file. 
HTML files can then be used to visualise the data with d3
To be used in environments where you don't want full blown packet capture analysis software

# Requirements
Python Scapy is required which can be installed with pip:

```
pip install scapy
```

Other packages that are required but are installed by default with python:

* os
* sys
* json
* hashlib
* copy

The HTML files get the d3 javascript files from the below URL's:
* d3js.org/d3.v4.min.js
* d3js.org/d3-selection-multi.v1.js
* d3js.org/d3.v3.min.js

# Using
Locate the folder that contains your PCAP file and run the python script

```
pcap-analyzer.py C:\my-pcap-files\
```

The script will then loop through all the pcap files in this folder. Try to make sure the PCAP file are named appropriately so that they are parsed chronologically this will ensure the DNS mapping will be as accurate as possible.

This will create 2 JSON files:
* output.json - This is the main json file which can be used to visualise the data
* dnsMapping.json - This is the IP address to DNS name mappings. The script finds DNS requests in the pcap and maps IP addresses to domain names. This is the output of that mapping

You can then use the below command to launch a simple web server:

```
python -m SimpleHTTPServer
```

Then access the force map on the below url:
http://127.0.0.1:8000/forced.html

and the treemap on:
http://127.0.0.1:8000/treemap.html


The d3 Treemap visualisation is based on http://bl.ocks.org/ganeshv/6a8e9ada3ab7f2d88022
THe d3 forced graph is based on various examples on http://bl.ocks.org