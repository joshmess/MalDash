'''
University of Georgia
CSCI 8240: Software Security & Cyber Forensics
MalDash: A web application for network capture analysis.
Usage: $python3 app.py
Server runs at http://127.0.0.1:5000
'''

# import related libraries
from struct import pack
from flask import Flask, render_template, request
import sys, os
from scapy.all import *
import scapy
import plotly.express as px
import pandas as pd
import json
import plotly
import requests

# Important Variables
VT_API_KEY = 'fff1422d2f248f2713f21bbe99f855e4ec7695f56b85c56fbbf002a57eac93a5'


# Set up app with Flask
app = Flask(__name__)

   
# Mainpage endpoint
@app.route('/', methods=['GET', 'POST'])
def maldash():

    # Detect if a file is uploaded
    if request.method == 'POST':
        # Extract uploaded files
        if request.files:
            file = request.files["file"]
            # Check name of upload
            if file.filename == "":
                err_msg = "Must upload a capture!"
                return render_template('mainpage.html',err_msg=err_msg)
            
            # Check file type of upload
            extension = file.filename.split('.')[1]
            if extension != 'pcap' and extension != 'pcapng':
                err_msg = "Must upload a pcaket capture (pcap or pcapng)"
                return render_template('mainpage.html',err_msg=err_msg)
        
            # Save file to machine
            direct_path = f"{os.getcwd()}\\uploaded_captures"
            app.config["FILE_UPLOADS"] = rf"{direct_path}"
            file.save(os.path.join(app.config["FILE_UPLOADS"], file.filename))

            # IMPORTANT: Load Scapy TLS layer
            load_layer('tls')

            # Unpack capture with Scapy
            path = "uploaded_captures/"+file.filename
            packets = rdpcap(path)

            # Query VirusTotal for File properties
            

            total_packets=0

            # Analyze Packets
            for i, p in enumerate(packets):

                total_packets += 1

            return render_template('report.html',filename=file.filename,total=total_packets)


    # Assuming no POST request, render main (upload) page
    return render_template('mainpage.html')



   
# About page endpoint
@app.route('/about')
def about():

    # Assuming no POST request, render main (upload) page
    return render_template('about.html')

if __name__ == "__main__":
   app.run(debug=True)

if __name__ == "__main__":
   app.run(debug=True)

   
