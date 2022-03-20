'''
University of Georgia
CSCI 8240: Software Security & Cyber Forensics
MalDash: A web application for network capture analysis.
Usage: $python3 app.py
Server runs at http://127.0.0.1:5000
'''

# import related libraries
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
@app.route('/', methods=["GET", "POST"])
def maldash():

    

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

   