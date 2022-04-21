'''
University of Georgia
CSCI 8240: Software Security & Cyber Forensics
MalDash: A web application for network capture analysis.
Usage: $python3 app.py
Server runs at http://127.0.0.1:5000
'''

# import related libraries
from pydoc import source_synopsis
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
from collections import Counter
import country_converter as coco
from ip2geotools.databases.noncommercial import DbIpCity

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
            direct_path = f"{os.getcwd()}/uploaded_captures"
            app.config["FILE_UPLOADS"] = rf"{direct_path}"
            file.save(os.path.join(app.config["FILE_UPLOADS"], file.filename))

            # IMPORTANT: Load Scapy TLS layer
            load_layer('tls')

            # Unpack capture with Scapy
            path = "uploaded_captures/"+file.filename
            packets = rdpcap(path)

            '''
            *****************************************************************************************
            Next section of code is where we query VirusTotal for things like file hashes, malware detections, etc.
            *****************************************************************************************
            '''
            
            # Get hashes (md5, sha256, sha1)
            url = 'https://www.virustotal.com/vtapi/v2/file/scan'
            params = {'apikey': VT_API_KEY}
            files = {'file':(path, open(path, 'rb'))}
            response = requests.post(url=url,files=files,params=params)
            
            md5 = response.json()['md5']
            sha1 = response.json()['sha1']
            sha256 = response.json()['sha256']

            # Generate figure based on VT scan results
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': VT_API_KEY,'resource':md5}
            response = requests.get(url,params=params)
            vendors = []
            for key in response.json():
                if key == 'scans':
                    for vendor in response.json()[key]:
                        vendors.append(vendor)
            report_tuple = (response,vendors)
            detections = ''
            detected_vendors = []
            results = []


            for vendor in report_tuple[1]:
                if report_tuple[0].json()['scans'][vendor]['detected']:
                    detections += '['+ vendor + ':  ' + report_tuple[0].json()['scans'][vendor]['result'] + ']'
                    detected_vendors.append(vendor)
                    results.append(report_tuple[0].json()['scans'][vendor]['result'])

            character = ['Detections']
            value = []
            for vendor in vendors:
                character.append(vendor)
            parent = []
            # create parents array
            for vendor in vendors:
                if vendor in detected_vendors:
                    character.append(response.json()['scans'][vendor]['result'])
            counter = 0
            for child in character:
                if child == 'Detections':
                    parent.append("")
                    value.append(10)
                elif child in results:
                    parent.append(detected_vendors[counter])
                    counter += 1
                    value.append(16)
                else:
                    parent.append("Detections")  
                    value.append(4)                                  
            data= dict(
                character = character,
                parent=parent,
                value=value
            )
            fig =px.sunburst(
                data,
                names='character',
                parents='parent',
                values='value',
                width=800, 
                height=400
            )
        
            # gen json to pass to html
            vt_figure = json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)
            

            '''
            *****************************************************************************************
            Next section of code is where we analyze and track each packet in the capture using Scapy
            *****************************************************************************************
            '''
            # Keep track of spot in capture
            total_packets=0
            pkt_index = -1
            total_len = 0
            avg_len = 0

            # Basic Packet Types
            ethernet_pkts = 0
            ip_pkts = 0 
            tcp_pkts = 0
            udp_pkts = 0
            tls_pkts = 0

            # IP Trackers
            source_ips = []
            tls_ips = []

            # Indices of various information
            msg_indices = []
            data_indices = []
            tls_indices = []

            # TLS specific info
            tls_handshakes = 0
            tls_app_data = 0
            tls_cipher_spec = 0
            tls_alert = 0
            all_ciphers = []
            all_servernames = []
            total_encrypt_len = 0
            tls_pkt_sizes = []

            # Set up log files
            logpath = './logs'
            filename = "[TLS-DUMP]" + file.filename + '.txt'
            completeName = os.path.join(logpath,filename)
            summary_filename = "[SUMMARY]" + file.filename.split('.')[0] + '.txt'
            summary_completeName = os.path.join(logpath,summary_filename)
            dump = open(completeName, "w",encoding='utf-8')
            summary_log = open(summary_completeName, "w")

            # Iterate over all packets in capture
            for i, p in enumerate(packets):

                total_packets += 1
                pkt_index += 1

                # Track basic packet breakdown
                if Ether in p:
                    ethernet_pkts += 1
                if IP in p:
                    ip_pkts += 1
                    source_ips.append(p[IP].src)           # detect IP
                    total_len += p[IP].len
                    avg_len += 1
                if TCP in p:
                    tcp_pkts += 1
                if UDP in p:
                    udp_pkts += 1
                if TLS in p:

                    tls_pkts += 1
                    total_encrypt_len += p[TLS].len
                    # update stats
                    tls_pkt_sizes.append(p[TLS].len)
                    tls_indices.append(pkt_index)
                    msg_index = 0
                    encrypt_index = 0
                    tls_ips.append(p[IP].src)

                    # create tuple
                    label = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
                    # write to tls dump
                    dump.write("PKT INDEX: ")
                    dump.write(str(pkt_index))
                    dump.write('-->')
                    dump.write(str(label))
                    dump.write('\n')
                    # change standard output to the file for a second so scapy show() dumps to our log
                    save_stdout = sys.stdout
                    sys.stdout = dump
                    p[TLS].show()
                    # change standar output back
                    sys.stdout = save_stdout
                        
                    # track types of TLS messages
                    if p[TLS].type == 23:                   # app data pkt
                        tls_app_data += 1
                    if p[TLS].type == 22:                   # handhsake pkt
                        tls_handshakes += 1
                        msg = p[TLS].msg
                        msg = str(msg)
                        if 'server_hello' in msg:
                            #extract cipher
                            if 'cipher' in msg:
                                i = msg.index('cipher')
                                next_sp = msg.index(" ",i)
                                cipher = msg[i+7:next_sp]
                                all_ciphers.append(cipher)
                        if "servernames=" in msg:
                            # extract server
                            i = msg.index('servernames=')
                            server = msg[i+15:msg.index("'",i+15)]
                            all_servernames.append(server)
                    if p[TLS].type == 20:                   # change cipher spec pkt
                        tls_cipher_spec += 1
                    if p[TLS].type == 21:                   # TLS alert pkt
                        tls_alert += 1
                        
                    # track index for heatmap
                    tls_message = str(p[TLS].msg)
                    if "msgtype" in tls_message:
                        msg_index += 10
                    if "msglen" in tls_message:
                        msg_index += 10
                    if "version" in tls_message:
                        msg_index += 10
                    if "gmt_unix_time" in tls_message:
                        msg_index += 10
                    if "random_bytes" in tls_message:
                        msg_index += 10
                    if "ciphers" in tls_message:
                        msg_index += 10
                    if "sid" in tls_message:
                        msg_index += 10
                    if "ext" in tls_message:
                        msg_index += 10
                    msg_indices.append(msg_index)
                    # calculate data index
                    encrypt_index = p[TLS].len / 18.1875
                    data_indices.append(encrypt_index) 
                    
            dump.close()
            #calc avg pkt len
            avg_len = int(total_len/avg_len)
            avg_encrypted_len = int(total_encrypt_len/tls_pkts)

            # Create summary log file
            text = ""
            text += 'Capture summary for file: ' + str(file.filename)
            text += '\nTotal packets detected: ' + str(total_packets)
            text += '\nEthernet packets detected: ' + str(ethernet_pkts)
            text += '\nUDP packets detected: ' + str(udp_pkts)
            text += '\nTCP packets detected: ' + str(tcp_pkts)
            text += '\nTLS packets detected: ' + str(tls_pkts)
            text += '\n\tTLS Handshake Packets detected: ' + str(tls_handshakes)
            text += '\n\tTLS Cipher Specification Packets detected: ' + str(tls_cipher_spec)
            text += '\n\tTLS Application Data Packets detected: ' + str(tls_app_data)
            text += '\n\tTLS Alerts detected: ' + str(tls_alert)
            text += '\nAverage Packet Length: ' + str(avg_len)

            summary_log.write(text)
            summary_log.close()


            '''
            *****************************************************************************************
            Next section of code is where we build different graphics using Plotly
            *****************************************************************************************
            '''

            '''
            ******Most Common IP Addresses******
            '''
            all_count = Counter()
            for ip in source_ips:
                all_count[ip] += 1
            # data for plotly
            xData = []
            yData = []
            
            # Aggregate data
            for ip, count in all_count.most_common(10):
                xData.append(ip)
                yData.append(count)
                    
            # create dataframes
            df_ip = pd.DataFrame({"ip":xData, "freq":yData})
            
            # create plotly objects
            normal_ip_fig = px.bar(df_ip,x="ip",y="freq",title="Source IP Addresses (All Packets)",
                labels={
                    "ip":"IP Address",
                    "freq":'Frequency'
                    })
            
            # gen json to pass to html
            common_ips = json.dumps(normal_ip_fig,cls=plotly.utils.PlotlyJSONEncoder)

            
            '''
            ******Most Common TLS IP Addresses******
            '''
            tls_count = Counter()
            for ip in tls_ips:
                tls_count[ip] += 1
            tls_xData = []
            tls_yData = []
            for ip, count in tls_count.most_common(10):
                tls_xData.append(ip)
                tls_yData.append(count)
            df_tls_ip = pd.DataFrame({"ip": tls_xData,"freq":tls_yData})
            # create figure
            tls_ip_fig = px.bar(df_tls_ip,x="ip",y="freq",color_discrete_sequence =['red']*len(df_tls_ip),title="Source IP Addresses (TLS Packets)",
                labels={
                    "ip":"IP Address",
                    "freq":'Frequency'
                    })

            # gen json to pass to html
            tls_ips = json.dumps(tls_ip_fig,cls=plotly.utils.PlotlyJSONEncoder)

            '''
            ******TLS Packet Size by Index******
            '''
            df = pd.DataFrame({"index":tls_indices, "size":tls_pkt_sizes})
            area = px.area(df,x="index",y="size",title="TLS Packet Sizes by Index",color_discrete_sequence=['indigo']*len(df))
        
            # gen json to pass to html
            tls_sizes = json.dumps(area,cls=plotly.utils.PlotlyJSONEncoder)

            '''
            ******TLS Packet Size Distribution******
            '''
             # create figure
            df = pd.DataFrame({"sizes":tls_pkt_sizes})
            fig = px.violin(df, x="sizes",title='TLS Packet Size Distribution',color_discrete_sequence=['teal']*len(df))

            # gen json to pass to html
            violin_json = json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

            '''
            ******TLS MSG Type Breakdown******
            '''
            # chart values
            df = []
            df.append(tls_handshakes)
            df.append(tls_cipher_spec)
            df.append(tls_app_data)
            df.append(tls_alert)
            # chart labels
            names = ['TLS Handshakes','Change Cipher Specification', 'TLS Application Data', 'TLS Alerts']
            # create figure
            tls_msgtype_fig = px.pie(values=df, names=names,title='TLS Message Types Detected')

            # gen json to pass to html
            # store image
            msgtype_json = json.dumps(tls_msgtype_fig,cls=plotly.utils.PlotlyJSONEncoder)

            '''
            ******Most Common TLS Servers******
            '''
            server_cnt = Counter()
            # tally servers
            for s in all_servernames:
                server_cnt[s] += 1
            
            stages = []
            occur = []
            for server, freq in server_cnt.most_common(5):
                stages.append(server)
                occur.append(freq)
            data = dict(
                number=occur,
                servers=stages)
            # create figure
            fig = px.funnel(data, x='number', y='servers',title="Most Common TLS Servers",color_discrete_sequence=['seagreen']*len(stages))

            # gen json to pass to html
            funnel_json = json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

            '''
            ******TLS Heatmaps******
            '''

            # Data Heatmap
            data = [data_indices]
            # create figure
            heatmap = px.imshow(data,labels=dict(x="Packet Index", color="Intensity"),
            x=tls_indices,
            y=['TLS encrypted data'])
    
            # gen json to pass to html
            data_heatmap = json.dumps(heatmap,cls=plotly.utils.PlotlyJSONEncoder)

            # MSG Heatmap
            data = [msg_indices]
            # create figure
            heatmap = px.imshow(data,labels=dict(x="Packet Index", color="Intensity"),
            x=tls_indices,
            y=['TLS msg field info  '])

            # gen json to pass to html
            msg_heatmap = json.dumps(heatmap,cls=plotly.utils.PlotlyJSONEncoder)

            '''
            ******All Country Codes******
            '''
            countryX = []
            countryY = []

            params = ['query', 'status', 'country', 'countryCode', 'city', 'timezone', 'mobile']


            for ip, count in all_count.most_common(6):

                resp = requests.get('http://ip-api.com/json/' + ip, params={'fields': ','.join(params)})
                info = resp.json()
                if(info['status'] == "success"):
                    #print(info)
                    countryCode = info['countryCode']
                    countryX.append(countryCode)
                    countryY.append(count)

            df = pd.DataFrame({"country": countryX,"freq":countryY})
            # create figure
            country_fig = px.bar(df,x="country",y="freq",color_discrete_sequence =['orange']*len(df),title="Common Country Codes",
                labels={
                    "ip":"IP Address",
                    "freq":'Frequency'
                    })
            country_fig.update_layout(font=dict(family="Arial",color='black'))

            # gen json to pass to html
            all_country_bar = json.dumps(country_fig,cls=plotly.utils.PlotlyJSONEncoder)

            iso3_codes = coco.convert(names=countryX,to='ISO3')
            full_country_names = coco.convert(names=iso3_codes,to='name_short')
            df = pd.DataFrame({"countryCode": iso3_codes,"freq":countryY,"proper_names":full_country_names})

            fig = px.scatter_geo(df, locations="countryCode",
                            hover_name="proper_names", # column added to hover information
                            size="freq", # size of markers
                            title="IP Address Origins (All Source IPs)",
                            projection="natural earth")
            fig.update_layout(font=dict(family="Arial",color='black'))

            # gen json to pass to html

            all_map_json = json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

            '''
            ******TLS Country Codes******
            '''
            countryX = []
            countryY = []

            params = ['query', 'status', 'country', 'countryCode', 'city', 'timezone', 'mobile']

            #print('ip',tls_count.most_common()[0])


            for ip, count in tls_count.most_common(6):

                #print(ip)
                resp = requests.get('http://ip-api.com/json/' + ip, params={'fields': ','.join(params)})
                info = resp.json()
                if(info['status'] == "success"):
                    #print(info)
                    countryCode = info['countryCode']
                    countryX.append(countryCode)
                    countryY.append(count)

            df = pd.DataFrame({"country": countryX,"freq":countryY})
            # create figure
            country_fig = px.bar(df,x="country",y="freq",color_discrete_sequence =['orange']*len(df),title="TLS Country Codes",
                labels={
                    "ip":"IP Address",
                    "freq":'Frequency'
                    })
            country_fig.update_layout(font=dict(family="Arial",color='black'))

            # gen json to pass to html
            country_json = json.dumps(country_fig,cls=plotly.utils.PlotlyJSONEncoder)

            iso3_codes = coco.convert(names=countryX,to='ISO3')
            full_country_names = coco.convert(names=iso3_codes,to='name_short')
            df = pd.DataFrame({"countryCode": iso3_codes,"freq":countryY,"proper_names":full_country_names})

            fig = px.scatter_geo(df, locations="countryCode",
                            hover_name="proper_names", # column added to hover information
                            size="freq", # size of markers
                            title="IP Address Origins (TLS Message IPs)",
                            projection="natural earth")
            fig.update_layout(font=dict(family="Arial",color='black'))

            # gen json to pass to html

            tls_map_json = json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


            return render_template('report.html',filename=file.filename,total=total_packets,md5=md5,sha256=sha256,sha1=sha1,vendor_chart=vt_figure, ethernet_pkts=ethernet_pkts,
                                    ip_pkts=ip_pkts,tcp_pkts=tcp_pkts,udp_pkts=udp_pkts,tls_pkts=tls_pkts,common_ips=common_ips, tls_ips=tls_ips, tls_sizes=tls_sizes,
                                    tls_violin=violin_json, tls_msg=msgtype_json, servers=funnel_json, data_heatmap=data_heatmap,
                                    msg_heatmap=msg_heatmap, tls_country_bar=country_json, tls_map=tls_map_json, all_country_bar=all_country_bar, all_map_json=all_map_json
                                    )
            


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

   
