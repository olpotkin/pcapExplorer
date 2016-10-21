######################
# Oleg Potkin        #
# olpotkin@gmail.com #
######################

import os
import subprocess
import time
import json

# Start tcpdump
# Command >> tcpdump -I -i en1 -w ~/Desktop/output.pcap

p = subprocess.Popen(['tcpdump', "-I", "-i", "en1",
                      '-w', 'cap.pcap'], stdout=subprocess.PIPE, shell=False)
time.sleep(60)      # Capturing traffic for N seconds
p.terminate()       # Stop tcpdump
time.sleep(5)

# Check if the subprocess has terminated
# If not - force kill

try:
    os.kill(p.pid, 0)
    p.kill()
    print ("tcpdump: forced kill...\n")
except OSError, e:
    print "tcpdump: terminated...\n"


# Start tshark (convert .pcap to .json)
# Command >> tshark -r cap.pcap -Tjson > cap.json

tsharkCommand = ['tshark','-r', 'cap.pcap', '-Tjson',
                 '-e', 'frame.number',
                 '-e', 'wlan_radio.channel',
                 '-e', 'wlan.qos',
                 '-e', 'wlan.qos.priority',
                 '-e', 'ip.version',
                 '-e', 'ip.src',
                 '-e', 'ip.dst',
                 '-e', 'data.len']

tsharkOutput = open("cap.json", "wb")
p = subprocess.Popen(tsharkCommand, stdout=tsharkOutput)
time.sleep(15)

# Analytics
# Open json
with open('cap.json') as json_data:
    dict = json.load(json_data)
    # Filter IP packs with QoS:
    #   - Src IP
    #   - Dst IP
    #   - QoS value
    #   - package ID
    iterator = 1
    dict_filter_1 = []
    for item in dict:
        try:
            d = {
                'ip.src': item["_source"]["layers"]["ip.src"][0],
                'ip.dst': item["_source"]["layers"]["ip.dst"],
                'frame.number': item["_source"]["layers"]["frame.number"],
                'valid_frame.number': iterator,
                'wlan.qos.priority': item["_source"]["layers"]["wlan.qos.priority"]
            }
            dict_filter_1.append(d)
            iterator += 1
        except:
            continue

# filter data for processing (delete elements: [], 'u)
dict_filter_2 = []
for item in dict_filter_1:
    d = {
        'VALID_FRAME_N': str(item["valid_frame.number"]),
        'FRAME_N': str(item["frame.number"][0]),
        'IP_SRC': str(item["ip.src"]),
        'IP_DST': str(item["ip.dst"][0]),
        'QOS': str(item["wlan.qos.priority"][0])
    }
    dict_filter_2.append(d)

# 3. Filter by IPs (srs->dst, dst->src)
src_ip = '10.10.20.44'
dst_ip = '10.10.20.47'


# 4. Show results
f = open('report.txt', 'w')

f.write("PKG_ID\t\tIP_PKG_ID\tSRC_IP\t\tDST_IP\t\tQoS MARK \n")
for item in dict_filter_2:
    if (item['IP_SRC'] == src_ip and item['IP_DST'] == dst_ip) or \
            (item['IP_SRC'] == dst_ip and item['IP_DST'] == src_ip):
        #print "{0: <10}{1: <12}{2: <16}{3: <16}{4: <16}".format(
        if item['QOS'] == '5':
            qos_mark = 'QoS (Video): {0}'.format(item['QOS'])
        elif item['QOS'] == '4':
            qos_mark = 'QoS (Video): {0}'.format(item['QOS'])
        elif item['QOS'] == '6':
            qos_mark = 'QoS (Voice): {0}'.format(item['QOS'])
        elif item['QOS'] == '0':
            qos_mark = 'Best effort: {0}'.format(item['QOS'])
        else:
            qos_mark = 'QoS: {0}'.format(item['QOS'])

        f.write("{0: <10}\t{1: <10}\t{2: <14}{3: <14}{4: <14}\n".format(
            item['FRAME_N'],
            item['VALID_FRAME_N'],
            item['IP_SRC'],
            item['IP_DST'],
            qos_mark
        ))
