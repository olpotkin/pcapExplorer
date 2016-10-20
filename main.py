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
time.sleep(1)

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
time.sleep(1)


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
    for item in dict:
        try:
            print item["_source"]["layers"]["ip.src"]
            print item["_source"]["layers"]["ip.dst"]
            print item["_source"]["layers"]["wlan.qos.priority"]
            print item["_source"]["layers"]["frame.number"]
            print iterator
            print "===============\n"
            iterator += 1
        except:
            continue


# 3. Filter by IPs (srs->dst, dst->src)
# 4. Show result list
