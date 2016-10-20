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
time.sleep(60)      # Capturing traffic for 30 seconds
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
# 1. Open json
# 2. Filter only packages with QoS marks:
#   - package ID
#   - Src IP
#   - Dst IP
#   - QoS value
#   - DSCP value
# 3. Filter by IPs (srs->dst, dst->src)
# 4. Show result list
