######################
# Oleg Potkin        #
# olpotkin@gmail.com #
######################


import os
import subprocess
import time
import json
import webbrowser

from reporting import Reporting

# Start tcpdump
# Command >> tcpdump -I -i en1 -w ~/Desktop/output.pcap
time.sleep(0.5)
print("\n==============================")
print("| Fastlane Test for iOS 10+ app |")
print("==============================\n")

# Apply settings
with open('config.json') as jsonConfig:
    configDict = json.load(jsonConfig)
    for item in configDict:
        try:
            d = {
                'src_ip': str(item["src_ip"]),
                'dst_ip': str(item["dst_ip"]),
                'cap_time': str(item["cap_time"]),
                'proc_time': str(item["proc_time"]),
                'appstore_link': str(item["appstore_link"])
            }
            configDict = []
            configDict.append(d)
        except:
            continue

print("1-st device IP: {0}".format(configDict[0]['src_ip']))
print("2-nd device IP: {0}".format(configDict[0]['dst_ip']))
print("Capturing time: {0}".format(int(configDict[0]['cap_time'])))
print("Processing time: {0}".format(int(configDict[0]['proc_time'])))
print("Load configuration: done\n")

# Capturing process
print("Capturing...\n")
p = subprocess.Popen(['tcpdump', "-I", "-i", "en0",
                      '-w', 'cap.pcap'], stdout=subprocess.PIPE, shell=False)
time.sleep(int(configDict[0]['cap_time']))  # Capturing traffic for N seconds
p.terminate()                               # Stop tcpdump
time.sleep(2)

# Check if the subprocess has terminated
# if not - force kill
try:
    os.kill(p.pid, 0)
    p.kill()
    print("\nCapturing: done\n")            # Force killed
except OSError, e:
    print("\nCapturing: done\n")

# Start tshark (convert .pcap to .json)
# Command >> tshark -r cap.pcap -Tjson > cap.json
tsharkCommand = ['tshark','-r', 'cap.pcap', '-Tjson',
                 '-e', 'frame.number',
                 #'-e', 'wlan_radio.channel',
                 '-e', 'wlan.qos',
                 '-e', 'wlan.qos.priority',
                 #'-e', 'ip.version',
                 '-e', 'ip.src',
                 '-e', 'ip.dst',
                 '-e', 'data.len',
                 '-e', 'ip.dsfield.dscp',
                 '-e', 'ip.len']

tsharkOutput = open("cap.json", "wb")
p = subprocess.Popen(tsharkCommand, stdout=tsharkOutput)

print "Start processing: done\n"
print "Processing...\n"
time.sleep(int(configDict[0]['proc_time']))

# Analytics
# Open json
with open('cap.json') as json_data:
    dict = json.load(json_data)
    # Filter IP packs with QoS:
    #   - Src IP
    #   - Dst IP
    #   - Frame number
    #   - Valid frame number (IP pkg)
    #   - DSCP value
    #   - QoS value
    #   - ip packet length
    iterator = 1
    dict_filter_1 = []
    for item in dict:
        try:
            d = {
                'ip.src': item["_source"]["layers"]["ip.src"][0],
                'ip.dst': item["_source"]["layers"]["ip.dst"],
                'frame.number': item["_source"]["layers"]["frame.number"],
                'valid_frame.number': iterator,
                'ip.dsfield.dscp': item["_source"]["layers"]["ip.dsfield.dscp"],
                'wlan.qos.priority': item["_source"]["layers"]["wlan.qos.priority"],
                'ip.len': item["_source"]["layers"]["ip.len"]
            }
            dict_filter_1.append(d)
            iterator += 1
        except:
            continue

# Filter data for processing (delete elements: [], 'u)
captureFilteredDict = []
for item in dict_filter_1:
    d = {
        'VALID_FRAME_N': str(item["valid_frame.number"]),       # IP Package
        'FRAME_N': str(item["frame.number"][0]),                # Frame
        'IP_SRC': str(item["ip.src"]),
        'IP_DST': str(item["ip.dst"][0]),
        'IP_DSCP': str(item["ip.dsfield.dscp"][0]),
        'QOS': str(item["wlan.qos.priority"][0]),
        'IP_LEN': str(item["ip.len"][0])
    }
    captureFilteredDict.append(d)

# Reporting: Create report file
flReport = Reporting("report.html", configDict, captureFilteredDict)
flReport.doReport()                                 # Generate report

print("Report created. Opening in browser...\n")
time.sleep(0.5)

new = 2                                             # Open in a new tab, if possible
url = "file://" + os.path.realpath("report.html")   # URL to report file
webbrowser.open(url, new=new)                       # Open report in web-browser
