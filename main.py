######################
# Oleg Potkin        #
# olpotkin@gmail.com #
######################

import os
import subprocess
import time

# Start tcpdump
# Command >> tcpdump -I -i en1 -w ~/Desktop/output.pcap
p = subprocess.Popen(['tcpdump', "-I", "-i", "en1",
                      '-w', 'cap.pcap'], stdout=subprocess.PIPE, shell=False)
time.sleep(20)      # Capturing traffic for 20 seconds
p.terminate()       # Stop tcpdump
time.sleep(0.5)

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
tsharkCommand = ['tshark','-r', 'cap.pcap', '-Tjson']
tsharkOutput = open("cap.json", "wb")
p = subprocess.Popen(tsharkCommand, stdout=tsharkOutput)


# TODO: 4. Analytics
