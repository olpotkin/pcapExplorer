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
    print ("Forced kill...\n")
except OSError, e:
    print "Properly terminated...\n"





# TODO: 3. Start tshark (convert .pcap to .json)

# TODO: 4. Analytics
