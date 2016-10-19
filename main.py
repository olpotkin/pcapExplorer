######################
# Oleg Potkin        #
# olpotkin@gmail.com #
######################

import subprocess
import time

# Start tcpdump
# Command >> tcpdump -I -i en1 -w ~/Desktop/output.pcap
p = subprocess.Popen(['tcpdump', "-I", "-i", "en1",
                      '-w', 'cap.pcap'], stdout=subprocess.PIPE)
time.sleep(20)      # Capturing traffic for 20 seconds
p.terminate()       # Stop tcpdump


# TODO: 3. Start tshark (convert .pcap to .json)

# TODO: 4. Analytics
