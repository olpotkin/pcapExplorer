
# Traffic capturing and analysis filter

[image1]: ./imgs/cap-report-example.png

Setup:

* Update macOS (Install the latest version of macOS)
* Install Wireshark (latest version)
* Open project (e.g. in PyCharm), check all dependencies (python 2.7)
* Config testing script by adding parameters to config.json file

## Instruction:

1. Set 'source IP', 'destination IP', 'link to the App Store' (set "#" if not available)  in `config.json`.

2. Run Termilal and use command: `python main.py`

3. Capturing just started. 
You need to send data between two IPs/devices (it;s possible to chang capturing time in `config.json` file)

4. After the end of a capturing process and processing/filtering of captured data 
you will see the capturing report in your browser:

![alt text][image1]
