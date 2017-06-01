######################
# Oleg Potkin        #
# olpotkin@gmail.com #
######################
import urllib2
import re


class Reporting:
    # Constructor
    def __init__(self,
                 fileName,                          # Report file name
                 configDict,                        # Global settings
                 captureDict):                      # Filtered capturing result (dict. from json)
        self.fileName = fileName
        self.config = configDict
        self.captureDict = captureDict
        self.appParameters = []                     # Here will be app parameters after iTunes page parsing
        ### List of summary calculations
        # Order:
        # 1. ip_packets (sum)
        # 2. best_effort
        # 3. background
        # 4. video
        # 5. voice

        # Available after doBodyDetails()
        self.reportSummary = []

    def doReport(self):
        self.retrieveItunes()                       # Retrieve app properties from it's iTunes page
        f = open(self.fileName, 'w')                # Open file for writing
        f.write(self.doHeader())                    # Write header

        ### ORDER is IMPORTANT!###
        body_p1 = self.doBody()                     # Report body (part 1) - start
        body_details = self.doBodyDetails()         # Report details (Write <table> with capturing details)
        body_p2 = self.doBodySum()                  # Report body (part 2) - summary
        ##########################

        f.write(body_p1)
        f.write(body_p2)
        f.write(body_details)

        f.write(self.doCloseBody())                 # Close tags
        f.close()                                   # Close report file

# Internal methods:
    def doHeader(self):
        # Add header and Necessary links to stylesheets (css/js)
        repHeader = "<!DOCTYPE html>\n"
        repHeader += "<html lang=\"en\">\n"
        repHeader += "<head>\n"
        repHeader += "<title>Capturing Report</title>\n"
        repHeader += "<meta charset=\"utf-8\">\n"
        repHeader += "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        repHeader += "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\">\n"
        repHeader += "<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js\"></script>\n"
        repHeader += "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js\"></script>\n"
        repHeader += "<style>\n"
        repHeader += ".logo{\n"
        repHeader += "width: 220px;\n"
        repHeader += "height: auto;}\n"
        repHeader += ".open-btn{\n"
        repHeader += "min-width: 120px;\n"
        repHeader += "max-width: 120px;\n"
        repHeader += "background-color: #64BBE3;\n"
        repHeader += "margin-right: 20px;}\n"
        repHeader += ".extra-padding{\n"
        repHeader += "margin-left: 30px;\n"
        repHeader += "margin-top: 30px;\n"
        repHeader += "margin-bottom: 30px;}\n"
        repHeader += ".header{\n"
        repHeader += "width: 100%\n"
        repHeader += "height: 250px;\n"
        repHeader += "padding-top: 20px;\n"
        repHeader += "background-color: #64BBE3}\n"
        repHeader += ".header-1{\n"
        repHeader += "font-size: 24pt;\n"
        repHeader += "margin-left: 30px;\n"
        repHeader += "margin-bottom: -15px;\n"
        repHeader += "color: #FFFFFF;\n"
        repHeader += "letter-spacing: 0.7px;\n"
        repHeader += "font-weight: normal;}\n"
        repHeader += ".header-2{\n"
        repHeader += "font-size: 16pt;\n"
        repHeader += "margin-left: 30px;\n"
        repHeader += "margin-bottom: 20px;\n"
        repHeader += "color: #FFFFFF;\n"
        repHeader += "letter-spacing: 0.7px;\n"
        repHeader += "font-weight: lighter;}\n"
        repHeader += ".summary{\n"
        repHeader += "width: 100%\n"
        repHeader += "height: 250px;\n"
        repHeader += "padding-top: 20px;\n"
        repHeader += "padding-bottom: 20px;\n"
        repHeader += "background-color: #FFFFFF}\n"
        repHeader += ".summary-h-1{\n"
        repHeader += "font-size: 16pt;\n"
        repHeader += "margin-left: 30px;\n"
        repHeader += "margin-bottom: 10px;\n"
        repHeader += "color: #000000;\n"
        repHeader += "letter-spacing: 0.7px;\n"
        repHeader += "font-weight: normal;}\n"
        repHeader += ".summary-h-2{\n"
        repHeader += "font-size: 12pt;\n"
        repHeader += "margin-left: 50px;\n"
        repHeader += "margin-bottom: 10px;\n"
        repHeader += "color: #000000;\n"
        repHeader += "letter-spacing: 0.7px;\n"
        repHeader += "font-weight: lighter;}\n"

        repHeader += ".details{"
        repHeader += "width: 100%;"
        repHeader += "padding-top: 20px;"
        repHeader += "background-color: #F7F7F7;}"
        repHeader += ".details-table{"
        repHeader += "padding-left: 50px;"
        repHeader += "padding-right: 50px;}"
        repHeader += "table{"
        repHeader += "width: 100%;"
        repHeader += "margin-top: 10px;"
        repHeader += "border-collapse: collapse;}"
        repHeader += "thead th{"
        repHeader += "background-color: #64BBE3;"
        repHeader += "font-size: 12pt;\n"
        repHeader += "font-weight: normal;\n"
        repHeader += "color: #FFFFFF;}"
        repHeader += "tbody td{"
        repHeader += "font-size: 10pt;\n"
        repHeader += "font-weight: normal;\n"
        repHeader += "text-align: left;}"

        repHeader += "</style>\n"
        repHeader += "</head>\n"
        return repHeader


    def doBody(self):
        # Report includes:
        # 1. Package number (from .pcap)
        # 2. Source IP
        # 3. Destination IP
        # 4. Protocol (optional)
        # 5. DSCP value
        # 6. QoS value
        # 7. IP Package size (optional)

        # Get parameters from config dictionary
        src_ip = self.config[0]['src_ip']
        dst_ip = self.config[0]['dst_ip']
        cap_time = self.config[0]['cap_time'] + " s."

        repOpenBody = "<body>"
        repOpenBody += "<div class=\"container-fluid\">"
        repOpenBody += "<div class=\"row\">"
        repOpenBody += "<div class=\"col-md-12\">"
        repOpenBody += "<img class=\"logo extra-padding\" src=\"Content/logo.png\">"
        repOpenBody += "</div>"
        repOpenBody += "</div>"
        repOpenBody += "<div class=\"row\">"
        repOpenBody += "<div class=\"col-md-12\">"
        repOpenBody += "<div class=\"header\">"
        repOpenBody += "<div class=\"row\">"

        repOpenBody += "<div class=\"col-md-1\">"
        repOpenBody += "<img class=\"header-1\" style=\"width: 80px; height: auto;  margin-bottom: 10px;\" src=\"{0}\">".format(
            self.appParameters[1])
        repOpenBody += "</div>"

        repOpenBody += "<div class=\"col-md-11\">"
        repOpenBody += "<a href=\"{0}\"><p class=\"header-1\">{1}</p></a><br>".format(
            self.config[0]['appstore_link'],
            self.appParameters[0])
        repOpenBody += "<p class=\"header-2\">Cisco-Apple Fastlane compatibility test</p>"
        repOpenBody += "</div>"

        repOpenBody += "</div>"
        repOpenBody += "</div>"
        repOpenBody += "</div>"
        repOpenBody += "</div>"
        repOpenBody += "<div class=\"row\">"
        repOpenBody += "<div class=\"col-md-12\">"
        repOpenBody += "<div class=\"summary\">"
        repOpenBody += "<div class=\"row\">"
        repOpenBody += "<div class=\"col-md-12\">"
        repOpenBody += "<p class=\"summary-h-1\">Summary:</p>"
        repOpenBody += "</div>"
        repOpenBody += "</div>"
        repOpenBody += "<div class=\"row\">"
        repOpenBody += "<div class=\"col-md-12\">"
        repOpenBody += "<p class=\"summary-h-2\">Device-01 IP: {0}</p>".format(src_ip)
        repOpenBody += "</div>"
        repOpenBody += "</div>"
        repOpenBody += "<div class=\"row\">"
        repOpenBody += "<div class=\"col-md-12\">"
        repOpenBody += "<p class=\"summary-h-2\">Device-02 IP: {0}</p>".format(dst_ip)
        repOpenBody += "</div>"
        repOpenBody += "</div>"

        repOpenBody += "<div class=\"row\">"
        repOpenBody += "<div class=\"col-md-12\">"
        repOpenBody += "<p class=\"summary-h-2\">Capturing time: {0}</p>".format(cap_time)
        repOpenBody += "</div>"
        repOpenBody += "</div>"

        # doBodySum()

        return repOpenBody


    def doBodySum(self):
        # Add summary calculations
        # Call this method after doBodyDetails()
        repBodySum = "<div class=\"row\">"
        repBodySum += "<div class=\"col-md-12\">"
        repBodySum += "<p class=\"summary-h-2\">Captured <b>{0}</b> packets:</p>".format(self.reportSummary[0])
        repBodySum += "</div>"
        repBodySum += "</div>"

        repBodySum += "<div class=\"row\">"
        repBodySum += "<div class=\"col-md-12\">"
        repBodySum += "<p class=\"summary-h-2\">- marked as \"Best effort\": <b>{0}</b> packets</p>".format(self.reportSummary[1])
        repBodySum += "</div>"
        repBodySum += "</div>"

        repBodySum += "<div class=\"row\">"
        repBodySum += "<div class=\"col-md-12\">"
        repBodySum += "<p class=\"summary-h-2\">- marked as \"Background\": <b>{0}</b> packets</p>".format(self.reportSummary[2])
        repBodySum += "</div>"
        repBodySum += "</div>"

        repBodySum += "<div class=\"row\">"
        repBodySum += "<div class=\"col-md-12\">"
        repBodySum += "<p class=\"summary-h-2\">- marked as \"Interactive video\": <b>{0}</b> packets</p>".format(self.reportSummary[3])
        repBodySum += "</div>"
        repBodySum += "</div>"

        repBodySum += "<div class=\"row\">"
        repBodySum += "<div class=\"col-md-12\">"
        repBodySum += "<p class=\"summary-h-2\">- marked as \"Interactive voice\": <b>{0}</b> packets</p>".format(self.reportSummary[4])
        repBodySum += "</div>"
        repBodySum += "</div>"

        repBodySum += "<div class=\"row\">"
        repBodySum += "<div class=\"col-md-10\" style=\"margin-left: 50px\">"
        repBodySum += "<a href=\"#\" class=\"btn btn-primary open-btn\" role=\"button\">Open .pcap</a>"
        repBodySum += "<a href=\"#\" class=\"btn btn-primary open-btn\" role=\"button\">Open .json</a>"
        repBodySum += "</div>"
        repBodySum += "</div>"

        repBodySum += "</div>"
        repBodySum += "</div>"
        repBodySum += "</div>"

        return repBodySum


    def doBodyDetails(self):

        # Get parameters from config dictionary
        src_ip = self.config[0]['src_ip']
        dst_ip = self.config[0]['dst_ip']

        best_effort = 0
        background = 0
        video = 0
        voice = 0
        ip_packets = 0

        # Table: detailed capturing data
        repDetails = "<div class=\"row\">"
        repDetails += "<div class=\"col-md-12\">"
        repDetails += "<div class=\"details\">"
        repDetails += "<div class=\"row\">"
        repDetails += "<div class=\"col-md-12\">"
        repDetails += "<p class=\"summary-h-1\">Capturing details:</p>"
        repDetails += "</div>"
        repDetails += "</div>"

        repDetails += "<div class=\"row\">"
        repDetails += "<div class=\"col-md-12\">"
        repDetails += "<div class=\"details-table\">"
        repDetails += "<table class=\"table\">"
        repDetails += "<thead>"
        repDetails += "<tr>"
        repDetails += "<th>Packet ID</th>"
        repDetails += "<th>Source IP</th>"
        repDetails += "<th>Destination IP</th>"
        repDetails += "<th>IP Total Length</th>"
        repDetails += "<th>QoS</th>"
        repDetails += "<th>DSCP</th>"
        repDetails += "</tr>"
        repDetails += "</thead>"

        repDetails += "<tbody>"

        for item in self.captureDict:
            # CASE with two testing devices
            #if (item['IP_SRC'] == src_ip and item['IP_DST'] == dst_ip) or \
            #        (item['IP_SRC'] == dst_ip and item['IP_DST'] == src_ip):

            # CASE with one testing device (in and out traffic)
            # if (item['IP_SRC'] == src_ip or item['IP_DST'] == dst_ip) or \
            #        (item['IP_SRC'] == dst_ip or item['IP_DST'] == src_ip):

            # CASE outgoing traffic, one device (#or)
            if item['IP_SRC'] == src_ip and \
                   (item['IP_DST'] == dst_ip):
                ip_packets += 1                 # for summary

                if item['QOS'] == '5':
                    video += 1                  # for summary
                    qos_mark = 'QoS (Video): {0}'.format(item['QOS'])
                    repDetails += "<tr class=\"success\"><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>".format(
                        item['FRAME_N'], item['IP_SRC'], item['IP_DST'], item['IP_LEN'], qos_mark, item['IP_DSCP'])
                elif item['QOS'] == '4':
                    video += 1                  # for summary
                    qos_mark = 'QoS (Video): {0}'.format(item['QOS'])
                    # f.write("<tr class=\"success\"><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>".format(
                    #    item['FRAME_N'], item['IP_SRC'], item['IP_DST'], qos_mark, item['IP_DSCP']))
                elif item['QOS'] == '6':
                    voice += 1                  # for summary
                    qos_mark = 'QoS (Voice): {0}'.format(item['QOS'])
                    repDetails += "<tr class=\"success\"><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>".format(
                        item['FRAME_N'], item['IP_SRC'], item['IP_DST'], item['IP_LEN'], qos_mark, item['IP_DSCP'])
                elif item['QOS'] == '0':
                    best_effort += 1            # for summary
                    qos_mark = 'Best effort: {0}'.format(item['QOS'])
                    repDetails += "<tr class=\"warning\"><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>".format(
                        item['FRAME_N'], item['IP_SRC'], item['IP_DST'], item['IP_LEN'], qos_mark, item['IP_DSCP'])
                elif item['QOS'] == '1':
                    background += 1             # for summary
                    qos_mark = 'Background: {0}'.format(item['QOS'])
                    repDetails += "<tr class=\"success\"><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>".format(
                        item['FRAME_N'], item['IP_SRC'], item['IP_DST'], item['IP_LEN'], qos_mark, item['IP_DSCP'])
                else:
                    qos_mark = 'QoS: {0}'.format(item['QOS'])
                    repDetails += "<tr class=\"info\"><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>".format(
                        item['FRAME_N'], item['IP_SRC'], item['IP_DST'], item['IP_LEN'], qos_mark, item['IP_DSCP'])

        # Add parameters to summary:
        self.reportSummary.append(ip_packets)
        self.reportSummary.append(best_effort)
        self.reportSummary.append(background)
        self.reportSummary.append(video)
        self.reportSummary.append(voice)

        repDetails += "</tbody>"
        repDetails += "</table>"
        repDetails += "</div>"

        repDetails += "</div>"
        repDetails += "</div>"
        repDetails += "</div>"
        repDetails += "</div>"
        repDetails += "</div>"
        return repDetails

    def doCloseBody(self):
        repCloseBody = "</div>"
        repCloseBody += "</body>"
        repCloseBody += "</html>"
        return repCloseBody


# Retrieve app parameters from Itunes page
# - app Name
# - app Icon (address)
# - app Description - optional
    def retrieveItunes(self):
        #opener = urllib2.build_opener()
        #try:
        #    response = opener.open(self.config[0]['appstore_link'])
        #    html = response.read()
        #except:
        #    self.appParameters.append("App Title")
        #    self.appParameters.append("#")
        #    return

        #search_name = re.search('<h1 itemprop=\"name\">(.*)</h1>', html)
        #UDP Client (FastLane workshop)
        search_name = "UDP Client (FastLane workshop)"
        #self.appParameters.append(search_name.group(1))
        self.appParameters.append(search_name)

        #search_icon = re.search('<meta itemprop=\"image\" content=\"(.*)\"></meta>', html)
        search_icon = "Content/empty.png"
        #self.appParameters.append(search_icon.group(1))
        self.appParameters.append(search_icon)
