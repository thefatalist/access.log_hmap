#!/usr/bin/python2.6
from sys import argv, exit, stdout
from fl import opener
from os import path
from time import time
import gzip

DELIMETER = '\t'
#sorter = lambda x: x[1]['normal']
#sorter = lambda x: x[1]['total']
sorter = lambda x: x[0]

config = {
		### Ignore parameters. Affect how much data will be ingored in file
		"ignoreIP"        : [  ### Ignore lines with requests from selected IPs
			],
		"ignoreTimeFrame" : [  ### Timeframe should be added in "HH:MM:SS-HH:MM:SS" format for each ignore window
			],
		"ignoreURL"       : [  ### Begining of URL queries which we are ignoring
			],
		"ignoreHTTPcode"  : [  ### Ignore lines with mentioned HTTP Return code
				 "400"
				,"301"
			],
		"ignoreAgent"     : [
			],

		### Following parameters forces application to search ONLY for their data
		"lookForIP"       : [  ### Ignore "ignoreIP" config. Look ONLY for marked IPs
			],
		"lookForURL"      : [  ### Ignore "ignoreURL" config. Look ONLY for marked URLs
				"/spring/update"
				###"/a4j/"
			],

		### How to workaround IP and URL checks
		"IPcheck"		  : {
			"check" : [],
			"code"  : True
			},
		"URLcheck"        : {
			"check" : [],
			"code"  : True
			},

		# COMMON configuration parameters
		"filename"        : "/tmp/access.log",    # Default name of the file
		"file"            : None,                 # File descriptor
		"resultfile"      : None,                 # File descriptor for the results CVS file
		"since"           : "",                   # text pattern since when to start parsing
		"relevance"       : 10,                   # Minimum amount of appearances to keep the ipagent
		"filesize"        : 0,                    # Size of log file to calculate progress
		"lastinform"      : 0,                    # Last time when we informed about current position
		"ipagent"         : [  ### How to generate ipagent line
				 "IP"
				,"agent"
				,"cookie"
			]
		}

# Choose which IP check to choose. Look for exact IP, or skipping irrelevant
if config["lookForIP"]:
	config["IPcheck"]["check"] = config["lookForIP"]
	config["IPcheck"]["code"]  = False
else:
	config["IPcheck"]["check"] = config["ignoreIP"]


# Choose which URL check to choose. Look for exact URLs, or skipping irrelevant
if config["lookForURL"]:
	config["URLcheck"]["check"] = config["lookForURL"]
	config["URLcheck"]["code"]  = False
else:
	config["URLcheck"]["check"] = config["ignoreURL"]

#########################################################################################
#### FUNCTIONS
#########################################################################################


class gzipReader(gzip.GzipFile):
        def __enter__(self):
                if self.fileobj is None:
                        raise ValueError("I/O operation on closed GzipFile object")
                return self

        def __exit__(self, *args):
                self.close()


def opener(filename):
        if filename.endswith('.gz'):
                print "GZIP file!!"
                return gzipReader( filename, 'rb' )
                #return gzip.GzipFile( filename, 'rb' )
                #return gzip.open( filename, 'rb' )
        return open( filename, 'r' )

# Print out the current position
def printPosition():
	if time() - config["lastinform"] < 0.2: return
	pos = config["file"].tell()
	max = config["filesize"]
	percent = 100.0*pos/max
	stdout.write("\r%0.2f%%    " % percent)
	stdout.flush()
	config["lastinform"] = time()


# Parse the access log line
def getLineParsed(line):
	printPosition()
	line = line.split('"')
	a = line[0].strip().split()
	b = line[1].strip().split()
	try:
		method = b[0]
	except:
		method = ''
	try:
		URL = b[1]
	except:
		URL = ''
	c = line[2].strip().split()
	result = {
		"IP"     : a[0],
		"date"   : a[5][1:12],
		"time"   : a[5][13:],
		"method" : method,
		"URL"    : URL,
		"code"   : c[0],
		"agent"  : line[5].strip(),
		"cookie" : line[9].strip(),
			}
	#return (result["IP"],result["date"],result["time"],result["code"],result["method"],result["URL"],result["agent"],result["cookie"], )
	return result

# Ensure that URL is correct
def checkURLallowed(line,checkURL):
	urllist = checkURL["check"]
	urlres  = checkURL["code"]
	for url in urllist:
		if line["URL"].startswith( url ) == urlres:
			return True
	return False


# Generate the IPAgentLine
def getIPAgentLine(line):
	result = []
	for i in config["ipagent"]:
		result.append( line[i] )
	return ' '.join(result)

# Check if line is suitable for parse or should be skiped
def goodIPAgent(line, ipagentlist):
	checkIP    = config["IPcheck"]
	checkAgent = config["ignoreAgent"]
	if (line["IP"] in checkIP["check"]) == checkIP["code"]:
		#print "'%s' in list of IPs" % line["IP"]
		return None
	if checkURLallowed(line, config["URLcheck"]):
		#print "'%s' in list of URLs" % line["URL"]
		return None
	#if line["time"] in config["ignoreTimeFrame"]:
	#	continue
	if line["agent"] in checkAgent:
		#print "'%s' in list of agents" % line["agent"]
		return None
	ipagent = getIPAgentLine(line)
	return ipagent

# CleanUp irrelevant IPAgents
def dropIrrelevant(ipagentlist):
	result = []
	for ipagent, appearence in ipagentlist.iteritems():
		if appearence < config["relevance"]: continue
		result.append(ipagent)
	return result

# Get the list of possible IP + HTTP Agent variations in the log file
def getIPAgent(logfile):
	ipagentlist = {}
	#ipagentlist = ["TIME"]
	#checkIP    = config["IPcheck"]
	#checkAgent = config["ignoreAgent"]
	for line in logfile:
		line = getLineParsed(line)
		ipagent = goodIPAgent(line=line, ipagentlist=ipagentlist)
		if not ipagent:
			continue
		if not ipagentlist.has_key(ipagent):
			ipagentlist[ipagent] = 1
			continue
		#ipagentlist.append( ipagent )
		ipagentlist[ipagent] += 1
	return dropIrrelevant(ipagentlist)
	#return ipagentlist

# fullfil the dict with current IPagent data (fill with zeroes)
def fillMinute(data,ipagentlist):
	for ipagent in ipagentlist:
		data[ipagent] = 0

# get one line for the CVS file. Parse the log for one minute
def getOneMinuteStats(logfile, currenttime='00:00'):
	currenttime = currenttime
	result = {"TIME":currenttime}
	ipagentlist = config["ipagentlist"]
	fillMinute( data=result, ipagentlist=ipagentlist)
	#result["TIME"] = currenttime
	#print "RESULT ::::: ", result
	for line in logfile:
		line = getLineParsed(line)
		ipagent = goodIPAgent(line=line, ipagentlist=ipagentlist)
		if not ipagent:
			continue
		if ipagent not in ipagentlist:
			continue
		result[ipagent] += 1

		# If time has changed - return result
		if line["time"][:5] != currenttime:
			nexttime = line["time"][:5]
			#print "RETURN :::: "
			return (nexttime, result)
	return (None, result)

# Print out oneMinute statistic
def getOneMinuteOutput(data, ipagentlist):
	result = [data["TIME"],]
	#result = []
	for ipagent in ipagentlist:
		result.append( data[ipagent] )
	return result

#########################################################################################
#### MAIN APPLICATION RUN
#########################################################################################

if __name__ == "__main__":
	since = False
	try:
		config["filename"] = argv[1]
	except:
		print "No filename passed, using default: '%s'" % config["filename"]
	if  len(argv)>2: since = argv[2]
	config["resultfile"] = open("./result.csv", 'w')
	config["filesize"] = path.getsize(config["filename"])
	print "_________ %s (filesize: %s) _ Since: %s : " % (config["filename"], config["filesize"], config["since"])
	
	print("Parsing the access.log file to get list of all IP Agents")
	# Get the list of required IPAgents to parse the file
	with opener(config["filename"]) as logfile:
		config["file"] = logfile
		ipagentlist = getIPAgent(logfile)

	config["ipagentlist"] = ipagentlist

	print("\nAll IP Agents are found. Starting from the begining of file to collect statistics")
	config["resultfile"].write("TIME"+DELIMETER)
	config["resultfile"].write(DELIMETER.join(ipagentlist))
	config["resultfile"].write("\n")

	# Parse the file
	with opener(config["filename"]) as logfile:
		config["file"] = logfile
		nexttime = '00:00'
		while True:
			line = getOneMinuteStats(logfile=logfile, currenttime=nexttime)
			result = getOneMinuteOutput( data=line[1], ipagentlist=ipagentlist )
			config["resultfile"].write(DELIMETER.join( str(i) for i in result ))
			config["resultfile"].write("\n")
			#print line
			nexttime = line[0]
			if not line[0]:				
				break

	
	print("\nAll data collected!")
