import os
import sys
import subprocess
import hashlib
import datetime
import getpass

check_template = "<div class=\"contentpane\">\r\n\t<h2>Name</h2>\r\n\t<div class=\"entry\">{name}</div>\r\n\t<h2>Result</h2>\r\n\t<div class=\"entry\">{result}</div>\r\n\t<h2>Reason</h2>\r\n\t<div class=\"entry\">{reason}</div>\r\n</div>\r\n"
"""name, result, reason"""

report_template = "<!DOCTYPE html>\r\n<html>\r\n<head>\r\n<style>\r\nhtml { \r\n  height:100%; \r\n}\r\n\r\nbody {\r\n  background-color: #E2D893;\r\n  height: 100%;\r\n  font-family: Arial;\r\n}\r\n\r\n.contentpane {\r\n  background: #FFF;\r\n  list-style-type: none;\r\n  overflow: hidden;\r\n  padding: 20px;\r\n  -webkit-border-radius: 9;\r\n  -moz-border-radius: 9;\r\n  border-radius: 9px;\r\n  -webkit-flex: 1;\r\n          flex: 1;\r\n  margin: 10px;\r\n}\r\n\r\n.entry {\r\n  background: #5F9DA1;\r\n  color: #FFFFFF;\r\n  padding: 4px;\r\n  -webkit-border-radius: 9;\r\n  -moz-border-radius: 9;\r\n  border-radius: 9px;\r\n  margin-bottom: 4px;  \r\n}\r\n\r\n</style>\r\n</head>\r\n<body>\r\n<div class=\"contentpane\" name=\"sysinfo\">\r\n\t<h1>System information</h1>\r\n\t<h2>Hostname</h2>\r\n\t<div class=\"entry\">{hostname}</div>\r\n\t<h2>OS</h2>\r\n\t<div class=\"entry\">{os}</div>\r\n\t<h2>User</h2>\r\n\t<div class=\"entry\">{user}</div>\r\n\t<h2>Local time</h2>\r\n\t<div class=\"entry\">{localtime}</div>\r\n\t<h2>Scan result</h2>\r\n\t<div class=\"entry\">{result}</div>\r\n</div>\r\n{checklist}\r\n</body>\r\n</html>"
"""hostname, os, user, localtime, result, checklist"""

system_type = sys.platform
system_time = datetime.datetime.now()
system_currentuser = getpass.getuser()

checklist = ""

def create_entry(name, result, reason):
	entry = check_template
	entry.replace("{name}", name)
	if result == 1:
		entry.replace("{result}", "Found")
	elif result == 2:
		entry.replace("{result}", "Clean")
	else:
		entry.replace("{result}", "Inconclusive")
	entry.replace("{reason}", reason)
	checklist = checklist + entry

def checkfile_fullpath(path)
	name = "Checking if file exists: " + path
	result = 3
	reason = ""
	try:
		reason += "Checking with os.path.isfile...\r\n"		
		if os.path.isfile(path):
			result = 1
		else: 
			result = 2
	except:
		reason += "Something happened: \r\n" + sys.exc_info()[0]
	create_entry(name, result, reason)

def checkfile_filename(filename):
	name = "Searching for file on system: " + filename
	result = 2
	reason = ""
	try:
		if "win" in system_type:
			reason += "Checking all drives...\r\n"
			drivelist = subprocess.Popen('wmic logicaldisk get name,description', shell=True, stdout=subprocess.PIPE)
			drivelisto, err = drivelist.communicate()
			driveLines = drivelisto.split('\n')
			for x in driveLines:
				if "Local Fixed Disk" in x:
					drive = x.strip()[-2:]+"\\"
					reason += "Checking drive: " + drive
					for root, dirs, files in os.walk(drive):
						for file in files:
							if filename in file:
								result = 1
								reason += "File found in: " + os.path.join(root, file)
		elif "linux" in system_type:
			for root, dirs, files in os.walk("/"):
				for file in files:
					if filename in file:
						result = 1
						reason += "File found in: " + os.path.join(root, file) + "\r\n"
		else:
			reason += "Unknown system type: " + system_type + "\r\n"
			result = 3
	except:
		reason += "Something happened: \r\n" + sys.exc_info()[0]
		result = 3
	create_entry(name, result, reason)

def checkfile_md5(path, md5hash):
	name = "Checking md5 hash of file: " + path
	result = 3
	reason = ""	
	try:	
		hash = hashlib.md5()
		open(path, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash.update(chunk)
		hashstring = hash.hexdigest()
		reason += "Found file with hash: " + hashstring + "\r\n"
		reason += "Comparing with: " + md5hash + "\r\n"
		if hashstring == md5hash:
			result = 1
		else:
			result = 2
	except:
		reason += "Something happened: \r\n" + sys.exc_info()[0]
		result = 3
	create_entry(name, result, reason)

def checkfile_size(path, size):
	name = "Checking size of file: " + path
	result = 3
	reason = ""	
	try:	
		if os.path.getsize(path) == size:
			result = 1
			reason += "File size matches: " + size + "\r\n"
		else:
			result = 2
			reason += "File size does not match: " + size + "\r\n"
	except:
		reason += "Something happened: \r\n" + sys.exc_info()[0]
		result = 3
	create_entry(name, result, reason)


