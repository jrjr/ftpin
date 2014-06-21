# Copyright 2014 James Ritchey
# GNU GPLv3
 
from pydbg import *
from pydbg.defines import *
import time
from datetime import datetime
import subprocess

outputfile = r'C:\Users\<username>\Desktop\function_trace.out'
program = r'C:\Program Files\Mozilla Firefox\firefox.exe'
service = r'firefox.exe'
inputfile = r''
#regex = r'.*'
regex = r'ws2_32\.DLL:WSARecv$'
#regex = r'malloc'
dostacktrace = 0
doattach= True
pinbat = r'C:\Users\<username>\Downloads\pin-2.13-65163-msvc10-windows\pin-2.13-65163-msvc10-windows\pin_bat.bat'
pintool = r'C:\Users\<username>\Downloads\pin-2.13-65163-msvc10-windows\pin-2.13-65163-msvc10-windows\source\tools\ManualExamples\obj-ia32\function_trace.dll'

def getTimeStamp():
	return datetime.now().strftime("%Y_%m_%d_%H_%M_%S")

# MAIN #
dbg = pydbg()
found = 0
for (pid, name) in dbg.enumerate_processes():
	if name == service:
		found=1
		break
		
print  getTimeStamp() + "executing pin tool"
if (doattach):
	if (found):
		returnv = subprocess.call(pinbat + ' -follow_execv -pid '+ str(pid) +' -t ' + pintool  + ' -o ' + outputfile + ' -s ' + str(dostacktrace) + ' -r ' + regex + ' --' , shell=True)
	else:
		print getTimeStamp() + " couldn't find service"
		sys.exit(0)
else:
	returnv = subprocess.call(pinbat + ' -follow_execv -t ' + pintool  + ' -o ' + outputfile + ' -s ' + str(dostacktrace) + ' -r ' + regex + ' -- "' + program + '" ' + inputfile, shell=True)