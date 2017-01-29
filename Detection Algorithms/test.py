from LIB import sniffer
import re

data = open("log_links","a")
while(1):
  retn_data = sniffer()
  if retn_data['proto'] == 'TCP' or retn_data['proto'] == 'UDP':
    res = re.findall( r'https?://.{1,60}', retn_data['pure_data'])
    if res:
    	for link in res:
    		data.write(retn_data['src_ip'] + " \t " + link + "\n") 
