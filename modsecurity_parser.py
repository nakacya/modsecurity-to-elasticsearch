#!/usr/bin/env python
#
#
import pdb 
import sys, os, getopt, json, time
from datetime import datetime,date
 
# output JSON file
output = "/var/log/modsecurity/audit.json"

# parse arguments
opts, args = getopt.getopt(sys.argv[1:],"hd:",["help","log-directory="])
for i in opts:
        if i[0] == "-d" or i[0] == "--log-directory":
                basedir = i[1]

# set headers name to lowercase
def renameKeys(iterable):
    if type(iterable) is dict:
        for key in iterable.keys():
            iterable[key.lower()] = iterable.pop(key)
            if type(iterable[key.lower()]) is dict or type(iterable[key.lower()]) is list:
                iterable[key.lower()] = renameKeys(iterable[key.lower()])
    elif type(iterable) is list:
        for item in iterable:
            item = renameKeys(item)
    return iterable
 
# parsing...
def parseLogFile(file):
 
    #X#pdb.set_trace()
    try:
            fi = open(file,'r')
            fir = fi.read()
            firu = unicode(fir,'utf-8','ignore')
            # set all dict keys to lower
            d = renameKeys(json.loads(firu))
            # create a unixts field as a timestamp field
            d['transaction']['unixts'] = int(d['transaction']['unique_id'][0:10].replace('.',''))
    except:
            print ('Cannot Analyze or Write Log')
            print (d)
    else:
            # because objects in array are not well supported,
            # redefine all "messages" params and values in "msg"

            n = {}
            n['message'] = {}
            n['message']['unixts'] = int(d['transaction']['unique_id'][0:10].replace('.',''))
            n['message']['client_ip'] = d['transaction']['client_ip']
            n['message']['time_stamp'] = d['transaction']['time_stamp']
            n['message']['server_id'] = d['transaction']['server_id']
            n['message']['client_port'] = d['transaction']['client_port']
            n['message']['host_ip'] = d['transaction']['host_ip']
            n['message']['host_port'] = d['transaction']['host_port']
            n['message']['unique_id'] = d['transaction']['unique_id']
            n['message']['request'] = d['transaction']['request']
            n['message']['response'] = d['transaction']['response']
            n['message']['producer'] = d['transaction']['producer']

            new_messages = []
            new_ruleid = []
            new_tags = []
            new_file = []
            new_linenumber = []
            new_data = []
            new_match = []
            new_severity = []

            for i in d['transaction']['messages']:
                    n['message']['msg'] = {}
                    new_messages = i['message']
                    new_ruleid = i['details']['ruleid']

                    for tag in i['details']['tags']:
                                    new_tags.append(tag)
                    new_file = i['details']['file']
                    new_linenumber = i['details']['linenumber']
                    new_data = i['details']['data']
                    new_match = i['details']['match']
                    new_severity = i['details']['severity']

                    n['message']['msg']['message'] = new_messages
                    n['message']['msg']['ruleid'] = new_ruleid
                    n['message']['msg']['tags'] = new_tags
                    n['message']['msg']['file'] = new_file
                    n['message']['msg']['linenumber'] = new_linenumber
                    n['message']['msg']['data'] = new_data
                    n['message']['msg']['match'] = new_match
                    n['message']['msg']['severity'] = new_severity
                    n['message']['date'] = datetime.fromtimestamp(d['transaction']['unixts']).isoformat()
                    output_json = open(output,'a')
                    #X#json.dump(n['message'],output_json, sort_keys=True, separators=(',', ': '), indent=4)
                    json.dump(n['message'],output_json, sort_keys=True, separators=(',', ': '))
                    output_json.write("\n".encode())
                    del n['message']['msg']

            del n['message']
            print ('Parsed '+str(file))
            os.remove(file)

while True:
    for root, subFolders, files in os.walk(basedir):
#X#        print ('RootDir '+str(root))
#X#        print ('subDir '+str(subFolders))
#X#        print ('files '+str(files))
        for file in files:
            logfile = os.path.join(root, file)
            parseLogFile(file=logfile)
        if root != basedir and len(files) != 0:
           os.rmdir(root)
        else:
           if root == basedir and len(subFolders) != 0:
             try:
               for subdir in subFolders:
                 sub_dir = os.path.join(root, subdir)
                 os.rmdir(sub_dir)
             except OSError:
               pass

    print ('Sleeping for a while...')
    time.sleep(15)
