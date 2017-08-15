import json
import re
import sys
import getopt


class JsonProgress(object):
    def __init__(self):
        self.count = 0

    def __call__(self, obj):
        self.count += 1
        if (self.count % 100)==0:
            sys.stdout.write("\r%8d" % self.count)
        return obj

def get_csv_string(*args):
    data=[]
    for argument in args:
        data.append(" ".join(argument.split()).strip().replace(";",","))
    return ";".join(data)


def open_file(filename,ext=".hashlist"):
    try:
        out_files[filename]=open("misp_" + filename + ext,'w')
    except Exception as e:
        print("[-] Could not create/open outpufile: %s" % filename)
        print(e)

def write_file(filename,data):
    try:
        out_files[filename].write(data)
    except:
        pass

def close_files():
    if not quiet : print("[+] Closing Files")
    for files in out_files:
        try:
            files.close()
        except:
            pass
    if not quiet : print("[+] Done!")

def print_usage(n):
    print("Usage: %s [-h] [-i] [-q] [-f misp_export.json]"%sys.argv[0])
    sys.exit(n)

def print_stats():
    global stats_to_clear
    sys.stdout.write('\x1b[1A\x1b[2K'*stats_to_clear)
    sys.stdout.write('\x1b[0G')

    width=40
    stats_to_clear=0
    if progress["event"][1]>0:
        progress_barlength=(progress["event"][0]*width)/progress["event"][1]
        progress_percentage=(progress["event"][0]*100)/progress["event"][1]
        print("[++] [{:_<{wdt}}] {:03d}%".format("+"*int(progress_barlength),int(progress_percentage),wdt=width))
        stats_to_clear+=1

    print("[++]   IOC-TYPE :  found | failed ")
    stats_to_clear+=1

    for key in stats:
        if stats[key][0]+stats[key][1]>0:
            stats_to_clear+=1
            print("[++] {:^10} : {:>7d}|{:d}".format(key,stats[key][0],stats[key][1]))



hashes={
    "md5":{
        "length" : 32,
        "text" : "MD5"},
    "sha1":{
        "length" : 40,
        "text" : "SHA-1"},
    "sha224":{
        "length" : 56,
        "text" : "SHA-224"},
    "sha256":{
        "length" : 64,
        "text" : "SHA-256"} ,
    "sha384":{
        "length" : 96,
        "text" : "SHA-384"},
    "sha512":{
        "length" : 128,
        "text" : "SHA-512"
        }
    }

#Variable declaration
misp_export='misp.json'
quiet=False
interactive=False
stats={}
progress={}
stats_to_clear=0
stats_update_interval=10
event_count=0
attribute_count=0
out_files={}

#Parsing Commandline Arguments
try:
    opts, args = getopt.getopt(sys.argv[1:],"hiqf:")
except getopt.GetoptError: print_usage(2)
for option, argument in opts:
    if option == '-h': print_usage(0)
    elif option == '-i':
        interactive=True
    elif option == '-q':
        quiet=True
    elif option in ("-f"): misp_export = argument


#reading input file
if not quiet : print("[+] Reading Json-Data from %s ..." % misp_export)
try:
    with open(misp_export) as data_file:
        if quiet:
            data = json.load(data_file)
        else:
            data = json.load(data_file,object_hook=JsonProgress())
            print("\r[+] Done")
except Exception as e:
    print("[-] JSON File could not be processed")
    print(e)
    print(type(e))
    exit(3)

response = data["response"]


filenames_regex=re.compile(r"[^|]+")
open_file("filenames",".list")
open_file("all_hashes_lut",".csv")
write_file("all_hashes_lut","hash;hashtype;category;attribute_value;event_info;event_id\n")
stats["filenames"]=[0,0]
for hashalgo in hashes:
    pattern=r"(^|[^a-fA-F0-9])([a-fA-F0-9]{" + str(hashes[hashalgo]["length"]) + r"})($|[^a-fA-F0-9])"
    hashes[hashalgo]["regex"]=re.compile(pattern)
    stats[hashalgo]=[0,0]

    open_file(hashalgo)
    write_file(hashalgo,hashes[hashalgo]["text"]+"\n")


if not quiet : print("[+] Extracting:")

progress["event"]=[1,len(response)]
progress["attribs"]=[0,0]
progress["ioc"]=0


for i in response:
    event = i["Event"]
    if not quiet and progress["event"][0]%stats_update_interval==0:
        print_stats()
    if "Attribute" in event:
        progress["attribs"]=[0,len(event["Attribute"])]
        for ioc in event["Attribute"]:
            progress["ioc"]+=1
            for hashalgo in hashes:
                if hashalgo in ioc["type"]:
                    foundhash=hashes[hashalgo]["regex"].search(ioc["value"])
                    if foundhash is not None:
                        stats[hashalgo][0]+=1
                        event_info="|".join(event["info"].split("\n"))
                        write_file("all_hashes_lut",get_csv_string(foundhash.group(2),hashalgo,ioc["category"],ioc["value"],event_info,event["id"])+"\n")
                        # write_file("all_hashes_lut","%s;%s;%s;%s;%s;%s\n" % (foundhash.group(2),hashalgo,ioc["category"],ioc["value"].replace(';',','),event_info.replace(';',','),event["id"]))
                        write_file(hashalgo,"%s\n" % foundhash.group(2))
                    else:
                        stats[hashalgo][1]+=1

            if "filename" in ioc["type"]:
                filename=filenames_regex.match(ioc["value"])
                if filename is not None:
                    stats["filenames"][0]+=1
                    write_file("filenames","%s\n" % filename.group(0))
                else:
                    stats["filenames"][1]+=1
    progress["event"][0]+=1
if not quiet :
    print_stats()
    print("[+] Done! Extracted {:d} IOCs".format(progress["ioc"]))


close_files()
