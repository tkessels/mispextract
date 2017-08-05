import json
import re
import sys
misp_export='misp.json'
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
        "text" : "SHA-512"}
    }
xways_files={}
stats={}
progress={}
stats_to_clear=0


class JsonProgress(object):
    def __init__(self):
        self.count = 0

    def __call__(self, obj):
        self.count += 1
        if (self.count % 100)==0:
            sys.stdout.write("\r%8d" % self.count)
        return obj

def clear_lines():
    sys.stdout.write('\x1b[1A\x1b[2K'*stats_to_clear)
    sys.stdout.write('\x1b[0G')

def print_stats():
    global stats_to_clear
    clear_lines()
    width=40
    header=[]
    if progress["event"][1]>0:
        progress_barlength=(progress["event"][0]*width)/progress["event"][1]
        progress_percentage=(progress["event"][0]*100)/progress["event"][1]

    print("[++] [{:_<{wdt}}] {:03d}%".format("+"*int(progress_barlength),int(progress_percentage),wdt=width))
    print("[++]   IOC-TYPE :  found | failed ")
    stats_to_clear=2

    for key in stats:
        if stats[key][0]+stats[key][1]>0:
            stats_to_clear+=1
            print("[++] {:^10} : {:>7d}|{:d}".format(key,stats[key][0],stats[key][1]))





filenames_regex=re.compile(r"[^|]+")
filenames_file=open("misp_filenames.list",'w')
stats["filenames"]=[0,0]
for hashalgo in hashes:
    pattern=r"(^|[^a-fA-F0-9])([a-fA-F0-9]{" + str(hashes[hashalgo]["length"]) + r"})($|[^a-fA-F0-9])"
    hashes[hashalgo]["regex"]=re.compile(pattern)
    stats[hashalgo]=[0,0]
    def_file=open("misp_all_hashes_lut.csv",'w')
    def_file.write("hash;hashtype;category;attribute_value;event_info;event_id\n")

    xways_files[hashalgo]=open("misp_" + hashalgo + "_xways.hashlist",'w')
    xways_files[hashalgo].write(hashes[hashalgo]["text"]+"\n")

print("[+] Reading Jason-Data from %s ..." % misp_export)
with open(misp_export) as data_file:
    data = json.load(data_file,object_hook=JsonProgress())
    # data = json.load(data_file)
    print("\r[+] Done") # \r in the next line erases the progress output
response = data["response"]
event_count=0
attribute_count=0
print("[+] Extracting:")

progress["event"]=[1,len(response)]
progress["attribs"]=[0,0]
progress["ioc"]=0

print_stats()

for i in response:
    event = i["Event"]
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
                        def_file.write("%s;%s;%s;%s;%s;%s\n" % (foundhash.group(2),hashalgo,ioc["category"],ioc["value"],event["info"],event["id"]))
                        xways_files[hashalgo].write("%s\n" % foundhash.group(2))
                    else:
                        stats[hashalgo][1]+=1

            if "filename" in ioc["type"]:
                filename=filenames_regex.match(ioc["value"])
                if filename is not None:
                    stats["filenames"][0]+=1
                    filenames_file.write("%s\n" % filename.group(0))
                else:
                    stats["filenames"][1]+=1
    progress["event"][0]+=1
print("[+] Done! Extracted {:d} IOCs".format(progress["ioc"]))

for hashalgo in hashes:
    xways_files[hashalgo].close()
filenames_file.close()
def_file.close()
