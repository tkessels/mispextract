import json
import re
import sys
import getopt


ioc_md5={
    "shortname":"md5",
    "output_filename":"md5.hashlist",
    "output_headline":"MD5",
    "regex":re.compile(r"(^|[^a-fA-F0-9])([a-fA-F0-9]{32})($|[^a-fA-F0-9])"),
    "regex_grp":2
    }
ioc_sha1={
    "shortname":"sha1",
    "output_filename":"sha1.hashlist",
    "output_headline":"SHA-1",
    "regex":re.compile(r"(^|[^a-fA-F0-9])([a-fA-F0-9]{40})($|[^a-fA-F0-9])"),
    "regex_grp":2
}
ioc_sha224={
    "shortname":"sha224",
    "output_filename":"sha224.hashlist",
    "output_headline":"SHA-224",
    "regex":re.compile(r"(^|[^a-fA-F0-9])([a-fA-F0-9]{56})($|[^a-fA-F0-9])"),
    "regex_grp":2
}
ioc_sha256={
    "shortname":"sha256",
    "output_filename":"sha256.hashlist",
    "output_headline":"SHA-256",
    "regex":re.compile(r"(^|[^a-fA-F0-9])([a-fA-F0-9]{64})($|[^a-fA-F0-9])"),
    "regex_grp":2
}
ioc_sha256={
    "shortname":"sha256",
    "output_filename":"sha256.hashlist",
    "output_headline":"SHA-256",
    "regex":re.compile(r"(^|[^a-fA-F0-9])([a-fA-F0-9]{64})($|[^a-fA-F0-9])"),
    "regex_grp":2
}
ioc_sha256={
    "shortname":"sha256",
    "output_filename":"sha256.hashlist",
    "output_headline":"SHA-256",
    "regex":re.compile(r"(^|[^a-fA-F0-9])([a-fA-F0-9]{64})($|[^a-fA-F0-9])"),
    "regex_grp":2
}
ioc_sha384={
    "shortname":"sha384",
    "output_filename":"sha384.hashlist",
    "output_headline":"SHA-384",
    "regex":re.compile(r"(^|[^a-fA-F0-9])([a-fA-F0-9]{96})($|[^a-fA-F0-9])"),
    "regex_grp":2
}
ioc_sha512={
    "shortname":"sha512",
    "output_filename":"sha512.hashlist",
    "output_headline":"SHA-512",
    "regex":re.compile(r"(^|[^a-fA-F0-9])([a-fA-F0-9]{128})($|[^a-fA-F0-9])"),
    "regex_grp":2
}
ioc_filename={
    "shortname":"filename",
    "output_filename":"filenames.list",
    "regex":re.compile(r"[^|]+"),
    "regex_grp":0
}
ioc_domain={
    "shortname":"domain",
    "output_filename":"domains.list",
    "regex":re.compile(r".*"),
    "regex_grp":0
}
ioc_ips={
    "shortname":"ips",
    "types":["ip-src","ip-dst"],
    "output_filename":"ips.list",
    "regex":re.compile(r".*"),
    "regex_grp":0

}
ioc_def=[ioc_md5,ioc_sha1,ioc_sha224,ioc_sha256,ioc_sha384,ioc_sha512,ioc_filename,ioc_domain,ioc_ips]


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
        #turn anything into string and replace newlines
        string=str(argument).replace("\n","|")
        #remove any other speacial chars and double whitespaces
        string=" ".join(string.split())
        #replace not csv compliant chars
        string=string.replace(";", ",")
        #cut string to a max length
        length=70
        string=(string[:length] + '...') if len(string) > length else string
        #put string up as a field
        data.append(string)
    return ";".join(data)


def open_file(shortname,filename):
    try:
        out_files[shortname]=open("misp_" + filename,'w')
    except Exception as e:
        print("[-] Could not create/open outpufile: %s" % filename)
        print(e)

def write_file(shortname,data):
    try:
        out_files[shortname].write(data+"\n")
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
tag_filter=None
out_files={}

#Parsing Commandline Arguments
try:
    opts, args = getopt.getopt(sys.argv[1:],"hiqt:f:")
except getopt.GetoptError: print_usage(2)
for option, argument in opts:
    if option == '-h': print_usage(0)
    elif option == '-i':
        interactive=True
    elif option == '-q':
        quiet=True
    elif option in ("-f"):
        misp_export = argument
    elif option in ("-t"):
        if not quiet : print("[+] Filter set! Only IOCs matching one of the following words will be exportet: {}".format(argument))
        tag_filter = argument


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


open_file("lut","ioc_look_up_table.csv")
write_file("lut","value;ioc_type;category;ids_relevant;attribute_value;event_info;event_id")
for ioc_type in ioc_def:
    stats[ioc_type["shortname"]]=[0,0]
    open_file(ioc_type["shortname"],ioc_type["output_filename"])
    if "output_headline" in ioc_type:
        write_file(ioc_type["shortname"],ioc_type["output_headline"])


if not quiet : print("[+] Extracting:")

progress["event"]=[1,len(response)]
progress["attribs"]=[0,0]
progress["ioc"]=0

def check_event(event):
    if "Attribute" in event:
        if tag_filter:
            if "Tag" in event and len(event["Tag"])>0:
                for x in event["Tag"]:
                    for word in tag_filter.split():
                        if word in x["name"].lower():
                            return True
        else:
            return True
    return False


for i in response:
    event = i["Event"]
    if not quiet and progress["event"][0]%stats_update_interval==0:
        print_stats()
    if check_event(event):
        progress["attribs"]=[0,len(event["Attribute"])]
        for ioc in event["Attribute"]:
            progress["attribs"][0]+=1
            progress["ioc"]+=1
            for ioc_type in ioc_def:
                if ("types" in ioc_type and [i for i in ioc_type["types"] if i in ioc["type"] ] ) or ioc_type["shortname"] in ioc["type"]:
                    value_match=ioc_type["regex"].search(ioc["value"])
                    if value_match is not None:
                        value=value_match.group(ioc_type["regex_grp"])
                        stats[ioc_type["shortname"]][0]+=1
                        write_file("lut",get_csv_string(value,ioc_type["shortname"],ioc["category"],ioc["to_ids"],ioc["value"],event["info"],event["id"]))
                        write_file(ioc_type["shortname"],value)
                    else:
                        stats[ioc_type["shortname"]][1]+=1

    progress["event"][0]+=1
if not quiet :
    print_stats()
    print("[+] Done! Extracted {:d} IOCs".format(progress["ioc"]))


close_files()
