import json
import re
misp_export='misp.json'
hashes={ "md5":{"length" : 32, "text" : "MD5"},"sha1":{"length" : 40, "text" : "SHA-1"},"sha224":{"length" : 56, "text" : "SHA-224"},"sha256":{"length" : 64, "text" : "SHA-256"} ,"sha384":{"length" : 96, "text" : "SHA-384"},"sha512":{"length" : 128, "text" : "SHA-512"}}
def_files={}
xways_files={}

for hashalgo in hashes:
    pattern=r"(^|[^a-fA-F0-9])([a-fA-F0-9]{" + str(hashes[hashalgo]) + r"})($|[^a-fA-F0-9])"
    hashes[hashalgo]["regex"]=re.compile(pattern)
    def_files[hashalgo]=open(hashalgo,'w')
    xways_files[hashalgo]=open(hashalgo+".xways",'w')
    xways_files[hashalgo].write(hashes[hashalgo]["text"])


with open(misp_export) as data_file:
    data = json.load(data_file)
response = data["response"]

#list of eventdicts
for i in response:
    event = i["Event"]
    if "Attribute" in event:
        for ioc in event["Attribute"]:
            for hashalgo in hashes:
                if hashalgo in ioc["type"]:
                    foundhash=hashes[hashalgo].search(ioc["value"])
                    if foundhash is not None:
                        def_files[hashalgo].write("%s;%s;%s\n" % (foundhash.group(2),ioc["category"],ioc["value"]))
                        xways_files[hashalgo].write("%s\n" % foundhash.group(2))
                    else:
                        print(">%s< did not match >%s<" % (ioc["value"],hashes[hashalgo].pattern))
                        exit()

for hashalgo in hashes:
    files[hashalgo].close()
    xways_files[hashalgo].close()
