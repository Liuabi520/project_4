import sys
import time
import subprocess
website = {}
def main():
    with open(sys.argv[1]) as f:
        for line in f:
            website[line.strip()] = {}
    f.close()
    for key in website:
        website[key]["scan_time"] = time.time()
        try:
            result = subprocess.check_output(["nslookup",key,"8.8.8.8"],timeout =2,stderr=subprocess.STDOUT).decode("utf-8")
            result = result.split("Name:")[1]
            if result.find("Addresses:") == -1:
                result = result.split("Address:")[1]
            else:
                result = result.split("Addresses:")[1]
        except Exception as e:
            result = "Error"
            print(e)
        if result != "Error":
            for i in result.split("\n"):
                if i != "":
                    if i.count(":") < 1 and len(i) > 1:
                        if "ipv4_addresses" not in website[key]:
                            website[key]["ipv4_addresses"] = []
                        website[key]["ipv4_addresses"].append(i.strip())        
        get_ipv6(key,website)
        
        print(website[key])
def get_ipv6(address,website):
    website[address]["ipv6_addresses"] = []
    try:
        result = subprocess.check_output(["nslookup","-type=AAAA",address,"8.8.8.8"],timeout =2,stderr=subprocess.STDOUT).decode("utf-8")
        result = result.split("Name:")[1]
        if result.find("Addresses:") == -1:
            result = result.split("Address:")[1]
        else:
            result = result.split("Addresses:")[1]
    except Exception as e:
        result = "Error"
        print(e)
    if result != "Error":
        for i in result.split("\n"):
            if i != "":
                if i.count(":") > 1:
                    website[address]["ipv6_addresses"].append(i.strip())
                                      
if __name__ == "__main__":
    main()