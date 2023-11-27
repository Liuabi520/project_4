import sys
import time
import subprocess
import socket
import requests
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
        http = check_http(key)
        if http != "Error":
            website[key]["http_server"] = http
        else:
            website[key]["http_server"] = None
        website[key]["insecure_http"], website[key]["redirect_to_https"] = check_insecure_http(key)
        website[key]["hsts"] = check_hsts(key)
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
def check_http(address):
    try:
        result = subprocess.check_output(["curl",'-I',address],timeout =2,stderr=subprocess.STDOUT).decode("utf-8")
        result = result.split("Server:")[1]
        result = result.split("\n")[0].strip()
        return result
    except Exception as e:
        result = "Error"
        print(e)
        return result
def check_insecure_http(address):
    insecure = False
    try:
        r = requests.get("http://"+address, allow_redirects= True,timeout=2)
        if r.status_code == 200:
            insecure = True
        else:
            insecure = False
    except Exception as e:
        print(e)
        insecure = False
    if insecure == False:
        return insecure, False
    for i in r.history:
        print(i.url)
        if (i.url).find("https://") != -1:
            return insecure, True
    return insecure, False

def check_hsts(site):
    try:
        response = requests.get("https://" + site)
        if 'strict-transport-security' in response.headers.keys():
            return True
        else:
            return False
    except:
        return False
if __name__ == "__main__":
    main()