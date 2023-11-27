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
            result = result.split("Name:")[1:]
            joined = ""
            for i in result:
                joined += i.split("Address:")[1]
            result = joined
        except Exception as e:
            result = "Error"
            print(e)
        if result != "Error":
            for i in result.split("\n"):
                print(i)
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
        website[key]["tls"] = check_tls(key)
        print(website[key])
def get_ipv6(address,website):
    website[address]["ipv6_addresses"] = []
    try:
        result = subprocess.check_output(["nslookup","-type=AAAA",address,"8.8.8.8"],timeout =2,stderr=subprocess.STDOUT).decode("utf-8")
        result = result.split("Name:")[1:]
        joined = ""
        for i in result:
            joined += i.split("Address:")[1]
        result = joined
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
    print(address)
    insecure = False
    try:
        session = requests.Session()
        session.max_redirects = 10
        r = session.get("http://"+address, allow_redirects= True,timeout=10)
        if r.status_code == 200:
            insecure = True
        else:
            insecure = False
        if insecure == False:
            return insecure, False
        i = r.history[r.history.__len__()-1]
        if (i.url).find("https://") != -1:
            return insecure, True
    except Exception as e:
        print(e)
        insecure = False

    return insecure, False
def check_hsts(site):
    try:
        session = requests.Session()
        session.max_redirects = 10
        response = session.get("https://" + site, allow_redirects= True,timeout=10)
        if 'strict-transport-security' in response.headers.keys():
            return True
        else:
            return False
    except Exception as e:
        print(e)
        return False
def check_tls(site):
    tls =[]
    try:
        response = subprocess.check_output(["nmap","--script", "ssl-enum-ciphers","-p","443",site],timeout =10,stderr=subprocess.STDOUT).decode("utf-8")
        if response.find("SSLv2") != -1:
            tls.append("SSLv2")
        if response.find("SSLv3") != -1:
            tls.append("SSLv3")
        if response.find("TLSv1.0") != -1:
            tls.append("TLSv1.0")
        if response.find("TLSv1.1") != -1:
            tls.append("TLSv1.1")
        if response.find("TLSv1.2") != -1:
            tls.append("TLSv1.2")
        if response.find("TLSv1.3") != -1:
            tls.append("TLSv1.3")
        return tls
    except Exception as e:
        print(e)
        return tls


if __name__ == "__main__":
    main()