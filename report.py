import sys
import json
import texttable
def main():
    with open(sys.argv[1]) as f:
        website = json.load(f)
    rtt(website)
    root_ca(website)
    type_server(website)
    checkpercentage(website)
    f.close()


def rtt(website):
    table = texttable.Texttable()
    table.set_cols_align(["l", "l", "l", "l"])
    table.set_cols_valign(["t", "t", "t", "t"])
    table.set_cols_width([20, 20, 20, 20])
    table.add_rows([["Address", "Min RTT", "Max RTT", "Range"]])
    rtt = []
    for key in website:
        if "rtt_range" in website[key]:
            rtt.append([key, website[key]["rtt_range"][0], website[key]["rtt_range"][1], website[key]["rtt_range"]])
    rtt.sort(key=lambda x: x[1])
    for i in rtt:
        table.add_row(i)
    with open(sys.argv[2], "a") as f:
        f.write(table.draw())
    # print(table.draw())
    table.reset()
    f.close()
def root_ca(website):
    table = texttable.Texttable()
    count = {}
    for key in website:
        if "root_ca" in website[key]:
            if website[key]["root_ca"] not in count:
                count[website[key]["root_ca"]] = 0
            count[website[key]["root_ca"]] += 1
    table.set_cols_align(["l", "l"])
    table.set_cols_valign(["t", "t"])
    table.set_cols_width([20, 20])
    table.add_rows([["Root CA", "Count"]])
    count = sorted(count.items(), key=lambda x: x[1], reverse=True)
    for i in count:
        table.add_row([i[0], i[1]])
    with open(sys.argv[2], "a") as f:
        f.write(table.draw())
    # print(table.draw())
    table.reset()
    f.close()
def type_server(website):
    table = texttable.Texttable()
    count = {}
    for key in website:
        if "http_server" in website[key]:
            if website[key]["http_server"] not in count:
                count[website[key]["http_server"]] = 0
            count[website[key]["http_server"]] += 1
    table.set_cols_align(["l", "l"])
    table.set_cols_valign(["t", "t"])
    table.set_cols_width([20, 20])
    table.add_rows([["Server", "Count"]])
    count = sorted(count.items(), key=lambda x: x[1], reverse=True)
    for i in count:
        table.add_row([i[0], i[1]])
    with open(sys.argv[2], "a") as f:
        f.write(table.draw())
    # print(table.draw())
    table.reset()
    f.close()
def checkpercentage(website):
    total = 0
    insec = 0
    redirect = 0
    ipv6 = 0
    hsts = 0
    count= {}
    count["TLSv1.0"] = 0
    count["TLSv1.1"] = 0
    count["TLSv1.2"] = 0
    count["TLSv1.3"] = 0
    count["SSLv2"] = 0
    count["SSLv3"] = 0
    table = texttable.Texttable()
    table.set_cols_align(["l", "l"])
    table.set_cols_valign(["t", "t"])
    table.set_cols_width([20, 20])
    table.add_rows([["TLS Version", "Percentage"]])
    for key in website:
        if "tls" in website[key]:
            for i in website[key]["tls"]:
                print(i)
                count[i] += 1
                total += 1
        if "insecure_http" in website[key]:
            if website[key]["insecure_http"] == True:
                insec += 1
        if "redirect_to_https" in website[key]:
            if website[key]["redirect_to_https"] == True:
                redirect += 1
        if "ipv6_addresses" in website[key]:
            if len(website[key]["ipv6_addresses"]) > 0:
                ipv6 += 1
        if "hsts" in website[key]:
            if website[key]["hsts"] == True:
                hsts += 1
    for key in count:
        count[key] = round(count[key]/len(website)*100,2)
        table.add_row([key,count[key]])
    table.add_row(["Insecure HTTP",round(insec/len(website)*100,2)])
    table.add_row(["Redirect to HTTPS",round(redirect/len(website)*100,2)])
    table.add_row(["HSTS",round(hsts/len(website)*100,2)])
    table.add_row(["IPv6",round(ipv6/len(website)*100,2)])
    with open(sys.argv[2], "a") as f:
        f.write(table.draw())
    print(table.draw())
    table.reset()



    

    
if __name__ == "__main__":
    main()