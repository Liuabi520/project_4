import sys
import json
import texttable
def main():
    with open(sys.argv[1]) as f:
        website = json.load(f)
    print(website)
    f.close()


def rtt(website):
    table = texttable.Texttable()
    table.set_cols_align(["l", "l", "l", "l"])
    table.set_cols_valign(["t", "t", "t", "t"])
    table.set_cols_width([20, 20, 20, 20])
    table.add_rows([["Address", "Min RTT", "Max RTT", "Range"]])
    for key in website:
        if "rtt_range" in website[key]:
            table.add_row([key, website[key]["rtt_range"][0], website[key]["rtt_range"][1], website[key]["rtt_range"][1] - website[key]["rtt_range"][0]])
    print(table.draw())

if __name__ == "__main__":
    main()