from abuseipdb import *

ipdb = AbuseIPDB('api key')

blacklisted_ips = ipdb.GetBlacklistedIPs()

for ip in blacklisted_ips:
    print((ip.ipAddress, str(ip.abuseConfidenceScore)))