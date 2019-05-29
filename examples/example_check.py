from abuseipdb import *

ipdb = AbuseIPDB('api key')

ip_check = ipdb.Check('31.17.27.96')

print((ip_check.ipAddress, ip_check.countryName, ip_check.abuseConfidenceScore))