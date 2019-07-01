from abuseipdb import *

ipdb = AbuseIPDB('api key')

ip_check = ipdb.check('31.17.27.96')

print("----------")
print("IP Address: " + ip_check.ipAddress)
print("Last reported at: " + ip_check.lastReportedAt)
print("Abuse confidence score: " + str(ip_check.abuseConfidenceScore))
print("Abuser country: " + ip_check.countryName)
print("Abuser ISP: " + ip_check.isp)
print("Total reports of abuser: " + str(ip_check.totalReports))
print("----------")
