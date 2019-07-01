from abuseipdb import *

ipdb = AbuseIPDB('api key')

report = ipdb.report('127.0.0.3', 'Test Report', [ReportCategories.ssh, ReportCategories.bruteforce])

print((report.ipAddress, report.abuseConfidenceScore))
