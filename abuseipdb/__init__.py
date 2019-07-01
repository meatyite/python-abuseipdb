import requests
import json


class ReportCategories:
    fraud_orders = 3
    ddos = 4
    ftp_bruteforce = 5
    ping_of_death = 6
    phishing = 7
    fraud_voip = 8
    open_proxy = 9
    web_spam = 10
    email_spam = 11
    blog_spam = 12
    vpn_ip = 13
    port_scan = 14
    hacking = 15
    sql_injection = 16
    spoofing = 17
    bruteforce = 18
    bad_web_bot = 19
    exploited_host = 20
    web_app_attack = 21
    ssh = 22
    iot_targeted = 23


class ReportError(Exception):
    pass


class CheckError(Exception):
    pass


class BlacklistError(Exception):
    pass


class CheckBlockError(Exception):
    pass


class CheckBlock:

    def __init__(self, networkAddress, netmask, minAddress, maxAddress, numPossibleHosts, addressSpaceDesc, reportedAddress):
        self.networkAddress = networkAddress
        self.netmask = netmask
        self.minAddress = minAddress
        self.maxAddress = maxAddress
        self.numPossibleHosts = numPossibleHosts
        self.addressSpaceDesc = addressSpaceDesc
        self.reportedAddress = reportedAddress


class reportedAddress:

    def __init__(self, ipAddress, numReports, mostRecentReport, abuseConfidenceScore, countryCode):
        self.ipAddress = ipAddress
        self.numReports = numReports
        self.mostRecentReport = mostRecentReport
        self.abuseConfidenceScore = abuseConfidenceScore
        self.countryCode = countryCode


class Report:

    def __init__(self, reportedAt, comment, categories, reporterId, reporterCountryCode, reporterCountryName):
        self.reportedAt = reportedAt
        self.comment = comment
        self.categories = categories
        self.reportedId = reporterId
        self.reporterCountryCode = reporterCountryCode
        self.reporterCountryName = reporterCountryName


class Check:

    def __init__(self, lastReportedAt, ipAddress, isPublic, ipVersion, isWhitelisted, abuseConfidenceScore, countryCode, countryName, usageType, isp, domain, totalReports, reports):
        self.lastReportedAt = lastReportedAt
        self.ipAddress = ipAddress
        self.isPublic = isPublic
        self.ipVersion = ipVersion
        self.isWhitelisted = isWhitelisted
        self.abuseConfidenceScore = abuseConfidenceScore
        self.countryCode = countryCode
        self.countryName = countryName
        self.usageType = usageType
        self.isp = isp
        self.domain = domain
        self.totalReports = totalReports
        self.reports = reports


class NewReport:

    def __init__(self, ipAddress, abuseConfidenceScore):
        self.ipAddress = ipAddress
        self.abuseConfidenceScore = abuseConfidenceScore


class BlacklistedIP:

    def __init__(self, ipAddress, totalReports, abuseConfidenceScore):
        self.ipAddress = ipAddress
        self.totalReports = totalReports
        self.abuseConfidenceScore = abuseConfidenceScore


class AbuseIPDB:

    def __init__(self, apikey):
        self.apikey = apikey

    def report(self, ip, comment="", categories=[]):
        report_json = requests.post(
            'https://api.abuseipdb.com/api/v2/report',
            headers={
                'Key': self.apikey,
                'Accept': 'application/json'
            },
            data={
                'ip': ip,
                'categories': ','.join(str(category) for category in categories),
                'comment': comment
            }
        ).content.decode()
        report_json = json.loads(report_json)
        if 'errors' in report_json.keys():
            error = report_json['errors'][0]['detail']
            raise ReportError(error)
        else:
            return NewReport(
                ipAddress=report_json['data']['ipAddress'],
                abuseConfidenceScore=report_json['data']['abuseConfidenceScore']
            )

    def check(self, ipAddress, maxAgeInDays=90):
        check_json = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={
                'Key': self.apikey,
                'Accept': 'application/json'
            },
            params={
                'ipAddress': ipAddress,
                'verbose': '',
                'maxAgeInDays': 90
            }
        ).content.decode()
        check_json = json.loads(check_json)
        if 'errors' in check_json.keys():
            error = check_json['errors'][0]['detail']
            raise CheckError(error)
        else:
            d = check_json['data']
            reports = []
            for report_data in d['reports']:
                reports.append(
                    Report(
                        reportedAt=report_data['reportedAt'],
                        comment=report_data['comment'],
                        categories=report_data['categories'],
                        reporterId=report_data['reporterId'],
                        reporterCountryCode=report_data['reporterCountryCode'],
                        reporterCountryName=report_data['reporterCountryName']
                    )
                )
            return Check(
                ipAddress=d['ipAddress'],
                isPublic=d['isPublic'],
                ipVersion=d['ipVersion'],
                isWhitelisted=d['isWhitelisted'],
                abuseConfidenceScore=d['abuseConfidenceScore'],
                countryCode=d['countryCode'],
                countryName=d['countryName'],
                usageType=d['usageType'],
                isp=d['isp'],
                domain=d['domain'],
                totalReports=d['totalReports'],
                lastReportedAt=d['lastReportedAt'],
                reports=reports
            )

    def get_blacklisted_ips(self, countMinimum=15, maxAgeInDays=60, confidenceMinimum=90):
        blacklisted_ips = []

        blacklisted_ip_json = requests.get(
            'https://api.abuseipdb.com/api/v2/blacklist',
            headers={
                'Key': self.apikey,
                'Accept': 'application/json'
            },
            params={
                'countMinimum': str(countMinimum),
                'maxAgeInDays': str(maxAgeInDays),
                'confidenceMinimum': str(confidenceMinimum)
            }
        ).content.decode()
        blacklisted_ip_json = json.loads(blacklisted_ip_json)
        if 'errors' in blacklisted_ip_json.keys():
            error = blacklisted_ip_json['errors'][0]['detail']
            raise BlacklistError(error)
        else:
            blacklist_ip_d = blacklisted_ip_json['data']
            for d in blacklist_ip_d:
                blacklisted_ips.append(
                    BlacklistedIP(
                        ipAddress=d['ipAddress'],
                        totalReports=d['totalReports'],
                        abuseConfidenceScore=d['abuseConfidenceScore']
                    )
                )
            return blacklisted_ips

    def checkblock(self, network, maxAgeInDays=15):
        checkblock_json = requests.get(
            'https://api.abuseipdb.com/api/v2/check-block',
            headers={
                'Key': self.apikey,
                'Accept': 'application/json'
            },
            params={
                'network': network,
                'maxAgeInDays': str(maxAgeInDays),
            }
        ).content.decode()
        checkblock_json = json.loads(checkblock_json)
        if 'errors' in checkblock_json.keys():
            error = checkblock_json['errors'][0]['detail']
            raise CheckBlockError(error)
        else:
            d = checkblock_json['data']
            reportedAddresses = []
            for reportedAddr in d['reportedAddress']:
                reportedAddresses.append(
                    reportedAddress(
                        ipAddress=reportedAddr['ipAddress'],
                        numReports=reportedAddr['numReports'],
                        mostRecentReport=reportedAddr['mostRecentReport'],
                        abuseConfidenceScore=reportedAddr['abuseConfidenceScore'],
                        countryCode=reportedAddr['countryCode']
                    )
                )
            return CheckBlock(
                networkAddress=d['networkAddress'],
                netmask=d['netmask'],
                minAddress=d['minAddress'],
                maxAddress=d['maxAddress'],
                numPossibleHosts=d['numPossibleHosts'],
                addressSpaceDesc=d['addressSpaceDesc'],
                reportedAddress=reportedAddresses
            )
