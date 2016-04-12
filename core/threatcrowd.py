import requests, json, logging

# Queries the ThreadCrowd API for information on domains and IPs
class ThreatCrowd(object):
    
    BASE_URL = "https://www.threatcrowd.org/searchApi/v2"
    IP_URL = BASE_URL + "/ip/report/"
    DOMAIN_URL = BASE_URL + "/domain/report/"
    LOGGER = logging.getLogger(__name__)
    
    @staticmethod
    def _query(url, data):
        try:
            text = requests.get(url, params=data).text
            return json.loads(text)
        except Exception as e:
            ThreatCrowd.LOGGER.warn("Error retrieving data from ThreatCrowd: " + str(e))
            return {'error':str(e)}

    @staticmethod
    def queryDomain(domain):
        ThreatCrowd.LOGGER.info("Querying ThreatCrowd for domain: " + domain)
        return ThreatCrowd._query(ThreatCrowd.DOMAIN_URL,{"domain":domain})
    
    @staticmethod
    def queryIp(ip):
        ThreatCrowd.LOGGER.info("Querying ThreatCrowd for ip: " + ip)
        return ThreatCrowd._query(ThreatCrowd.IP_URL,{"ip":ip})
