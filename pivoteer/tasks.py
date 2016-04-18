from __future__ import absolute_import
from netaddr import *

import datetime, logging, json
import dpath.util
from collections import OrderedDict
from django.conf import settings
from RAPID.celery import app
from core.threatcrowd import ThreatCrowd
from core.totalhash import TotalHashApi
from core.lookups import lookup_ip_whois, lookup_domain_whois, resolve_domain, geolocate_ip, lookup_ip_censys_https, \
    lookup_google_safe_browsing
from core.lookups import lookup_ip_whois, lookup_domain_whois, resolve_domain, geolocate_ip, lookup_ip_censys_https, lookup_google_safe_browsing, lookup_certs_censys
from pivoteer.collectors.scrape import RobtexScraper, InternetIdentityScraper
from pivoteer.collectors.scrape import VirusTotalScraper, ThreatExpertScraper
from pivoteer.collectors.api import PassiveTotal
from .models import IndicatorRecord

logger = logging.getLogger(None)

@app.task(bind=True)
def certificate_cen(self, indicator):
	current_time = datetime.datetime.utcnow()
	record = lookup_certs_censys(indicator, 25)
	record['indicator'] = indicator
	logger.info("Retrieved Censys.io search results for indicator %s" % indicator)
	if record:
		try:
			record_entry = IndicatorRecord(record_type="CE",
											info_source="CEN",
											info_date=current_time,
											info=record)
			record_entry.save()
			logger.info("CE record saved successfully")
		except Exception as e:
			logger.warn("Error creating or saving CE record: %s" % str(e))

# Task to look up threatcrowd domain
@app.task(bind=True)
def domain_thc(self, domain):
    current_time = datetime.datetime.utcnow()
    record = ThreatCrowd.queryDomain(domain)
    record['domain'] = domain
    logger.info("Retrieved ThreatCrowd data for domain %s. Data: %s" % (domain, json.dumps(record)))
    if record:
        try:
            record_entry = IndicatorRecord(record_type="TR",
                                            info_source="THR",
                                            info_date=current_time,
                                            info=record)
            logger.info("Created TR record_entry %s" % str(record_entry))
            record_entry.save()
            logger.info("TR record saved successfully")
        except Exception as e:
            logger.warn("Error creating or saving TR record: %s" % str(e))
            print(e)

# Task to look up threatcrowd ip
@app.task(bind=True)
def ip_thc(self, ip):
    current_time = datetime.datetime.utcnow()
    record = ThreatCrowd.queryIp(ip)
    record['ip'] = ip
    if record:
        try:
            record_entry = IndicatorRecord(record_type="TR",
                                            info_source="THR",
                                            info_date=current_time,
                                            info=record)
            record_entry.save()
        except Exception as e:
            print(e)

@app.task(bind=True)
def domain_whois(self, domain):
    current_time = datetime.datetime.utcnow()
    record = lookup_domain_whois(domain)

    if record:
        try:
            record_entry = IndicatorRecord(record_type="WR",
                                           info_source="WIS",
                                           info_date=current_time,
                                           info=OrderedDict({'domain_name': record['domain_name'],
                                                             'status': record['status'],
                                                             'registrar': record['registrar'],
                                                             'updated_date': record['updated_date'],
                                                             'expiration_date': record['expiration_date'],
                                                             'nameservers': record['nameservers'],
                                                             'contacts': record['contacts']}))
            record_entry.save()
        except Exception as e:
            print(e)


@app.task(bind=True)
def ip_whois(self, ip_address):

    current_time = datetime.datetime.utcnow()
    record = lookup_ip_whois(ip_address)

    if record:
        try:
            record_entry = IndicatorRecord(record_type="WR",
                                           info_source="WIS",
                                           info_date=current_time,
                                           info=OrderedDict({'query': record['query'],
                                                             'asn_cidr': record['asn_cidr'],
                                                             'asn': record['asn'],
                                                             'asn_registry': record['asn_registry'],
                                                             'asn_country_code': record['asn_country_code'],
                                                             'asn_date': record['asn_date'],
                                                             'referral': record['referral'],
                                                             'nets': record['nets']}))
            record_entry.save()
        except Exception as e:
            print(e)


@app.task(bind=True)
def domain_hosts(self, domain):

    current_time = datetime.datetime.utcnow()
    hosts = resolve_domain(domain)

    if type(hosts) == list:
        for host in hosts:

            ip_location = geolocate_ip(host)
            https_cert = lookup_ip_censys_https(host)

            try:
                record_entry = IndicatorRecord(record_type="HR",
                                               info_source="DNS",
                                               info_date=current_time,
                                               info=OrderedDict({"geo_location": ip_location,
                                                                 "https_cert": https_cert,
                                                                 "ip": host, "domain": domain}))
                record_entry.save()
            except Exception as e:
                print(e)


@app.task(bind=True)
def ip_hosts(self, ip_address):

    current_time = datetime.datetime.utcnow()
    scraper = RobtexScraper()
    hosts = scraper.run(ip_address)
    ip_location = geolocate_ip(ip_address)
    https_cert = lookup_ip_censys_https(ip_address)

    if type(hosts) == list:
        for host in hosts:
            try:
                record_entry = IndicatorRecord(record_type="HR",
                                               info_source="REX",
                                               info_date=current_time,
                                               info=OrderedDict({"geo_location": ip_location,
                                                                 "https_cert": https_cert,
                                                                 "ip": ip_address, "domain": host}))
                record_entry.save()
            except Exception as e:
                print(e)

@app.task(bind=True)
def passive_hosts(self, indicator, source):

    if source == "IID":
        scraper = InternetIdentityScraper()
        passive = scraper.run(indicator)  # returns table of data rows {ip, domain, date, ip_location}

    elif source == "PTO":
        api_key = settings.PASSIVE_TOTAL_API
        collector = PassiveTotal(api_key, api_version="v1")
        passive = collector.retrieve_data(indicator, "passive")

    elif source == "VTO":
        scraper = VirusTotalScraper()
        passive = scraper.get_passive(indicator)  # returns table of data rows {ip, domain, date, ip_location}

    else:
        passive = {}

    for entry in passive:
        try:
            record_entry = IndicatorRecord(record_type="HR",
                                           info_source=source,
                                           info_date=entry['date'],
                                           info=OrderedDict({"geo_location": entry['ip_location'],
                                                             "ip": entry['ip'], "domain": entry['domain']}))
            record_entry.save()
        except Exception as e:
            print(e)


@app.task(bind=True)
def malware_samples(self, indicator, source):

    if source == "VTO":
        scraper = VirusTotalScraper()
        malware = scraper.get_malware(indicator) #

    elif source == "TEX":
        scraper = ThreatExpertScraper()
        malware = scraper.run(indicator)

    else:
        malware = []

    for entry in malware:
        try:
            record_entry = IndicatorRecord(record_type="MR",
                                           info_source=source,
                                           info_date=entry['date'],
                                           info=OrderedDict({"md5": entry['md5'],
                                                             "sha1": entry['sha1'],
                                                             "sha256": entry['sha256'],
                                                             "indicator": entry['C2'],
                                                             "link": entry['link']}))
            record_entry.save()
        except Exception as e:
            print(e)

@app.task(bind=True)
def google_safebrowsing(self, indicator):
    current_time = datetime.datetime.utcnow()
    safebrowsing_response = lookup_google_safe_browsing(indicator)
    safebrowsing_status = safebrowsing_response[0]
    safebrowsing_body = safebrowsing_response[1]
    try:
        record_entry = IndicatorRecord(record_type="SB",
                                       info_source='GSB',
                                       info_date=current_time,
                                       # We store the status code that the Google SafeSearch API returns.
                                       info=OrderedDict({"indicator": indicator,
                                                        "statusCode": safebrowsing_status,
                                                         "body": safebrowsing_body}))
        record_entry.save()
    except Exception as e:
        print(e)


# Task to look up totalhash ip or domain search terms
@app.task(bind=True)
def totalhash_ip_domain_search(self, indicator):
    th_logger = logging.getLogger(None)
    api_id = settings.TOTAL_HASH_API_ID
    api_secret = settings.TOTAL_HASH_SECRET
    current_time = datetime.datetime.utcnow()
    th = TotalHashApi(user=api_id, key=api_secret)
    if valid_ipv6(indicator) or valid_ipv4(indicator):
        query = "ip:" + indicator
    else:
        query = "dnsrr:" + indicator
    th_logger.info("Querying Totalhash for %s" % query)
    res = th.do_search(query)
    record = th.json_response(res)  # from totalhash xml response
    record_count = dpath.util.get(json.loads(record), "response/result/numFound")

    if int(record_count) > 0:
        try:
            raw_record = json.loads(record)
            # key 'text' contains actual hash
            hash_list = []
            for elm in th.scrape_hash(raw_record, 'text'):
                # link is not using api 'key' & 'user' combination
                hash_list.append(dict(indicator=indicator, hash=elm, link='https://totalhash.cymru.com/analysis/?' + elm))

            th_logger.info("Retrieved Totalhash data for query %s Data: %s" % (query, hash_list))

            # adding to malware records
            for entry in hash_list:
                record_entry = IndicatorRecord(record_type="MR",
                                               info_source="THS",
                                               info_date=current_time,
                                               info=OrderedDict({"sha1": entry['hash'],
                                                                 "indicator": entry['indicator'],
                                                                 "link": entry['link']}))
                record_entry.save()

            logger.info("%d TH record_entries saved successfully" % len(hash_list))
        except Exception as e:
            logger.warn("Error creating or saving TH record: %s" % str(e))
            print(e)
    else:
        logger.info("No Totalhash data, save aborted")
