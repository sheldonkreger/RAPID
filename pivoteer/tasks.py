from __future__ import absolute_import

import datetime
from collections import OrderedDict
from django.conf import settings
from RAPID.celery import app
from core.lookups import lookup_ip_whois, lookup_domain_whois, resolve_domain, geolocate_ip, lookup_ip_censys_https, lookup_google_safe_browsing
from pivoteer.collectors.scrape import RobtexScraper, InternetIdentityScraper
from pivoteer.collectors.scrape import VirusTotalScraper, ThreatExpertScraper
from pivoteer.collectors.api import PassiveTotal
from .models import IndicatorRecord


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
    print("domain hosts retrieved ....." + ', '.join(hosts))

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
def google_safesearch(self, indicator):
    current_time = datetime.datetime.utcnow()
    safesearch_status = lookup_google_safe_browsing(indicator)
    try:
        record_entry = IndicatorRecord(record_type="SS",
                                       info_source='GOO',
                                       info_date=current_time,
                                       info=OrderedDict({"status": safesearch_status,
                                                         "foo2": "bar2"}))
        record_entry.save()
    except Exception as e:
        print(e)
