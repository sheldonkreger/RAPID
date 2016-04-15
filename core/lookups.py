import unittest
import os
import logging
import tldextract
import pythonwhois
import dns.resolver
import geoip2.database
import urllib.request
from ipwhois import IPWhois
from collections import OrderedDict
from ipwhois.ipwhois import IPDefinedError
from censys.ipv4 import CensysIPv4
from censys.certificates import CensysCertificates
from censys.base import CensysException
from django.conf import settings

logger = logging.getLogger(__name__)
current_directory = os.path.dirname(__file__)


def geolocate_ip(ip):

    geolocation_database = os.path.join(current_directory, 'GeoLite2-City.mmdb')
    reader = geoip2.database.Reader(geolocation_database)

    try:
        response = reader.city(ip)

        # Geo-location results - city, state / province, country
        results = OrderedDict({"city": response.city.name,
                               "province": response.subdivisions.most_specific.name,
                               "country": response.country.name})
        return results

    except ValueError:
        logger.debug("Invalid IP address passed")

    except geoip2.errors.AddressNotFoundError:
        logger.debug("IP address not found in database")

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)

    return OrderedDict({"city": "", "province": "", "country": ""})


def resolve_domain(domain):

    # Set resolver to Google openDNS servers
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    try:
        query_answer = resolver.query(qname=domain)
        answer = [raw_data.address for raw_data in query_answer]
        return answer

    except dns.resolver.NXDOMAIN:
        alert = "NX Domain"

    except dns.resolver.Timeout:
        alert = "Query Timeout"

    except dns.resolver.NoAnswer:
        alert = "No Answer"

    except dns.resolver.NoNameservers:
        alert = "No Name Server"

    except Exception:
        alert = "Unexpected error"

    return [alert]


def lookup_domain_whois(domain):

    # Extract base domain name for lookup
    ext = tldextract.extract(domain)
    delimiter = "."
    sequence = (ext.domain, ext.tld)
    domain_name = delimiter.join(sequence)

    try:
        # Retrieve parsed record
        record = pythonwhois.get_whois(domain_name)
        record.pop("raw", None)
        record['domain_name'] = domain_name
        return record

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)

    return None


def lookup_ip_whois(ip):

    try:
        # Retrieve parsed record
        record = IPWhois(ip).lookup()
        record.pop("raw", None)
        record.pop("raw_referral", None)
        return record

    except ValueError:
        logger.debug("Invalid IP address passed")

    except IPDefinedError:
        logger.debug("Private-use network IP address passed")

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)

    return None

# See docs: https://developers.google.com/safe-browsing/lookup_guide#HTTPGETRequest

def lookup_google_safe_browsing(domain):
    url = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=" + settings.GOOGLE_SAFEBROWSING_API_CLIENT + "&key=" + settings.GOOGLE_SAFEBROWSING_API_KEY + "&appver=1.5.2&pver=3.1&url=" + domain
    response = urllib.request.urlopen(url)

    # We only get a request body when Google thinks the indicator is malicious. There are a few different values it might return.
    if response.status == 200:
        body = response.read().decode("utf-8")

    elif response.status == 400:
        logger.error("Bad request to Google SafeBrowsing API. Indicator:")
        logger.error(domain)
        body = "Bad Request to API"

    elif response.status == 401:
        logger.error("Bad API key for Google SafeBrowsing API.")
        body = "Bad Request to API"

    elif response.status == 503:
        logger.error("Google SafeSearch API is unresponsive. Potentially too many requests coming from our application, or their service is down.")
        body = "SafeBrowsing API offline or throttling our requests"

    # There is no body when the API thinks this inidcator is safe.
    else:
        body = "OK"

    return (response.status, body)

def lookup_ip_censys_https(ip):
    api_id = settings.CENSYS_API_ID
    api_secret = settings.CENSYS_API_SECRET

    try:
        ip_data = CensysIPv4(api_id=api_id, api_secret=api_secret).view(ip)
        return ip_data['443']['https']['tls']['certificate']['parsed']
    except KeyError:
        return {'status':404,'message':"No HTTPS certificate data was found for IP " + ip}
    except CensysException as ce:
        return {'status':ce.status_code,'message':ce.message}

def lookup_certs_censys(other, count):
    api_id = settings.CENSYS_API_ID
    api_secret = settings.CENSYS_API_SECRET

    try:
        cc = CensysCertificates(api_id=api_id, api_secret=api_secret)
        generator = cc.search(other)
        i = 0
        results = {'records':[]}
        for record in generator:
            if i == 0:
                results['total'] = generator.gi_frame.f_locals['payload']['metadata']['count']
            for sha256 in record['parsed.fingerprint_sha256']:
                results['records'].append(cc.view(sha256))
                i+=1
            if i >= count:
                break
        results['count'] = i
        return results
    except CensysException as ce:
        return {'status':ce.status_code,'message':ce.message}
