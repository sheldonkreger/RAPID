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


def lookup_google_safe_browsing(domain):
    url = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=rapid-dev&key=AIzaSyDtkkL0PIOrm86_Z8Q9Te14w-rOQF8Buko&appver=1.5.2&pver=3.1&url=" + domain
    response = urllib.request.urlopen(url)
    return response.status

    # https://sb-ssl.google.com/safebrowsing/api/lookup?client=rapid-dev&key=AIzaSyDtkkL0PIOrm86_Z8Q9Te14w-rOQF8Buko&appver=1.5.2&pver=3.1&url=sheldonkreger.com