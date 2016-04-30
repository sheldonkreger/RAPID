import unittest
import os
import logging
import tldextract
import pythonwhois
import dns.resolver
import geoip2.database
import core.google
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
        return {'status': 404, 'message': "No HTTPS certificate data was found for IP " + ip}
    except CensysException as ce:
        return {'status': ce.status_code, 'message': ce.message}


def google_for_indicator(indicator, limit=10, domain=None):
    """
    Find the top 'limit' Google search results for 'indicator' (excluding those from 'domain').

    Note: The domain will be wrapped in quotes before being submitted to Google.  It should therefore NOT be so wrapped
    when passed to this function.

    This method will also filter any results to ensure that none of the URLs returned actually point to the given domain
    (or any subdomain thereof).   In this manner, if you search for "domain.com," results such as
    "http://domain.com/page.html" and "http://sub.domain.com/file.pdf" will NOT be included in the results.

    :param indicator: The indicator value for which to search.  This should NOT be wrapped in quotation marks.
    :param limit: The maximum number of search results to return (optional, default: 10)
    :param domain: A domain from which results should be excluded
    :return: A list containing the URLs of the search results, in the order returned by Google
    """
    logger.debug("Searching Google for indicator '%s' (limit: %d)", indicator, limit)
    parameter = "\"" + indicator + "\""

    if domain is None:
        sifter = core.google.KeepSifter()
    else:
        sifter = core.google.DomainSifter(domain)
    result = list()
    try:
        for info in core.google.search(parameter, limit=limit, sifter=sifter):
            result.append(info.to_dict())
    except Exception:
        # Something went wrong, most likely when querying Google.  There's nothing we can really do about it, so we will
        # log the error and return an empty list
        logger.exception("Unexpected error performing Google search")
        result = list()
    if logger.isEnabledFor(logging.INFO):
        msg = "Found top %d/%d search result(s) for indicator '%s':" % (len(result), limit, indicator)
        rank = 0
        for info in result:
            rank += 1
            url = info["url"]
            msg += "\n\t%d - %s" % (rank, url)
        logger.info(msg)
    return result


def lookup_certs_censys(other, count):
    """Search the Censys.io API for any certificates that contain the search string
    
        Args:
            other (str): The string to search for in certificates (named other referencing
                the 'other' indicator type
            count (int): The maximum number of records to retrieve
            
        Returns (dict):
            Returns a dictionary that contains the following keys:
                records (list): A list of the certificates that matched this search string
                total (int): The total number of certificates that match this search
                count (int): The number of records being returned by this search
            If an error occurs while accessing the api, the dictionary will have the following keys:
                status (int): The status code of the error
                message (str): The error message
    """
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
