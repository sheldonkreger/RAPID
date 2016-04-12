import os
import logging
import tldextract
import pythonwhois
import dns.resolver
import geoip2.database
import google
from ipwhois import IPWhois
from collections import OrderedDict
from ipwhois.ipwhois import IPDefinedError
from censys.ipv4 import CensysIPv4
from censys.base import CensysException
from django.conf import settings
from urllib.parse import urlparse


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


def search_for_domain(domain, limit=10):
    """Find the top 'limit' Google search results for 'domain' (excluding those from 'domain' itself)."""
    logger.debug("Searching Google for domain '%s' (limit: %d)", domain, limit)
    parameter = "\"" + domain + "\""
    result = list()

    # We actually need to filter our results to ensure that we are NOT including results from the actual domain being
    # queried.  As a result, it might be necessary to query Google multiple times.  We will attempt to reduce this by
    # asking Google for three times the number of requested results.  (On the one hand, we don't want to ask Google too
    # frequently lest we be blocked.  On the other hand, we don't want excess results lest we waste time filtering.)
    num = limit * 3
    start = 0
    stop = limit
    try:
        while True:
            logger.debug("Checking Google (start: %d, stop: %d, num: %d)", start, stop, num)
            urls = list(google.search(parameter, num=num, start=start, stop=stop))
            logger.debug("Google results: %s", urls)
            if not urls:
                logger.warn("Only %d Google results were found for domain '%s' (requested %d)",
                            len(result),
                            domain,
                            limit)
                break
            result += [url for url in urls if not urlparse(url).netloc.endswith(domain)]
            logger.debug("Updated results: %s", result)

            # It's possible that we could end up with more results than requested, in which case we need to take only
            # the top 'limit' results.
            if len(result) >= limit:
                logger.debug("Maximum requested results met or exceeded (requested: %d, found %d)", limit, len(result))
                result = result[:limit]
                break

            start = stop
            stop += limit

    except Exception:
        # Something went wrong, most likely while querying Google.  There's nothing we can really do about it, so we
        # will log the error and return our list as-is (which is probably empty)
        logger.exception("Unexpected error performing google search")

    logger.debug("Found top %d/%d search results for domain '%s': %s", len(result), limit, domain, result)
    return result
