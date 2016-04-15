import datetime
from IPy import IP
import tldextract
import re


def time_jump(days=0, hours=0, minutes=0):
    """
    Return the time X number of hours from current time (utc)
    """
    start_timestamp = datetime.datetime.utcnow()
    minute_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M')

    current_time = datetime.datetime.strptime(minute_timestamp, '%Y-%m-%d %H:%M')
    differential = current_time + datetime.timedelta(days=days,
                                                     hours=hours,
                                                     minutes=minutes)

    return differential


def check_ip_valid(submission):
    """
    Check if submission is a valid IP address
    """
    try:
        if str(IP(submission)) == str(submission):
            return True
        else:
            return False

    except ValueError:
        return False


def check_email_valid(submission):
    """
    Check if submission is a valid email address
    """
    if re.match(r"[^@]+@[^@]+\.[^@]+", submission):
        return True
    else:
        return False


def check_domain_valid(submission):
    """
    Check if submission is a valid domain
    """
    ext = tldextract.extract(submission)
    tld = ext.tld
    domain = ext.domain

    if tld and domain:
        return True
    else:
        return False


def discover_type(submission):
    """
    Figure out type of indicator a submission is
    """
    if check_ip_valid(submission):
        return "ip"

    elif check_email_valid(submission):
        return "email"

    elif check_domain_valid(submission):
        return "domain"

    else:
        return "other"


def get_base_domain(submission):
    # Extract base domain name for lookup
    ext = tldextract.extract(submission)

    if ext.domain and ext.tld:
        delimiter = "."
        sequence = (ext.domain, ext.tld)
        domain_name = delimiter.join(sequence)
        return domain_name

    return None
