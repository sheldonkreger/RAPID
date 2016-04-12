# -*- coding: utf-8 -*-

"""
Search
======
The search API resource exposes each of the totalhash search terms for programmatic use.

The current search terms are as follows;

av – search for samples that contain a specific phrase in all anti virus output. example: av:*poison*
Example:
    av: Trojan.Poison

dnsrr – search for samples that contain a specific phrase in any DNS requests made during dynamic analysis.
Example:
    dnsrr:*.3322.org
    dnsrr:mta5.am0.yahoodns.net

email – search for samples that contain a specific phrase in any email address that the malware sample has sent to
        during dynamic analysis.
Example:
    email:*@mail.ru
    example: email:fernanda88@hotmail.com

filename – search for samples that contain a specific phrase in any filenames that have been created/modified/deleted
            during dynamic analysis.
Example:
    filename:*sdra64.exe

hash – search for samples that have a specific SHA1 or MD5 hash. The hash maybe the whole sample or sections within a
        sample.
Example:
    hash:da39a3ee5e6b4b0d3255bfef95601890afd80709

ip – search for samples that have generated a network connection towards a specific IP address or an IP address seen
    in a DNS record.
Example:
    ip:8.8.8.8

mutex – search for samples that contain a specific phrase in a mutex value the sample has created during dynamic
        analysis.
Examples;
    mutex:DC_MUTEX_* mutex:ASPLOG

pdb – search for samples that contain a specific phrase found in the pdb path embedded in a sample.
Example:
    pdb:*Documents and Settings*

registry – search for samples that contain a specific phrase found in registry values that have been
            created/modified/deleted during dynamic analysis.
Example:
    registry:*rundll32.exe*

url – search for samples that contain a specific phrase found in any URLs generated during dynamic analysis.
Example:
    url:*/gate.php

useragent – search for samples that contain a specific phrase found in any user- agent strings seen in HTTP requests
        during dynamic analysis.
Example:
    useragent:malware.exe useragent:*wget*

version – search for samples that contain a specific phrase found in the version string embedded in the sample.
Example:
    version:*calc.exe*

Search terms can be combined using the logical operators AND, OR, NOT.

For example the following term could be used to find poison ivy samples that do not use the default mutex;
    av:*poison* NOT mutex:)!VoqA.I4
"""

import json
import urllib.request, urllib.error, urllib.parse
import hashlib
import hmac
import xmltodict


class TotalHashApi():
    def __init__(self, user='', key=''):
        self.baseurl = "http://api.totalhash.com/"
        self.user = user
        self.key = key
        print('user - ', self.user)
        print('key - ', self.key)

    def do_search(self, this_query, page_num=0):
        if page_num:
            url = self.baseurl + "search/" + this_query + "&id=%s" % self.user + "&sign=%s" % \
                                                                                 self.get_signature(this_query)
        else:
            url = self.baseurl + "search/" + this_query + "&id=%s" % self.user + "&sign=%s" % \
                                                                                 self.get_signature(
                                                                                     this_query) + "&start=%s" % page_num
        r = urllib.request.Request(url)
        return r

    def get_analysis(self, this_hash, page_num=0):
        if page_num:
            url = self.baseurl + "analysis/" + this_hash + "&id=%s" % self.user + "&sign=%s" % \
                                                                                  self.get_signature(this_hash)
        else:
            url = self.baseurl + "analysis/" + this_hash + "&id=%s" % self.user + "&sign=%s" % \
                                                                                  self.get_signature(
                                                                                      this_hash) + "&start=%s" % page_num
        r = urllib.request.Request(url)
        return r

    def get_usage(self):
        url = self.baseurl + "usage/" + "id=%s" % self.user + "&sign=%s" % self.get_signature('usage')
        r = urllib.request.Request(url)
        return r

    def string_response(self, response):
        opener = urllib.request.build_opener()
        response.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE+8.0; Windows NT 5.1; Trident/4.0;)')
        data = opener.open(response).read().decode('utf-8').strip()
        return data

    def json_response(self, response, pretty=True):
        opener = urllib.request.build_opener()
        response.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE+8.0; Windows NT 5.1; Trident/4.0;)')
        data = opener.open(response).read().decode('utf-8').strip()
        if pretty:
            return json.dumps(self.fix_keys(xmltodict.parse(data)), sort_keys=False, indent=4)
        else:
            return json.dumps(self.fix_keys(xmltodict.parse(data)))

    def get_signature(self, query):
        return hmac.new(self.key.encode('utf-8'), msg=query.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

    def fix_keys(self, somedict):
        return dict([(str(key_value[0]).replace('@', ""), key_value[1]) for key_value in list(somedict.items())])
