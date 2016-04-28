
"""
Python API for malwr.com Website.

Note: Copied from https://github.com/PaulSec/API-malwr.com and modified
for python 3 compatibility.

Followings are the available search terms;
______________________________________________________________________
|   PREFIX	    |       DESCRIPTION                                  |
----------------------------------------------------------------------
|   name:	    |   File name pattern
|   type:	    |   File type/format
|   string:	    |   String contained in the binary
|   ssdeep:	    |   Fuzzy hash
|   crc32:	    |   CRC32 hash
|   imphash:	|   Search for PE Imphash
|   file:	    |   Opened files matching the pattern
|   key:	    |   Opened registry keys matching the pattern
|   mutex:	    |   Opened mutexes matching the pattern
|   domain:	    |   Contacted the specified domain
|   ip:	        |   Contacted the specified IP address
|   url:	    |   Performed HTTP requests matching the URL pattern
|   signature:	|   Search for Cuckoo Sandbox signatures
|   tag:	    |   Search on your personal tags
----------------------------------------------------------------------
"""

import hashlib, ssl, logging
import re
import requests
from bs4 import BeautifulSoup


class MalwrApi(object):
    """
        MalwrAPI Main Handler
    """
    session = None
    logged = False
    verbose = False

    url = "https://malwr.com"
    headers = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE+8.0; Windows NT 5.1; Trident/4.0;)'
    }
    LOGGER = logging.getLogger(__name__)

    def __init__(self, verbose=False, username=None, password=None):

        self.verbose = verbose
        self.session = requests.session()

        # Authenticate and store the session
        if username and password:

            soup = self.request_to_soup(self.url + '/account/login')
            csrf_input = soup.find(attrs=dict(name='csrfmiddlewaretoken'))
            csrf_token = csrf_input['value']

            payload = {
                'csrfmiddlewaretoken': csrf_token,
                'username': u'{0}'.format(username),
                'password': u'{0}'.format(password)
            }
            login_request = self.session.post("https://malwr.com/account/login/",
                                              data=payload, headers=self.headers)

            if login_request.status_code == 200:
                self.logged = True
            else:
                self.logged = False
                Malwr.LOGGER.warn ("Error Not being able to login using the credentials")

    def request_to_soup(self, url=None):

        if not url:
            url = self.url

        req = self.session.get(url, headers=self.headers)
        soup = BeautifulSoup(req.content, "html.parser")

        return soup

    def search(self, search_word):

        # Need better exception handling if not logged in
        if not self.logged:
            return []

        search_url = self.url + '/analysis/search/'
        c = self.request_to_soup(search_url)

        csrf_input = c.find(attrs=dict(name='csrfmiddlewaretoken'))
        csrf_token = csrf_input['value']
        payload = {
            'csrfmiddlewaretoken': csrf_token,
            'search': u'{}'.format(search_word)
        }
        sc = self.session.post(search_url, data=payload, headers=self.headers)
        ssc = BeautifulSoup(sc.content, "html.parser")

        res = []
        submissions = ssc.findAll('div', {'class': 'box-content'})[0]
        sub = submissions.findAll('tbody')[0]
        for submission in sub.findAll('tr'):
            infos = submission.findAll('td')
            infos_to_add = {
                'submission_time': infos[0].string,
                'hash': infos[1].find('a').string,
                'submission_url': infos[1].find('a')['href'],
                'file_name': infos[2].string
            }
            res.append(infos_to_add)

        return res