import datetime, logging
from celery import Celery
from collections import OrderedDict
from django.test import TestCase
from pivoteer.models import IndicatorRecord, IndicatorManager
from pivoteer.tasks import certificate_cen, domain_thc, ip_thc, domain_whois, ip_whois, domain_hosts, ip_hosts, passive_hosts, malware_samples, google_safebrowsing, totalhash_ip_domain_search, make_indicator_search_records

app = Celery('RAPID')

logger = logging.getLogger(None)


class SimplisticTest(TestCase):

    indicator = "foo.com"
    current_time = datetime.datetime.utcnow()

    def setUp(self):
        print('In setUp()')
        app.conf.update(CELERY_ALWAYS_EAGER=True)
        app.conf.update(TEST_RUNNER = 'djcelery.contrib.test_runner.CeleryTestSuiteRunner')

    def tearDown(self):
        print('In tearDown()')

    def test_safesearch_record_contents(self):
        # Execute Celery task synchrounously using .delay(). This will store the record in the test DB.
        google_safebrowsing(self.indicator)

        # Retreive records (return value is a QuerySet).
        safebrowsing_records = IndicatorRecord.objects.safebrowsing_record(self.indicator)
        self.assertGreater(safebrowsing_records.count(), 0)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in safebrowsing_records:
            self.assertTrue("SB" in record.record_type)
            self.assertTrue("GSB" in record.info_source)
            self.assertGreater(datetime.datetime.utcnow(), record.info_date)
            self.assertTrue("statusCode" in record.info)
            self.assertTrue("indicator" in record.info)
            self.assertTrue("body" in record.info)

    def test_malware_record_contents(self):
        # Execute Celery task synchrounously using .delay(). This will store the record in the test DB.
        malware_samples.delay(self.indicator, "VTO")

        # Retreive records (return value is a QuerySet).
        malware_vto_records = IndicatorRecord.objects.malware_records(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in malware_vto_records:
            self.assertTrue("MR" in record.record_type)
            self.assertTrue("VTO" in record.info_source)
            self.assertEqual(self.current_time, record.info_date)
            self.assertTrue("md5" in record.info)
            self.assertTrue("sha1" in record.info)
            self.assertTrue("indicator" in record.info)
            self.assertTrue("link" in record.info)

    def test_certificate_cen_contents(self):
        # Execute Celery task synchrounously using .delay(). This will store the record in the test DB.
        certificate_cen.delay(self.indicator, "VTO")

        # Retreive records (return value is a QuerySet).
        certificate_cen_records = IndicatorRecord.objects.recent_cert(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in certificate_cen_records:
            self.assertTrue("CE" in record.record_type)
            self.assertTrue("CEN" in record.info_source)
            self.assertEqual(self.current_time, record.info_date)
            self.assertTrue("info" in record)

    def test_domain_thc(self):
        # Execute Celery task synchrounously using .delay(). This will store the record in the test DB.
        domain_thc.delay(self.indicator)

        # Retreive records (return value is a QuerySet).
        domain_thc_records = IndicatorRecord.objects.recent_tc(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in domain_thc_records:
            self.assertTrue("TR" in record.record_type)
            self.assertTrue("THR" in record.info_source)
            self.assertEqual(self.current_time, record.info_date)
            self.assertTrue("info" in record)

    def test_ip_thc(self):
        # Execute Celery task synchrounously using .delay(). This will store the record in the test DB.
        ip_thc.delay(self.indicator)

        # Retreive records (return value is a QuerySet).
        ip_thc_records = IndicatorRecord.objects.recent_tc(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in ip_thc_records:
            self.assertTrue("TR" in record.record_type)
            self.assertTrue("THR" in record.info_source)
            self.assertEqual(self.current_time, record.info_date)
            self.assertTrue("info" in record)

    def test_domain_whois(self):
        # Execute Celery task synchrounously using .delay(). This will store the record in the test DB.
        domain_whois.delay(self.indicator)

        # Retreive records (return value is a QuerySet).
        domain_whois_records = IndicatorRecord.objects.whois_records(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in domain_whois_records:
            self.assertTrue("WR" in record.record_type)
            self.assertTrue("WIS" in record.info_source)
            self.assertEqual(self.current_time, record.info_date)
            self.assertTrue("info" in record)
            self.assertTrue("domain" in record.info)
            self.assertTrue("status" in record.info)
            self.assertTrue("registrar" in record.info)
            self.assertTrue("updated_date" in record.info)
            self.assertTrue("expiration_date" in record.info)
            self.assertTrue("nameservers" in record.info)
            self.assertTrue("contacts" in record.info)

    def test_ip_whois(self):
        # Execute Celery task synchrounously using .delay(). This will store the record in the test DB.
        ip_whois.delay(self.indicator)

        # Retreive records (return value is a QuerySet).
        ip_whois_records = IndicatorRecord.objects.whois_records(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in ip_whois_records:
            self.assertTrue("WR" in record.record_type)
            self.assertTrue("WIS" in record.info_source)
            self.assertEqual(self.current_time, record.info_date)
            self.assertTrue("info" in record)
            self.assertTrue("query" in record.info)
            self.assertTrue("asn" in record.info)
            self.assertTrue("asn_registry" in record.info)
            self.assertTrue("asn_country_code" in record.info)
            self.assertTrue("asn_date" in record.info)
            self.assertTrue("referral" in record.info)
            self.assertTrue("dates" in record.info)


    def test_domain_hosts(self):
        # Execute Celery task synchrounously using .delay(). This will store the record in the test DB.
        domain_hosts.delay(self.indicator)

        # Retreive records (return value is a QuerySet).
        domain_hosts_records = IndicatorRecord.objects.recent_hosts(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in domain_hosts_records:
            self.assertTrue("HR" in record.record_type)
            self.assertTrue("DNS" in record.info_source)
            self.assertEqual(self.current_time, record.info_date)
            self.assertTrue("info" in record)
            self.assertTrue("geo_location" in record.info)
            self.assertTrue("https_cert" in record.info)
            self.assertTrue("ip" in record.info)

    def test_ip_hosts(self):
        # Execute Celery task synchrounously using .delay(). This will store the record in the test DB.
        ip_hosts.delay(self.indicator)

        # Retreive records (return value is a QuerySet).
        ip_hosts_records = IndicatorRecord.objects.recent_hosts(self.indicator)

        if not ip_hosts_records:
            print("no good")

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in ip_hosts_records:
            self.assertTrue("HR" in record.record_type)
            self.assertTrue("REX" in record.info_source)
            self.assertEqual(self.current_time, record.info_date)
            self.assertTrue("info" in record)
            self.assertTrue("geo_location" in record.info)
            self.assertTrue("htts_cert" in record.info)
            self.assertTrue("ip" in record.info)

    # def test_passive_hosts(self):
