import pickle
import hashlib
import datetime
import logging
from django.db import models
from django.db.models import Q
from django.db.models import Max, Min
from django_pgjson.fields import JsonField
from core.utilities import check_domain_valid, get_base_domain


class IndicatorManager(models.Manager):

    LOGGER = logging.getLogger(__name__)

    def host_records(self, indicator):
        record_type = 'HR'

        records = self.get_queryset().filter(Q(record_type=record_type),
                                             Q(info__at_domain__endswith=indicator) |
                                             Q(info__at_ip__endswith=indicator))
        return records

    def recent_tc(self, indicator):
        record_type = 'TR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(Q(record_type=record_type),
                                             Q(info_date__gte=time_frame),
                                             Q(info__at_domain__endswith=indicator) |
                                             Q(info__at_ip__endswith=indicator)).values('info', 'info_date')
        if records:
            return records.latest('info_date')
        IndicatorManager.LOGGER.info("Failed to retrieve ThreatCrowd data for indicator %s" % s)
        return records

    def recent_hosts(self, indicator):
        record_type = 'HR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(Q(record_type=record_type),
                                             Q(info_date__gte=time_frame),
                                             Q(info__at_domain__endswith=indicator) |
                                             Q(info__at_ip__endswith=indicator))
        return records

    def historical_hosts(self, indicator, request):
        record_type = 'HR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        if request.user.is_staff:
            records = self.get_queryset().filter(Q(record_type=record_type),
                                                 Q(info_date__lt=time_frame),
                                                 Q(info__at_domain__endswith=indicator) |
                                                 Q(info__at_ip__endswith=indicator))

        else:
            records = self.get_queryset().filter(~Q(info_source="PTO"),
                                                 ~Q(info_source="IID"),
                                                 Q(record_type=record_type),
                                                 Q(info_date__lt=time_frame),
                                                 Q(info__at_domain__endswith=indicator) |
                                                 Q(info__at_ip__endswith=indicator))
        return records

    def malware_records(self, indicator):
        record_type = 'MR'

        records = self.get_queryset().filter(Q(record_type=record_type),
                                             Q(info__contains=indicator))
        return records

    def recent_malware(self, indicator):
        record_type = 'MR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(days=-30)

        records = self.get_queryset().filter(Q(record_type=record_type),
                                             Q(info_date__gte=time_frame),
                                             Q(info__contains=indicator))
        return records

    def historical_malware(self, indicator):
        record_type = 'MR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(days=-30)

        records = self.get_queryset().filter(Q(record_type=record_type),
                                             Q(info_date__lt=time_frame),
                                             Q(info__contains=indicator))
        return records

    def whois_records(self, indicator):
        record_type = 'WR'

        if check_domain_valid(indicator):
            indicator = get_base_domain(indicator)

        records = self.get_queryset().filter(Q(record_type=record_type),
                                            Q(info__at_query__endswith=indicator) |
                                            Q(info__at_domain_name__endswith=indicator)).values('info', 'info_date')
        return records

    def recent_whois(self, indicator):
        record_type = 'WR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        if check_domain_valid(indicator):
            indicator = get_base_domain(indicator)

        record = self.get_queryset().filter(Q(record_type=record_type),
                                            Q(info_date__gte=time_frame),
                                            Q(info__at_query__endswith=indicator) |
                                            Q(info__at_domain_name__endswith=indicator)).values('info', 'info_date')

        if record:
            return record.latest('info_date')

        return record

    def historical_whois(self, indicator):
        record_type = 'WR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        if check_domain_valid(indicator):
            indicator = get_base_domain(indicator)

        raw_records = self.get_queryset().filter(Q(record_type=record_type),
                                                 Q(info_date__lt=time_frame),
                                                 Q(info__at_query__endswith=indicator) |
                                                 Q(info__at_domain_name__endswith=indicator)).values('info_hash',
                                                                                                     'info_date')

        tracking = []
        unique_records = []
        annotated_records = raw_records.annotate(latest=Max('info_date')).annotate(earliest=Min('info_date'))

        for record in annotated_records:
            hash_value = record['info_hash']

            if hash_value not in tracking:
                record_info = self.get_queryset().filter(info_hash=hash_value).values('info')[0]['info']
                new_record = {'latest': record['latest'], 'earliest': record['earliest'], 'info': record_info}
                unique_records.append(new_record)
                tracking.append(hash_value)

        return unique_records


class IndicatorRecord(models.Model):

    record_choices = (
        ('HR', 'Host Record'),
        ('MR', 'Malware Record'),
        ('WR', 'Whois Record'),
        ('TR', 'ThreatCrowd Record'),
    )

    source_choices = (
        ('VTO', 'Virus Total'),
        ('TEX', 'Threat Expert'),
        ('IID', 'Internet Identity'),
        ('PTO', 'Passive Total'),
        ('DNS', 'DNS Query'),
        ('REX', 'Robtex'),
        ('WIS', 'WHOIS'),
        ('THR', 'ThreatCrowd'),
    )

    record_type = models.CharField(max_length=2, choices=record_choices)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True)

    info = JsonField()
    info_source = models.CharField(max_length=3, choices=source_choices)
    info_hash = models.CharField(max_length=40)
    info_date = models.DateTimeField()

    objects = IndicatorManager()

    class Meta:
        unique_together = (("info_hash", "info_source", "info_date"),)

    def generate_hash(self):
        info_pickle = pickle.dumps(self.info)
        info_sha1 = hashlib.sha1(info_pickle).hexdigest()
        return info_sha1

    def save(self, *args, **kwargs):

        if not self.info_hash:
            self.info_hash = self.generate_hash()

        super(IndicatorRecord, self).save(*args, **kwargs)


class TaskTracker(models.Model):
    """ Tracker for identifying and resuming tasks """
    keyword = models.CharField(max_length=253)
    group_id = models.CharField(max_length=50)
    type = models.CharField(max_length=50)
    date = models.DateTimeField()


class ExternalSessions(models.Model):
    """ External cookie sessions for scrapers """

    service_choices = (('IID', 'Internet Identity'),)

    service = models.CharField(max_length=3, choices=service_choices)
    cookie = JsonField()

