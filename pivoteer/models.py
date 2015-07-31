import pickle
import hashlib
import datetime
import collections
from django.db import models
from django.db.models import Q
from jsonfield import JSONField


class IndicatorManager(models.Manager):

    def host_records(self, indicator):
        record_type = 'HR'

        records = self.get_queryset().filter(Q(record_type=record_type),
                                             Q(info__contains=indicator))
        return records

    def recent_hosts(self, indicator):
        record_type = 'HR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(Q(record_type=record_type),
                                             Q(info_date__gte=time_frame),
                                             Q(info__contains=indicator))
        return records

    def historical_hosts(self, indicator, request):
        record_type = 'HR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        if request.user.is_staff:
            records = self.get_queryset().filter(Q(record_type=record_type),
                                                 Q(info_date__lt=time_frame),
                                                 Q(info__contains=indicator))

        else:
            records = self.get_queryset().filter(~Q(info_source="PTO"),
                                                 ~Q(info_source="IID"),
                                                 Q(record_type=record_type),
                                                 Q(info_date__lt=time_frame),
                                                 Q(info__contains=indicator))
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

        record = self.get_queryset().filter(Q(record_type=record_type),
                                            Q(info__contains=indicator))
        return record

    def recent_whois(self, indicator):
        record_type = 'WR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        record = self.get_queryset().filter(Q(record_type=record_type),
                                            Q(info_date__gte=time_frame),
                                            Q(info__contains=indicator))

        if record:
            return record.latest('info_date')

        return record

    def historical_whois(self, indicator):
        record_type = 'WR'
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(Q(record_type=record_type),
                                             Q(info_date__lt=time_frame),
                                             Q(info__contains=indicator))
        return records


class IndicatorRecord(models.Model):

    record_choices = (
        ('HR', 'Host Record'),
        ('MR', 'Malware Record'),
        ('WR', 'Whois Record'),
    )

    source_choices = (
        ('VTO', 'Virus Total'),
        ('TEX', 'Threat Expert'),
        ('IID', 'Internet Identity'),
        ('PTO', 'Passive Total'),
        ('DNS', 'DNS Query'),
        ('REX', 'Robtex'),
        ('WIS', 'WHOIS'),
    )

    record_type = models.CharField(max_length=2, choices=record_choices)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True)

    info = JSONField(load_kwargs={'object_pairs_hook': collections.OrderedDict})
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
    cookie = JSONField(load_kwargs={'object_pairs_hook': collections.OrderedDict})

