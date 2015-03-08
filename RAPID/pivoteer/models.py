import collections
from django.db import models
from django.db.models import Q
from djorm_pgarray.fields import TextArrayField
from jsonfield import JSONField


class HostManager(models.Manager):

    def current_hosts(self, indicator, desired_time):

        current = self.get_queryset().filter(Q(domain_name=indicator) | Q(ip_address=indicator),
                                             Q(resolution_date__gte=desired_time),
                                             Q(query_keyword=indicator))

        # Iterate for unique values - not ideal solution but will work for now
        resolutions = [indicator]
        cleaned_records = []

        for record in current:
            if record.domain_name not in resolutions:
                resolutions.append(record.domain_name)
                cleaned_records.append(record)

            elif record.ip_address not in resolutions:
                resolutions.append(record.ip_address)
                cleaned_records.append(record)

        return cleaned_records

    def passive_records(self, indicator, request):

        if request.user.is_staff:
            records = self.get_queryset().filter(~Q(resolution_source="DNS Query"),
                                                 ~Q(resolution_source="Robtex"),
                                                 Q(query_keyword=indicator))

        else:
            records = self.get_queryset().filter(~Q(resolution_source="InternetIdentity"),
                                                 ~Q(resolution_source="DNS Query"),
                                                 ~Q(resolution_source="Robtex"),
                                                 Q(query_keyword=indicator))

        return records


class HostRecord(models.Model):
    domain_name = models.CharField(max_length=253)
    ip_address = models.CharField(max_length=45)
    ip_location = TextArrayField(default=[])
    resolution_date = models.DateTimeField()
    resolution_source = models.CharField(max_length=50)
    query_keyword = models.CharField(max_length=253)
    query_date = models.DateTimeField()

    objects = HostManager()


class MalwareManager(models.Manager):

    def malware_records(self, indicator):

        records = MalwareRecord.objects.filter(query_keyword=indicator)
        return records


class MalwareRecord(models.Model):
    submission_date = models.DateTimeField()
    MD5_value = models.CharField(max_length=32)
    SHA1_value = models.CharField(max_length=40)
    SHA256_value = models.CharField(max_length=64)
    report_link = models.URLField()
    report_source = models.CharField(max_length=50)
    query_keyword = models.CharField(max_length=253)
    query_date = models.DateTimeField()

    objects = MalwareManager()


class WhoisManager(models.Manager):

    def recent_record(self, indicator):

        whois = self.get_queryset().filter(query_keyword=indicator).latest('query_date')

        if whois:
            return whois.record
        else:
            return None


class WhoisRecord(models.Model):
    query_keyword = models.CharField(max_length=253)
    query_date = models.DateTimeField()
    record = JSONField(load_kwargs={'object_pairs_hook': collections.OrderedDict})

    objects = WhoisManager()


class SearchManager(models.Manager):

    def recent_record(self, indicator):

        record = self.get_queryset().filter(query_keyword=indicator).latest('query_date')
        return record


class SearchEngineHits(models.Model):
    query_keyword = models.CharField(max_length=253)
    query_date = models.DateTimeField()
    result_count = models.CharField(max_length=50)
    results = TextArrayField(default=[])

    objects = SearchManager()


class TaskTracker(models.Model):
    keyword = models.CharField(max_length=253)
    group_id = models.CharField(max_length=50)
    type = models.CharField(max_length=50)
    date = models.DateTimeField()


class ExternalSessions(models.Model):
    service = models.CharField(max_length=50)
    cookie = JSONField(load_kwargs={'object_pairs_hook': collections.OrderedDict})