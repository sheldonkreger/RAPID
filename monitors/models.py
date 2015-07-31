from django.db import models
from django.conf import settings
from djorm_pgarray.fields import TextArrayField


class IndicatorLookupBase(models.Model):
    """
    Base model for indicator lookups
    """
    owner = models.ForeignKey(settings.AUTH_USER_MODEL)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True)
    lookup_interval = models.IntegerField()
    next_lookup = models.DateTimeField()
    last_hosts = TextArrayField(blank=True, null=True)
    tags = models.ManyToManyField('IndicatorTag', blank=True)

    class Meta:
        abstract = True


class DomainMonitor(IndicatorLookupBase):
    domain_name = models.CharField(max_length=253, primary_key=True)

    class Meta:
        unique_together = (('owner', 'domain_name'),)


class IpMonitor(IndicatorLookupBase):
    ip_address = models.GenericIPAddressField(unpack_ipv4=True, primary_key=True)

    class Meta:
        unique_together = (('owner', 'ip_address'),)


class IndicatorAlert(models.Model):
    """
    Base model for indicator alerts
    """
    indicator = models.CharField(max_length=253)
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    message = models.CharField(max_length=100)


class IndicatorTag(models.Model):
    tag = models.CharField(max_length=40)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL)

    def __unicode__(self):
        return self.tag

    def __str__(self):
        return self.tag

    class Meta:
        unique_together = (('tag', 'owner'),)