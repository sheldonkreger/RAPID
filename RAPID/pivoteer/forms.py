from django import forms
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from core.utilities import discover_type
from .models import TaskTracker
from .tasks import *

from celery import group


class SubmissionForm(forms.Form):

    indicator = forms.CharField(label='Indicator Submission', widget=forms.TextInput())
    record_type = forms.CharField(widget=forms.TextInput())
    indicator_type = "unknown"

    def clean_indicator(self):
        indicator = self.cleaned_data.get('indicator').strip().lower()
        verified_type = discover_type(indicator)

        if verified_type:
            self.indicator_type = verified_type

        if self.indicator_type != "domain" and self.indicator_type != "ip":
            raise forms.ValidationError('That is not a valid ip or domain')

        return indicator

    def check_recent_tasks(self, desired_time):
        """
        Check if a recent task has been submitted for this indicator
        """

        indicator = self.cleaned_data['indicator']
        record_type = self.cleaned_data['record_type']

        try:
            recent_tasks = TaskTracker.objects.get(keyword=indicator,
                                                   type=record_type,
                                                   date__gte=desired_time)

        except MultipleObjectsReturned:
            recent_tasks = TaskTracker.objects.filter(keyword=indicator,
                                                      type=record_type,
                                                      date__gte=desired_time).latest('date')

        except ObjectDoesNotExist:
            recent_tasks = None

        return recent_tasks

    def create_new_task(self, current_time):
        """
        Create a task for a newly submitted indicator
        """
        indicator = self.cleaned_data['indicator']
        record_type = self.cleaned_data['record_type']

        if record_type == "current":

            if self.indicator_type == "domain":
                new_task = group([domain_whois.s(indicator),
                                  domain_hosts.s(indicator)])()

            elif self.indicator_type == "ip":
                new_task = group([ip_whois.s(indicator),
                                  ip_hosts.s(indicator)])()

            else:
                new_task = None

        elif record_type == "passive":
            new_task = group([virustotal_passive.s(indicator, self.indicator_type),
                              passivetotal_resolutions.s(indicator, self.indicator_type),
                              internet_identity.s(indicator)])()

        elif record_type == "malware":
            new_task = group([threatexpert_malware.s(indicator),
                              virustotal_malware.s(indicator)])()

        elif record_type == "other":
            new_task = group([google_search.s(indicator)])()

        else:
            new_task = None

        if new_task:  # Enforce saving of group meta for tracking
            new_task.save()

            TaskTracker(group_id=new_task.id, keyword=indicator,
                        type=record_type, date=current_time).save()

        return new_task