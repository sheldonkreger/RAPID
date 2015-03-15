import re
from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from core.utilities import time_jump
from core.utilities import check_domain_valid
from .models import DomainMonitor

User = get_user_model()


class SubmissionForm(forms.Form):
    domains = forms.CharField(label='Domain Submission', widget=forms.TextInput())

    def clean_domains(self):
        submission = self.cleaned_data.get('domains')
        domain_list = re.split(r'[,;|\n\r ]+', submission)
        validated_submissions = []

        for domain in domain_list:

            domain = domain.rstrip().lower()

            if check_domain_valid(domain):
                validated_submissions.append(domain)

        return validated_submissions

    def save_submission(self, request):

        domains = self.cleaned_data.get('domains')
        current_user = User.objects.get(email__exact=request.user)

        for domain in domains:

            try:
                DomainMonitor.objects.get(domain_name__exact=domain)

            except ObjectDoesNotExist:
                lookup_time = time_jump(minutes=1)
                new_monitor = DomainMonitor(domain_name=domain,
                                            lookup_interval='24',
                                            next_lookup=lookup_time)
                new_monitor.save()

            if domain not in current_user.domain_list:
                current_user.domain_list.append(domain)
                current_user.save()