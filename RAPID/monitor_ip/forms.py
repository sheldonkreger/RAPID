import re
from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from core.utilities import time_jump
from core.utilities import check_ip_valid
from .models import IpMonitor

User = get_user_model()


class SubmissionForm(forms.Form):

    ips = forms.CharField(label='IP Submission', widget=forms.TextInput())

    def clean_ips(self):
        submission = self.cleaned_data.get('ips')
        ip_list = re.split(r'[,;|\n ]+', submission)
        validated_submissions = []

        for ip in ip_list:

            ip = ip.lower()

            if check_ip_valid(ip):
                validated_submissions.append(ip)

        return validated_submissions

    def save_submission(self, request):

        ips = self.cleaned_data.get('ips')
        current_user = User.objects.get(email__exact=request.user)

        for ip in ips:

            try:
                IpMonitor.objects.get(ip_address__exact=ip)

            except ObjectDoesNotExist:
                lookup_time = time_jump(minutes=1)
                new_monitor = IpMonitor(ip_address=ip,
                                        lookup_interval='24',
                                        next_lookup=lookup_time)
                new_monitor.save()

            if ip not in current_user.ip_list:
                current_user.ip_list.append(ip)
                current_user.save()