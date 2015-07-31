import re
from django import forms
from django.contrib.auth import get_user_model
from core.utilities import time_jump
from core.utilities import discover_type
from .models import DomainMonitor, IpMonitor

User = get_user_model()


class MonitorSubmission(forms.Form):
    indicators = forms.CharField(label='Indicator Submission', widget=forms.TextInput())

    def __init__(self, *args, **kwargs):
        super(MonitorSubmission, self).__init__(*args, **kwargs)
        self.valid_domains = []
        self.valid_ips = []

    def clean_indicators(self):
        submission = self.cleaned_data.get('indicators')
        indicator_list = re.split(r'[,;|\n\r ]+', submission)

        for indicator in indicator_list:

            indicator = indicator.rstrip().lower()
            indicator_type = discover_type(indicator)

            if indicator_type == "domain":
                self.valid_domains.append(indicator)

            if indicator_type == "ip":
                self.valid_ips.append(indicator)

    def save_submission(self, request):

        current_user = User.objects.get(email__exact=request.user)
        lookup_time = time_jump(minutes=2)
        set_interval = 24

        for domain in self.valid_domains:

            try:
                new_monitor = DomainMonitor(owner=current_user,
                                            domain_name=domain,
                                            lookup_interval=set_interval,
                                            next_lookup=lookup_time)
                new_monitor.save()

            except:
                pass

        for ip_address in self.valid_ips:

            try:
                new_monitor = IpMonitor(owner=current_user,
                                        ip_address=ip_address,
                                        lookup_interval=set_interval,
                                        next_lookup=lookup_time)
                new_monitor.save()

            except:
                pass