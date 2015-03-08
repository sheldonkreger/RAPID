import csv
import json
import datetime

from django.http import HttpResponse
from django.shortcuts import render
from django.views.generic.base import View
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

from .forms import SubmissionForm
from .models import HostRecord, WhoisRecord, MalwareRecord
from .models import SearchEngineHits, TaskTracker
from core.utilities import time_jump

from celery.result import GroupResult
from braces.views import LoginRequiredMixin


class PivotManager(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = 'pivoteer/pivoteer.html'

    def __init__(self):
        self.template_vars = {'SubmissionForm': SubmissionForm}

    def get(self, request):
        return render(request, self.template_name, self.template_vars)

    def post(self, request):

        task_tracking = {}
        submitted_form = SubmissionForm(request.POST)
        current_time = datetime.datetime.utcnow()
        desired_time = time_jump(hours=-24)

        if submitted_form.is_valid():
            recent_tasks = submitted_form.check_recent_tasks(desired_time)

            # If a recent task exists, use that one instead
            if recent_tasks:
                task_tracking['id'] = recent_tasks.group_id
            else:
                new_task = submitted_form.create_new_task(current_time)

                if new_task:
                    task_tracking['id'] = new_task.id
                else:
                    task_tracking["errors"] = "Unexpected Failure"

        else:  # pass form errors back to user from async request
            task_tracking["errors"] = submitted_form.errors

        json_response = json.dumps(task_tracking)
        return HttpResponse(json_response, content_type="application/json")


# Check if task completed
# https://zapier.com/blog/async-celery-example-why-and-how/
class CheckTask(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = "pivoteer/UnknownRecords.html"

    def __init__(self):
        self.template_vars = {}

    def post(self, request):

        desired_time = time_jump(hours=-24)

        task = request.POST['task_id']
        res = GroupResult.restore(task)

        if res and not res.ready():
            return HttpResponse(json.dumps({"status": "loading"}), content_type="application/json")

        # Task completion allows for origin information to be pulled
        try:
            task_origin = TaskTracker.objects.get(group_id=task)
            record_type = task_origin.type
            indicator = task_origin.keyword

        except MultipleObjectsReturned:
            task_origin = TaskTracker.objects.filter(group_id=task).latest('date')
            record_type = task_origin.type
            indicator = task_origin.keyword

        except ObjectDoesNotExist:
            record_type = None
            indicator = None

        # Pull data according to the record type
        if record_type == "current":
            # Collect whois record for current records
            whois_record = WhoisRecord.objects.recent_record(indicator)
            self.template_vars["whois_record"] = whois_record

            # Collect host records for current records
            host_record = HostRecord.objects.current_hosts(indicator, desired_time)
            self.template_vars["host_record"] = host_record
            self.template_name = "pivoteer/CurrentRecords.html"

        elif record_type == "passive":
            host_records = HostRecord.objects.passive_records(indicator, request)
            self.template_vars["passive_records"] = host_records
            self.template_name = "pivoteer/PassiveRecords.html"

        elif record_type == "malware":
            malware_records = MalwareRecord.objects.malware_records(indicator)
            self.template_vars["malware_records"] = malware_records
            self.template_name = "pivoteer/MalwareRecords.html"

        elif record_type == "other":
            google_search = SearchEngineHits.objects.recent_record(indicator)
            self.template_vars["google_search"] = google_search
            self.template_name = "pivoteer/OtherRecords.html"

        return render(request, self.template_name, self.template_vars)


class ExportRecords(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    def __init__(self):

        # Create the HttpResponse object with the appropriate CSV header.
        self.response = HttpResponse(content_type='text/csv')
        self.response['Content-Disposition'] = 'attachment; filename="exported_records.csv"'
        self.writer = csv.writer(self.response)

    def post(self, request):
        indicator = request.POST['indicator']
        export = request.POST['export']

        if indicator and export == 'all':
            self.export_current(indicator)
            self.export_passive(indicator)
            self.export_malware(indicator)
            self.export_other(indicator)

        elif indicator and export == 'current':
            self.export_current(indicator)
        elif indicator and export == 'passive':
            self.export_passive(indicator, request)
        elif indicator and export == 'malware':
            self.export_malware(indicator)
        elif indicator and export == 'other':
            self.export_other(indicator)

        return self.response

    def export_current(self, indicator):

        desired_time = time_jump(hours=-24)
        hosts = HostRecord.objects.current_hosts(indicator, desired_time)
        self.writer.writerow(['Resolution Date', 'Domain', 'IP Address', 'Source'])

        for host in hosts:
            record = [host.resolution_date, host.domain_name, host.ip_address, host.resolution_source]
            self.writer.writerow(record)

        self.line_separator()

        whois = WhoisRecord.objects.recent_record(indicator)
        self.writer.writerow(['Whois Record'])
        self.writer.writerow([whois])
        self.line_separator()

    def export_passive(self, indicator, request):

        passive = HostRecord.objects.passive_records(indicator, request)
        self.writer.writerow(['Resolution Date', 'Domain', 'IP Address', 'Source'])

        for record in passive:
            entry = [record.resolution_date, record.domain_name, record.ip_address, record.resolution_source]
            self.writer.writerow(entry)

        self.line_separator()

    def export_malware(self, indicator):

        malware = MalwareRecord.objects.malware_records(indicator)
        self.writer.writerow(['Submission Date', 'SHA256', 'MD5', 'Source', 'Report Link'])

        for record in malware:
            entry = [record.submission_date, record.SHA256_value, record.MD5_value,
                     record.report_source, record.report_link]
            self.writer.writerow(entry)

        self.line_separator()

    def export_other(self, indicator):

        google = SearchEngineHits.objects.recent_record(indicator)
        self.writer.writerow([google.result_count])
        self.writer.writerow(['Title', 'Description', 'Link'])

        for entry in google.results:
            self.writer.writerow(entry)
        self.line_separator()

    def line_separator(self):
        self.writer.writerow([])