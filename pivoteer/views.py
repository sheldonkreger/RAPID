import csv
import json
import datetime

from django.http import HttpResponse
from django.shortcuts import render
from django.views.generic.base import View
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

from .forms import SubmissionForm
from .models import IndicatorRecord, TaskTracker
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
        if record_type == "Recent":

            self.template_name = "pivoteer/RecentRecords.html"

            # Current hosting records
            host_record = IndicatorRecord.objects.recent_hosts(indicator)
            self.template_vars["current_hosts"] = host_record

            # Current WHOIS record
            whois_record = IndicatorRecord.objects.recent_whois(indicator)
            self.template_vars["current_whois"] = whois_record

        elif record_type == "Historical":

            self.template_name = "pivoteer/HistoricalRecords.html"

            # Historical hosting records
            host_records = IndicatorRecord.objects.historical_hosts(indicator, request)
            self.template_vars["hosting_records"] = host_records

            # Historical WHOIS records
            whois_record = IndicatorRecord.objects.historical_whois(indicator)
            self.template_vars["historical_whois"] = whois_record

        elif record_type == "Malware":

            self.template_name = "pivoteer/MalwareRecords.html"

            malware_records = IndicatorRecord.objects.malware_records(indicator)
            self.template_vars["malware_records"] = malware_records

        self.template_vars["origin"] = indicator
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
            self.export_recent(indicator)
            self.export_historical(indicator, request)
            self.export_malware(indicator, request)

        elif indicator and export == 'recent':
            self.export_recent(indicator)

        elif indicator and export == 'historical':
            self.export_historical(indicator, request)

        elif indicator and export == 'malware':
            self.export_malware(indicator, request)

        return self.response

    def export_recent(self, indicator):

        hosts = IndicatorRecord.objects.recent_hosts(indicator)
        whois = IndicatorRecord.objects.recent_whois(indicator)
        malware = IndicatorRecord.objects.recent_malware(indicator)

        for host in hosts:
            try:
                entry = [host.info_date, host.info_source,
                         host.info['ip'], host.info['domain'],
                         host.info['geo_location']['city'],
                         host.info['geo_location']['province'],
                         host.info['geo_location']['country']]

                self.writer.writerow(entry)

            except:
                pass

        for record in malware:
            entry = [record.info_date, record.info_source, record.info['C2'], record.info['md5'],
                     record.info['sha1'], record.info['sha256'], record.info['link']]

            self.writer.writerow(entry)

        self.line_separator()
        self.writer.writerow([whois.info])
        self.line_separator()

    def export_historical(self, indicator, request):

        hosts = IndicatorRecord.objects.historical_hosts(indicator, request)
        whois = IndicatorRecord.objects.historical_whois(indicator)
        malware = IndicatorRecord.objects.historical_malware(indicator)

        for host in hosts:
            try:
                entry = [host.info_date, host.info_source,
                         host.info['ip'], host.info['domain'],
                         host.info['geo_location']['city'],
                         host.info['geo_location']['province'],
                         host.info['geo_location']['country']]

                self.writer.writerow(entry)

            except:
                pass

        for record in malware:
            entry = [record.info_date, record.info_source, record.info['C2'], record.info['md5'],
                     record.info['sha1'], record.info['sha256'], record.info['link']]

            self.writer.writerow(entry)

        for record in whois:
            self.line_separator()
            self.writer.writerow([record.info])

        self.line_separator()

    def export_malware(self, indicator, request):
        pass

    def line_separator(self):
        self.writer.writerow([])
