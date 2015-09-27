import csv

import datetime
from django.views.generic import TemplateView, ListView, FormView, View
from django.shortcuts import get_object_or_404, render
from django.http import HttpResponse
from django.shortcuts import redirect
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model

from core.utilities import discover_type

from .models import DomainMonitor, IpMonitor, IndicatorAlert, IndicatorTag
from .forms import MonitorSubmission

from braces.views import LoginRequiredMixin

User = get_user_model()


class MonitorDashboard(LoginRequiredMixin, TemplateView):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = "monitors/dashboard.html"


class DomainList(LoginRequiredMixin, ListView):

    login_url = "login"
    redirect_unauthenticated_users = True

    context_object_name = 'monitored_domains'
    template_name = 'monitors/domain.html'

    def get_queryset(self):
        domains = DomainMonitor.objects.filter(owner=self.request.user)
        return domains


class IpList(LoginRequiredMixin, ListView):

    login_url = "login"
    redirect_unauthenticated_users = True

    context_object_name = 'monitored_ips'
    template_name = 'monitors/ip.html'

    def get_queryset(self):
        ips = IpMonitor.objects.filter(owner=self.request.user)
        return ips


class AlertList(LoginRequiredMixin, ListView):
    login_url = "login"
    redirect_unauthenticated_users = True

    context_object_name = 'alerts'
    template_name = 'monitors/alerts.html'

    def get_queryset(self):
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(days=-7)
        alerts = IndicatorAlert.objects.filter(recipient=self.request.user,
                                               created__gte=time_frame)
        return alerts


class AddIndicator(LoginRequiredMixin, FormView):

    login_url = "login"
    redirect_unauthenticated_users = True

    form_class = MonitorSubmission
    template_name = "monitors/add.html"

    msg_success = "Indicators added for monitoring"
    msg_failure = "No indicators added for monitoring"

    def get_success_url(self):
        return reverse('monitor_dashboard')

    def form_valid(self, form):
        form.save_submission(self.request)
        messages.add_message(self.request, messages.SUCCESS, self.msg_success)
        return super(AddIndicator, self).form_valid(form)

    def form_invalid(self, form):
        messages.add_message(self.request, messages.WARNING, self.msg_failure)
        return redirect('monitor_dashboard')


class DeleteIndicator(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True
    template_name = "monitors/remove.html"

    msg_success = "Selected indicators removed from monitoring"

    def post(self, request):

        for indicator in request.POST.getlist('choices'):

            indicator_type = discover_type(indicator)

            if indicator_type == "domain":

                try:
                    DomainMonitor.objects.get(domain_name=indicator,
                                              owner=request.user).delete()
                except:
                    pass

            if indicator_type == "ip":

                try:
                    IpMonitor.objects.get(ip_address=indicator,
                                          owner=request.user).delete()
                except:
                    pass

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_dashboard')

    def get(self, request):
        return render(request, self.template_name, {})


class TagIndicator(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True
    template_name = "monitors/tagging.html"

    msg_success = "Selected indicators tagged"

    def post(self, request):

        tags = IndicatorTag.objects.filter(tag__in=request.POST.getlist('tags'),
                                           owner=request.user)

        if tags:

            for indicator in request.POST.getlist('choices'):

                indicator_type = discover_type(indicator)

                if indicator_type == "domain":

                    try:
                        monitor = DomainMonitor.objects.get(domain_name=indicator,
                                                            owner=request.user)
                    except:
                        pass

                    else:

                        for tag in tags:
                            monitor.tags.add(tag)

                if indicator_type == "ip":

                    try:
                        monitor = IpMonitor.objects.get(ip_address=indicator,
                                                        owner=request.user)
                    except:
                        pass

                    else:

                        for tag in tags:
                            monitor.tags.add(tag)

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_dashboard')

    def get(self, request):

        temp_context = dict()
        temp_context['tags'] = IndicatorTag.objects.filter(owner=request.user)
        return render(request, self.template_name, temp_context)


class UntagIndicator(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True
    template_name = "monitors/untag.html"

    msg_success = "Tags removed from selected indicators"

    def post(self, request):

        for indicator in request.POST.getlist('choices'):

            indicator_type = discover_type(indicator)

            if indicator_type == "domain":

                try:
                    monitor = DomainMonitor.objects.get(domain_name=indicator,
                                                        owner=request.user)
                except:
                    pass

                else:
                    monitor.tags.clear()

            if indicator_type == "ip":

                try:
                    monitor = IpMonitor.objects.get(ip_address=indicator,
                                                    owner=request.user)
                except:
                    pass

                else:
                    monitor.tags.clear()

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_dashboard')

    def get(self, request):
        return render(request, self.template_name, {})


@login_required(login_url='login')
def export_indicators(request):

    filtering = request.GET.get('filter', '')

    # Create the HttpResponse object with the appropriate CSV header.
    response = HttpResponse(content_type='text/csv')

    # Compile list of domains and ip addresses monitored by requesting user
    if filtering == "domain":
        response['Content-Disposition'] = 'attachment; filename="monitored_domains.csv"'
        domain_list = DomainMonitor.objects.filter(owner=request.user)
        ip_list = []

    elif filtering == "ip":
        response['Content-Disposition'] = 'attachment; filename="monitored_ips.csv"'
        ip_list = IpMonitor.objects.filter(owner=request.user)
        domain_list = []

    else:
        response['Content-Disposition'] = 'attachment; filename="monitored_indicators.csv"'
        domain_list = DomainMonitor.objects.filter(owner=request.user)
        ip_list = IpMonitor.objects.filter(owner=request.user)

    # Begin Writing to CSV object - Set Column Headings
    writer = csv.writer(response)
    writer.writerow(['Indicator', 'Last Lookup', 'Last Hosts', 'tags'])

    for monitor in domain_list:

        monitor_tags = [item["tag"] for item in monitor.tags.all().values("tag")]

        record = [monitor.domain_name, monitor.modified,
                  monitor.last_hosts, monitor_tags]

        writer.writerow(record)

    for monitor in ip_list:

        monitor_tags = [item["tag"] for item in monitor.tags.all().values("tag")]

        record = [monitor.ip_address, monitor.modified,
                  monitor.last_hosts, monitor_tags]

        writer.writerow(record)

    return response


class AddTag(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = "monitors/tagging.html"

    def post(self, request):

        new_tags = request.POST.getlist('new_tag')

        for new_tag in new_tags:

            if new_tag:

                try:
                    new_tag = IndicatorTag(tag=new_tag, owner=request.user)
                    new_tag.save()
                except:
                    pass

        temp_context = dict()
        temp_context['tags'] = IndicatorTag.objects.filter(owner=request.user)

        return render(request, self.template_name, temp_context)


class DeleteTags(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    msg_success = "Selected tags deleted"

    def post(self, request):

        IndicatorTag.objects.filter(tag__in=request.POST.getlist('tags'),
                                    owner=request.user).delete()

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_dashboard')