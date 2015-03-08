import csv

from django.views.generic import ListView, FormView, View
from django.http import HttpResponse
from django.core.urlresolvers import reverse
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model

from core.utilities import time_jump
from .models import IpMonitor, IpAlert
from .forms import SubmissionForm

from braces.views import LoginRequiredMixin

User = get_user_model()


class IpMonitorPanel(LoginRequiredMixin, ListView):

    login_url = "login"
    redirect_unauthenticated_users = True

    context_object_name = 'monitors'
    template_name = 'monitors/ip.html'

    def get_queryset(self):
        listing = User.objects.get(email__exact=self.request.user).ip_list
        monitors = IpMonitor.objects.filter(ip_address__in=listing)
        return monitors

    def get_context_data(self, **kwargs):
        listing = User.objects.get(email__exact=self.request.user).ip_list
        context = super(IpMonitorPanel, self).get_context_data(**kwargs)
        context['alerts'] = IpAlert.objects.filter(alert_time__gte=time_jump(hours=-72),
                                                   ip_address__in=listing)

        context['form'] = IpMonitorAddition.form_class

        return context


class IpMonitorAddition(LoginRequiredMixin, FormView):

    login_url = "login"
    redirect_unauthenticated_users = True

    form_class = SubmissionForm
    msg_success = "IP addresses added to monitoring"
    msg_failure = "Unable to add IP addresses for monitoring"

    def get_success_url(self):
        return reverse('monitor_ip')

    def form_valid(self, form):
        form.save_submission(self.request)
        messages.add_message(self.request, messages.SUCCESS, self.msg_success)
        return super(IpMonitorAddition, self).form_valid(form)

    def form_invalid(self, form):
        messages.add_message(self.request, messages.WARNING, self.msg_failure)
        return redirect('monitor_ip')


class IpMonitorDeletion(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    msg_success = "Selected IP addresses removed from monitoring"

    def post(self, request):

        for ip in request.POST.getlist('choices'):
            User.objects.delete_ip_monitor(request.user, ip)

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_ip')


@login_required(login_url='login')
def export_monitor(request):

    # Create the HttpResponse object with the appropriate CSV header.
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="monitored_ips.csv"'

    # Compile list of IP addresses monitored by requesting user
    ip_list = User.objects.get(email__exact=request.user).ip_list
    monitoring = IpMonitor.objects.filter(ip_address__in=ip_list)

    # Begin Writing to CSV object - Set Column Headings
    writer = csv.writer(response)
    writer.writerow(['IP Address', 'Last Lookup', 'Last Hosts'])

    for monitor in monitoring:
        record = [monitor.ip_address, monitor.last_lookup, monitor.last_hosts]
        writer.writerow(record)

    return response