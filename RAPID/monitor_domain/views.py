import csv

from django.views.generic import ListView, FormView, View
from django.http import HttpResponse
from django.shortcuts import redirect
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model

from core.utilities import time_jump
from .models import DomainMonitor, DomainAlert
from .forms import SubmissionForm

from braces.views import LoginRequiredMixin

User = get_user_model()


class DomainMonitorPanel(LoginRequiredMixin, ListView):

    login_url = "login"
    redirect_unauthenticated_users = True

    context_object_name = 'monitors'
    template_name = 'monitors/domain.html'

    def get_queryset(self):
        listing = User.objects.get(email__exact=self.request.user).domain_list
        monitors = DomainMonitor.objects.filter(domain_name__in=listing)
        return monitors

    def get_context_data(self, **kwargs):
        listing = User.objects.get(email__exact=self.request.user).domain_list
        context = super(DomainMonitorPanel, self).get_context_data(**kwargs)
        context['alerts'] = DomainAlert.objects.filter(alert_time__gte=time_jump(hours=-72),
                                                       domain_name__in=listing)

        context['form'] = DomainMonitorAddition.form_class

        return context


class DomainMonitorAddition(LoginRequiredMixin, FormView):

    login_url = "login"
    redirect_unauthenticated_users = True

    form_class = SubmissionForm
    msg_success = "Domains added to monitoring"
    msg_failure = "Unable to add domains for monitoring"

    def get_success_url(self):
        return reverse('monitor_domain')

    def form_valid(self, form):
        form.save_submission(self.request)
        messages.add_message(self.request, messages.SUCCESS, self.msg_success)
        return super(DomainMonitorAddition, self).form_valid(form)

    def form_invalid(self, form):
        messages.add_message(self.request, messages.WARNING, self.msg_failure)
        return redirect('monitor_domain')


class DomainMonitorDeletion(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    msg_success = "Selected domains removed from monitoring"

    def post(self, request):

        for domain in request.POST.getlist('choices'):
            User.objects.delete_domain_monitor(request.user, domain)

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_domain')


@login_required(login_url='login')
def export_monitor(request):

    # Create the HttpResponse object with the appropriate CSV header.
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="monitored_domains.csv"'

    # Compile list of domains monitored by requesting user
    domain_list = User.objects.get(email__exact=request.user).domain_list
    monitoring = DomainMonitor.objects.filter(domain_name__in=domain_list)

    # Begin Writing to CSV object - Set Column Headings
    writer = csv.writer(response)
    writer.writerow(['Domain Name', 'Last Lookup', 'Last Hosts'])

    for monitor in monitoring:
        record = [monitor.domain_name, monitor.last_lookup, monitor.last_hosts]
        writer.writerow(record)

    return response