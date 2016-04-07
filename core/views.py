from django.views.generic.base import View
from django.core.urlresolvers import reverse
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from core.lookups import lookup_google_safe_browsing

class HomePage(View):  # RedirectView

    def get(self, request):
        return redirect(reverse('login'))


class PrimaryNavigation(View):  # TemplateView
    
    template_name = 'monitors/dashboard.html'

    @method_decorator(login_required(login_url='login'))
    def get(self, request):

        return render(request, self.template_name)


def google(request, url):
    response = lookup_google_safe_browsing(url)
    return HttpResponse("hit google lookup with url: " + url)
