from django.conf.urls import patterns, url
from .views import HomePage, PrimaryNavigation
from . import views


urlpatterns = patterns('',
    url(r'^$', PrimaryNavigation.as_view(), name="menu"),
    url(r'^google/(?P<url>[^&]*)', views.google, name='url'),
)