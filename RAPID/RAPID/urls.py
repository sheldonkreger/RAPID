from django.conf.urls import patterns, include, url
from django.contrib import admin
import core.urls
import profiles.urls
import pivoteer.urls
import monitor_domain.urls
import monitor_ip.urls


urlpatterns = patterns('',
    url(r'^$', core.views.HomePage.as_view(), name="home"),
    url(r'^navigation/', include(core.urls)),
    url(r'^profile/', include(profiles.urls)),
    url(r'^pivoteer/', include(pivoteer.urls)),
    url(r'^monitor_domain/', include(monitor_domain.urls)),
    url(r'^monitor_ip/', include(monitor_ip.urls)),
    url(r'^admin/', include(admin.site.urls)),
)