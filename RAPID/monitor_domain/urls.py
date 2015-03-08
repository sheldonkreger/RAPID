from django.conf.urls import patterns, url

from .views import DomainMonitorPanel, DomainMonitorAddition
from .views import DomainMonitorDeletion, export_monitor


urlpatterns = patterns('',
    url(r'^$', DomainMonitorPanel.as_view(), name='monitor_domain'),
    url(r'^add_monitor', DomainMonitorAddition.as_view(), name='monitor_domain_add'),
    url(r'^del_monitor', DomainMonitorDeletion.as_view(), name='monitor_domain_del'),
    url(r'^exp_monitor', export_monitor, name='monitor_domain_exp'),
)