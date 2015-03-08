from django.conf.urls import patterns, url
from .views import IpMonitorPanel, IpMonitorAddition
from .views import IpMonitorDeletion, export_monitor


urlpatterns = patterns('',
    url(r'^$', IpMonitorPanel.as_view(), name='monitor_ip'),
    url(r'^add_monitor', IpMonitorAddition.as_view(), name='monitor_ip_add'),
    url(r'^del_monitor', IpMonitorDeletion.as_view(), name='monitor_ip_del'),
    url(r'^export_monitor', export_monitor, name='monitor_ip_exp'),
)