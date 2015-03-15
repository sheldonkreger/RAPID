from django.contrib import admin

from .models import IpMonitor, IpAlert


class IpMonitorAdmin(admin.ModelAdmin):
    exclude = ('lookup_interval',)
    list_display = ('ip_address', 'last_hosts')


class IpAlertAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'alert_time', 'alert_text')

admin.site.register(IpMonitor, IpMonitorAdmin)
admin.site.register(IpAlert, IpAlertAdmin)
