import datetime

from celery.schedules import crontab
from celery.task import PeriodicTask
from django.contrib.auth import get_user_model

from .models import DomainMonitor, IpMonitor, IndicatorAlert
from pivoteer.models import IndicatorRecord
from pivoteer.collectors.scrape import RobtexScraper
from core.lookups import resolve_domain, geolocate_ip
from core.tasks import deliver_email

User = get_user_model()


class IndicatorMonitoring(PeriodicTask):
    run_every = crontab()

    def run(self, **kwargs):
        start_timestamp = datetime.datetime.utcnow()
        minute_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M')

        current_time = datetime.datetime.strptime(minute_timestamp, '%Y-%m-%d %H:%M')
        desired_time = current_time + datetime.timedelta(minutes=1)

        # Check for overdue domain monitors
        overdue_domains = DomainMonitor.objects.filter(next_lookup__lt=current_time)

        for overdue_domain in overdue_domains:
            overdue_domain.next_lookup = current_time + datetime.timedelta(minutes=5)
            overdue_domain.save()

        # Check for overdue IP address monitors
        overdue_ips = IpMonitor.objects.filter(next_lookup__lt=current_time)

        for overdue_ip in overdue_ips:
            overdue_ip.next_lookup = current_time + datetime.timedelta(minutes=5)
            overdue_ip.save()

        # Compile list of domains to resolve based on lookup time
        domain_lookups = DomainMonitor.objects.filter(next_lookup__gte=current_time,
                                                      next_lookup__lte=desired_time)

        # Compile list of IP addresses to resolve based on lookup time
        ip_lookups = IpMonitor.objects.filter(next_lookup__gte=current_time,
                                              next_lookup__lte=desired_time)

        # Lookup domain resolutions
        for domain_lookup in domain_lookups:
            owner = domain_lookup.owner
            last_hosts = domain_lookup.last_hosts
            domain_resolutions = resolve_domain(domain_lookup.domain_name)

            if type(domain_resolutions) == list:
                for host in domain_resolutions:

                    ip_location = geolocate_ip(host)

                    try:
                        record_entry = IndicatorRecord(record_type="HR",
                                                       info_source="DNS",
                                                       info_date=current_time,
                                                       info={"geo_location": ip_location,
                                                             "ip": host, "domain": domain_lookup.domain_name})
                        record_entry.save()
                    except:
                        pass

                if domain_resolutions and last_hosts:
                    # Check for new or missing hosts since last lookup
                    missing_hosts = list(set(last_hosts).difference(domain_resolutions))
                    new_hosts = list(set(domain_resolutions).difference(last_hosts))

                    # Sanitize domain name for safe email content
                    sanitized_domain = domain_lookup.domain_name.replace('.', '[.]')

                    email_recipient = [owner.email]

                    # Compose alert and email content for hosting changes
                    if missing_hosts and new_hosts:
                        sanitized_missing = [host.replace('.', '[.]') for host in missing_hosts]
                        sanitized_new = [host.replace('.', '[.]') for host in new_hosts]

                        alert_text = 'Removed hosts: %s' % ', '.join(missing_hosts)
                        self.create_alert(domain_lookup.domain_name, alert_text, owner)

                        alert_text = 'New hosts: %s' % ', '.join(new_hosts)
                        self.create_alert(domain_lookup.domain_name, alert_text, owner)

                        email_subject = 'IP Address Changes for ' + sanitized_domain
                        email_body = """ DNS lookup performed at %s indicates that the tracked
                                         domain %s has dropped the following IP addresses: %s
                                         and has added the following IP addresses: %s
                                     """ % (str(current_time), sanitized_domain,
                                            sanitized_missing, sanitized_new)

                        deliver_email.delay(email_subject, email_body, email_recipient)

                    elif missing_hosts:
                        sanitized_missing = [host.replace('.', '[.]') for host in missing_hosts]
                        alert_text = 'Removed hosts: %s' % ', '.join(missing_hosts)
                        self.create_alert(domain_lookup.domain_name, alert_text, owner)

                        email_subject = 'IP Address Drops for ' + sanitized_domain
                        email_body = """ DNS lookup performed at %s indicates that the tracked
                                         domain %s has dropped the following IP addresses: %s
                                     """ % (str(current_time), sanitized_domain, sanitized_missing)

                        deliver_email.delay(email_subject, email_body, email_recipient)

                    elif new_hosts:
                        sanitized_new = [host.replace('.', '[.]') for host in new_hosts]
                        alert_text = 'New hosts: %s' % ', '.join(new_hosts)
                        self.create_alert(domain_lookup.domain_name, alert_text, owner)

                        email_subject = 'IP Address Additions for ' + sanitized_domain
                        email_body = """ DNS lookup performed at %s indicates that the tracked
                                         domain %s has changed to the following IP addresses: %s
                                     """ % (str(current_time), sanitized_domain, sanitized_new)

                        deliver_email.delay(email_subject, email_body, email_recipient)
            else:
                alert_text = domain_resolutions
                self.create_alert(domain_lookup.domain_name, alert_text, owner)

            # Update entry information
            domain_lookup.last_hosts = domain_resolutions
            domain_lookup.next_lookup = current_time + datetime.timedelta(hours=domain_lookup.lookup_interval)
            domain_lookup.save()

        # Lookup IP address resolutions
        scraper = RobtexScraper()

        for ip_lookup in ip_lookups:
            owner = ip_lookup.owner
            last_hosts = ip_lookup.last_hosts
            ip_resolutions = scraper.run(ip_lookup.ip_address)
            ip_location = geolocate_ip(ip_lookup.ip_address)

            if type(ip_resolutions) == list:

                for host in ip_resolutions:
                    try:
                        record_entry = IndicatorRecord(record_type="HR",
                                                       info_source="REX",
                                                       info_date=current_time,
                                                       info={"geo_location": ip_location,
                                                             "ip": ip_lookup.ip_address, "domain": host})
                        record_entry.save()
                    except:
                        pass

                if ip_resolutions and last_hosts:
                    # Check for new or missing hosts since last lookup
                    missing_hosts = list(set(last_hosts).difference(ip_resolutions))
                    new_hosts = list(set(ip_resolutions).difference(last_hosts))

                    # Sanitize ip address for safe email content
                    sanitized_ip = ip_lookup.ip_address.replace('.', '[.]')

                    email_recipient = [owner.email]

                    # Compose alert and email content for hosting changes
                    if missing_hosts and new_hosts:
                        sanitized_missing = [host.replace('.', '[.]') for host in missing_hosts]
                        sanitized_new = [host.replace('.', '[.]') for host in new_hosts]

                        alert_text = 'Removed hosts: %s' % ', '.join(missing_hosts)
                        self.create_alert(ip_lookup.ip_address, alert_text, owner)

                        alert_text = 'New hosts: %s' % ', '.join(new_hosts)
                        self.create_alert(ip_lookup.ip_address, alert_text, owner)

                        email_subject = 'Domain Changes for ' + sanitized_ip
                        email_body = """ IP lookup performed at %s indicates that the tracked
                                         IP address %s has dropped the following domains: %s
                                         and has added the following domains: %s
                                     """ % (str(current_time), sanitized_ip,
                                            sanitized_missing, sanitized_new)

                        deliver_email.delay(email_subject, email_body, email_recipient)

                    elif missing_hosts:
                        sanitized_missing = [host.replace('.', '[.]') for host in missing_hosts]
                        alert_text = 'Removed hosts: %s' % ', '.join(missing_hosts)
                        self.create_alert(ip_lookup.ip_address, alert_text, owner)

                        email_subject = 'Domain Drops for ' + sanitized_ip
                        email_body = """ IP lookup performed at %s indicates that the tracked
                                         IP address %s has dropped the following domains: %s
                                     """ % (str(current_time), sanitized_ip, sanitized_missing)

                        deliver_email.delay(email_subject, email_body, email_recipient)

                    elif new_hosts:
                        sanitized_new = [host.replace('.', '[.]') for host in new_hosts]
                        alert_text = 'New hosts: %s' % ', '.join(new_hosts)
                        self.create_alert(ip_lookup.ip_address, alert_text, owner)

                        email_subject = 'Domain Additions for ' + sanitized_ip
                        email_body = """ IP lookup performed at %s indicates that the tracked
                                         IP address %s has added the following domains: %s
                                     """ % (str(current_time), sanitized_ip, sanitized_new)

                        deliver_email.delay(email_subject, email_body, email_recipient)
            else:
                alert_text = ip_resolutions
                self.create_alert(ip_lookup.ip_address, alert_text, owner)

            # Update entry information
            ip_lookup.last_hosts = ip_resolutions
            ip_lookup.next_lookup = current_time + datetime.timedelta(hours=ip_lookup.lookup_interval)
            ip_lookup.save()

    def create_alert(self, indicator, alert_text, owner):
        new_alert = IndicatorAlert(indicator=indicator, message=alert_text, recipient=owner)
        new_alert.save()
