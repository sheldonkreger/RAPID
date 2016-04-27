"""
Classes and functions for writing Threat Crowd records.

Threat Crowd Records are IndicatorRecords with a record type of "TR."
"""

from pivoteer.writer.core import CsvWriter


class ThreatCrowdCsvWriter(CsvWriter):
    """
    A CsvWriter implementation for writing Threat Crowd Records (i.e. IndicatorRecords with a record type of "TR").
    """

    def __init__(self, writer):
        """
        Create a new CsvWriter for Host Records using the given writer.

        :param writer: The writer
        """
        super(ThreatCrowdCsvWriter, self).__init__(writer)

    def create_title_rows(self, indicator, records):
        return [["ThreatCrowd Records"]]

    def create_header(self):
        return ["Type", "Data", "Date"]

    def create_rows(self, record):
        if record is None:
            return
        info = record["info"]
        if info is None:
            return

        yield ["Lookup Date", record["info_date"], None]
        info = record["info"]
        yield ["Permalink", info["permalink"], None]
        emails = info["emails"]
        yield ["Emails", ", ".join(emails), None]
        resolutions = info["resolutions"]
        if resolutions:
            for resolution in resolutions:
                ip = resolution["ip_address"]
                resolved = resolution["last_resolved"]
                yield ["Resolution", ip, resolved]
        subdomains = info["subdomains"]
        if subdomains:
            for subdomain in subdomains:
                yield ["Subdomain", subdomain, None]
        hashes = info["hashes"]
        if hashes:
            for h in hashes:
                yield ["Hash", h, None]
