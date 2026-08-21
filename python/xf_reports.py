"""Report storage consumed by summaries."""


class Report:
    def __init__(self, pages=0):
        self.pages = pages


_reports = {}


def find_report(report_id):
    report = _reports.get(report_id)
    if report is None:
        return Report(pages=0)
    return report
