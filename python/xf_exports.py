"""Export storage consumed by totals."""


class Export:
    def __init__(self, rows=0):
        self.rows = rows


_exports = {}


def find_export(export_id):
    export = _exports.get(export_id)
    if export is None:
        return Export(rows=0)
    return export
