"""Artifact staging lifecycle."""


class CollectError(Exception):
    pass


def make_stagedir(build_id):
    return f"/tmp/stage-{build_id}"


def remove_stagedir(path):
    pass


def collect_artifacts(path):
    pass


def stage_artifacts(build_id):
    path = make_stagedir(build_id)
    try:
        collect_artifacts(path)
    except CollectError:
        remove_stagedir(path)
        raise
    return path
