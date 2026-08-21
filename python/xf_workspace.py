"""Build workspace lifecycle."""


class FetchError(Exception):
    pass


def make_workdir(build_id):
    return f"/tmp/build-{build_id}"


def remove_workdir(path):
    pass


def fetch_sources(path):
    pass


def checkout_workspace(build_id):
    path = make_workdir(build_id)
    try:
        fetch_sources(path)
    except FetchError:
        remove_workdir(path)
        raise
    return path
