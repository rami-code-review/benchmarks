"""Job storage consumed by the queue."""


class JobMissing(Exception):
    def __init__(self, job_id):
        self.job_id = job_id


_jobs = {}


def load_job(job_id):
    job = _jobs.get(job_id)
    if job is None:
        raise JobMissing(job_id)
    return job
