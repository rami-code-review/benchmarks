"""Note storage consumed by the editor."""


class NoteMissing(Exception):
    def __init__(self, note_id):
        self.note_id = note_id


_notes = {}


def load_note(note_id):
    note = _notes.get(note_id)
    if note is None:
        raise NoteMissing(note_id)
    return note
