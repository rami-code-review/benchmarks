"""Structural design fixtures for benchmark injection."""


# models.py
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from services import UserService

class User:
    def get_service(self) -> "UserService":
        from services import UserService
        return UserService(self)


class UserService:
    def __init__(self, repo):
        self.repo = repo

    def get_user(self, id): ...
    def create_user(self, data): ...

class EmailService:
    def __init__(self, client):
        self.client = client

    def send_email(self, to, subject, body): ...


class Animal:
    def __init__(self, locomotion, sound_maker):
        self.locomotion = locomotion
        self.sound_maker = sound_maker

    def move(self):
        self.locomotion.move()

    def make_sound(self):
        self.sound_maker.make_sound()


class Walking:
    def move(self):
        ...


class Barking:
    def make_sound(self):
        ...
