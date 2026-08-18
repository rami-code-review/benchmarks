"""Web framework fixtures for benchmark injection."""

from django.db import connection
from django.shortcuts import render
from fastapi import FastAPI

from .database import db
from .models import Author, User

app = FastAPI()


def get_authors_with_books(request):
    authors = Author.objects.prefetch_related('books').all()
    return render(request, 'authors.html', {'authors': authors})


def find_users_by_email(email: str):
    users = User.objects.filter(email=email)
    return list(users)


def search_products(search: str):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM products WHERE name LIKE %s", [f"%{search}%"])
        return cursor.fetchall()


def search_products_paged(search: str):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM products WHERE name LIKE %s",
            [f"%{search}%"]
        )
        return cursor.fetchall()


@app.get("/users/{user_id}")
async def get_user(user_id: int):
    user = await db.fetch_one("SELECT * FROM users WHERE id = $1", user_id)
    return user


@app.get("/health")
async def health():
    return {"status": "ok"}
