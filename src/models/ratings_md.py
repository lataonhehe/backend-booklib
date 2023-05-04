from init_app import db
from src.const import *
from src.utils import is_valid_text
from src.models.books_md import Books


class Ratings(db.Model):
    username = db.Column(db.String(20), primary_key=True)
    book_id = db.Column(db.Integer, primary_key=True)
    stars = db.Column(db.Integer)
    content = db.Column(db.String)

    def __init__(self, username):
        self.username = username
        self.book_id = None
        self.stars = None
        self.content = None

    def get_json(self):
        return {
            'username': self.username,
            'book_id': self.book_id,
            'stars': self.stars,
            'content': self.content,
        }

    def update_book_id(self, book_id):
        try:
            book = Books.query.filter_by(book_id=book_id)
            if book is not None:
                self.book_id = book_id
            return True
        except:
            return False

    def update_stars(self, new_stars):
        if self.stars != new_stars and isinstance(new_stars, int) and new_stars >= 1 and new_stars <= 5:
            self.stars = new_stars
            return True
        return False

    def update_content(self, new_content):
        if self.content != new_content and is_valid_text(new_content):
            self.content = new_content
            return True
        return False
