from init_app import db
from src.models.books_md import Books
from src.utils import *


class Bookmark(db.Model):
    username = db.Column(db.String, primary_key=True)
    book_id = db.Column(db.Integer, primary_key=True)
    bm_name = db.Column(db.String, primary_key=True)
    line_position = db.Column(db.Integer)
    content = db.Column(db.String)

    def __init__(self, username):
        self.username = username
        self.book_id = None
        self.bm_name = None
        self.line_position = 0

    def get_json(self):
        result = {
            'username': self.username,
            'book_id': self.book_id,
            'bm_name': self.bm_name
        }
        if self.bm_name == "bookmark":
            result.update({'line_position': self.line_position})
        else:
            result.update({'content': self.content})

        return result

    def update_book_id(self, book_id):
        try:
            book = Books.query.filter_by(book_id=book_id)
            if book is not None:
                self.book_id = book_id
            return True
        except:
            return False

    def update_bm_name(self, new_bm_name):
        if self.bm_name != new_bm_name and is_valid_name(new_bm_name):
            self.bm_name = new_bm_name
            return True
        return False

    def update_line_pos(self, new_line_pos):
        if self.line_position != new_line_pos and isinstance(new_line_pos, int):
            self.line_position = new_line_pos
            return True
        return False

    def update_content(self, new_content):
        if self.content != new_content and is_valid_text(new_content):
            self.content = new_content
            return True
        return False
