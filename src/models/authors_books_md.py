from init_app import db
from src.utils import is_valid_id


class BooksAuthors(db.Model):
    author_id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, primary_key=True)

    def __init__(self):
        self.author_id = None
        self.book_id = None

    @staticmethod
    def add_authors(book_id, author_ids):
        if not isinstance(author_ids, list):
            return False

        for author_id in author_ids:
            if not is_valid_id(author_id):
                return False
            new = BooksAuthors()
            new.author_id = author_id
            new.book_id = book_id
            db.session.add(new)

        db.session.commit()
        return True

    @staticmethod
    def update_authors(book_id, author_ids):
        if not isinstance(author_ids, list):
            return False

        books_authors = BooksAuthors.query.filter_by(book_id=book_id)
        current_authors = []
        for book_author in books_authors:
            current_authors.append(book_author.author_id)
            db.session.delete(book_author)

        current_authors.sort()
        author_ids.sort()
        if current_authors == author_ids:
            return False

        return BooksAuthors.add_authors(book_id, author_ids)
