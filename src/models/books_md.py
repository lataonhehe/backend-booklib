from init_app import db
from src.models.authors_books_md import BooksAuthors
from src.models.authors_md import Authors
from src.models.genres_md import Genres
from src.utils import *


class Books(db.Model):
    book_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(70))
    translator = db.Column(db.String(70))
    cover = db.Column(db.String)
    page_count = db.Column(db.Integer)
    public_year = db.Column(db.Integer)
    content = db.Column(db.String)
    descript = db.Column(db.String)
    republish_count = db.Column(db.Integer)
    current_rating = db.Column(db.Float)
    rating_count = db.Column(db.Integer)

    def __init__(self):
        self.current_rating = 0
        self.rating_count = 0
        # self.cover = None
        # self.page_count = None
        # self.public_year = None
        # self.content = None
        # self.descript = None
        # self.republish_count = None
        # self.current_rating = None

    def get_authors_list(self):
        authors = []

        books_authors = BooksAuthors.query.filter_by(
            book_id=self.book_id)

        for book_author in books_authors:
            author = Authors.query.filter_by(
                author_id=book_author.author_id).first()
            authors.append({book_author.author_id: author.author_name})

        return authors

    def get_summary_json(self):
        genre_query = Genres.query.filter_by(book_id=self.book_id)
        genres = []
        for book_genre in genre_query:
            genres.append(book_genre.genre)

        authors = self.get_authors_list()

        return {
            'book_id': self.book_id,
            'title': self.title,
            'authors': authors,
            'current_rating': self.current_rating,
            'genre': genres,
            'cover': self.cover,
            'page_count': self.page_count,
            'year': self.public_year
        }

    def get_detail_json(self):
        genre_query = Genres.query.filter_by(book_id=self.book_id)
        genres = []
        for book_genre in genre_query:
            genres.append(book_genre.genre)

        authors = self.get_authors_list()

        return {
            'book_id': self.book_id,
            'title': self.title,
            'authors': authors,
            'genre': genres,
            'translator': self.translator,
            'page_count': self.page_count,
            'public_year': self.public_year,
            'republish_count': self.republish_count,
            'descript': self.descript,
            'content': self.content,
            'cover': self.cover
        }

    def update_title(self, new_title):
        if self.title != new_title and is_valid_name(new_title):
            self.title = new_title
            return True
        return False

    def update_translator(self, new_translator):
        if self.translator != new_translator and is_valid_name(new_translator):
            self.translator = new_translator
            return True
        return False

    def update_cover(self, new_cover):
        if self.cover != new_cover and is_url_image(new_cover):
            self.cover = new_cover
            return True
        return False

    def update_page_count(self, new_page_count):
        if self.page_count != new_page_count and isinstance(new_page_count, int):
            self.page_count = new_page_count
            return True
        return False

    def update_public_year(self, new_public_year):
        if self.public_year != new_public_year and isinstance(new_public_year, int):
            self.public_year = new_public_year
            return True
        return False

    def update_content(self, new_content):
        if self.content != new_content and is_valid_text(new_content):
            self.content = new_content
            return True
        return False

    def update_descript(self, new_descript):
        if self.descript != new_descript and is_valid_text(new_descript):
            self.descript = new_descript
            return True
        return False

    def update_republish_count(self, new_republish_count):
        if self.republish_count != new_republish_count and isinstance(new_republish_count, int):
            self.republish_count = new_republish_count
            return True
        return False

    def is_valid_book(self, title, page_count, public_year, content, descript):
        if self.update_title(title) and self.update_page_count(page_count) and self.update_public_year(public_year) and self.update_content(content) and self.update_descript(descript):
            return True
        return False
