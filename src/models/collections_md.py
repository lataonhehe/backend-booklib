from init_app import db
from src.utils import *
from src.models.books_md import Books


class Collections(db.Model):
    username = db.Column(db.String(20), primary_key=True)
    coll_name = db.Column(db.String(50), primary_key=True)
    book_id = db.Column(db.Integer, primary_key=True)

    def __init__(self, username):
        self.username = username
        self.coll_name = None
        self.book_id = None

    @staticmethod
    def get_json(username, coll_name):
        '''
        Get JSON of a collection by the owner's username and its name
        '''
        collections_query = Collections.query.filter_by(
            username=username, coll_name=coll_name)
        books = []
        for collection in collections_query:
            book = Books.query.filter_by(book_id=collection.book_id).first()
            books.append(book.get_summary_json())

        return {
            'username': username,
            'coll_name': coll_name,
            'books': books,
        }

    @staticmethod
    def update_coll_name(username, coll_name, new_coll_name):
        if is_valid_name(new_coll_name, COLL_NAME_MAX_LENGTH):

            collections = Collections.query.filter_by(
                username=username, coll_name=coll_name)
            if collections.first().coll_name == new_coll_name:
                return False

            for collection in collections:
                collection.coll_name = new_coll_name
            return True

        return False
