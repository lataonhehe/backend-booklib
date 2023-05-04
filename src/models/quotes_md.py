from init_app import db
from src.models.authors_md import Authors
from src.utils import is_valid_text


class AuthorsQuotes(db.Model):
    quote_id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, primary_key=True)
    quote = db.Column(db.String)

    def __init__(self):
        self.quote_id = None
        self.author_id = None
        self.quote = None

    def get_json(self):
        return {
            'author_id': self.author_id,
            'quote': self.quote,
        }

    def get(self):
        return self.quote

    def update_author_id(self, new_author_id):
        try:
            author = Authors.query.filter_by(author_id=new_author_id)
            if author is not None:
                self.author_id = new_author_id
            return True
        except:
            return False

    def update_quote(self, new_quote):
        if self.quote != new_quote and is_valid_text(new_quote):
            self.quote = new_quote
            return True
        return False
