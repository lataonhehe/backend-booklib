from init_app import db
from src.models.authors_md import Authors
from src.utils import is_valid_username


class Subscription(db.Model):
    author_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))

    def __init__(self):
        self.author_name = None
        self.username = None

    def update_author_id(self, new_author_id):
        try:
            author = Authors.query.filter_by(author_id=new_author_id)
            if author is not None:
                self.author_id = new_author_id
            return True
        except:
            return False

    def update_username(self, new_username):
        if self.username != new_username and is_valid_username(new_username):
            self.username = new_username
            return True
        return False
