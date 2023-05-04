import validators as val

from init_app import db
from src.const import *
from src.utils import is_url_image, is_valid_name


class Authors(db.Model):
    author_id = db.Column(db.Integer, primary_key=True)
    author_name = db.Column(db.String(70))
    profile_pic = db.Column(db.String)
    bio = db.Column(db.String)
    social_account = db.Column(db.String)
    website = db.Column(db.String)

    def __init__(self):
        self.author_name = None
        self.profile_pic = None
        self.bio = None
        self.social_account = None
        self.website = None

    def get_json(self):
        return {
            'author_id': self.author_id,
            'author_name': self.author_name,
            'profile_pic': self.profile_pic,
            'bio': self.bio,
            'social_account': self.social_account,
            'website': self.website
        }

    def update_author_name(self, new_author_name):
        if new_author_name != self.author_name and is_valid_name(new_author_name, NAME_MAX_LENGTH):
            self.author_name = new_author_name
            return True
        return False

    def update_profile_pic(self, new_pic_url):
        if new_pic_url != self.profile_pic and is_url_image(new_pic_url):
            self.profile_pic = new_pic_url
            return True
        return False

    def update_bio(self, new_bio):
        if self.bio != new_bio:
            self.bio = new_bio
            return True
        return False

    def update_social_account(self, new_social_acc_url):
        if new_social_acc_url != self.social_account and val.url(new_social_acc_url):
            self.social_account = new_social_acc_url

    def update_website(self, new_website):
        if new_website != self.website and val.url(new_website):
            self.website = new_website
