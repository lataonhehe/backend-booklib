from init_app import db
from src.const import *
from src.models.collections_md import Collections
from src.utils import (is_url_image, is_valid_datetime, is_valid_name, is_valid_text,
                       is_valid_username, validate_phone)
from src.utils import get_username_from_email


class Users(db.Model):
    username = db.Column(db.String(64), primary_key=True)
    password = db.Column(db.String(30))
    email = db.Column(db.String(64))
    name = db.Column(db.String(64))
    phone = db.Column(db.String(64))
    profile_pic = db.Column(db.String(64))
    theme_preference = db.Column(db.Integer)
    login_state = db.Column(db.String(64))
    user_role = db.Column(db.Integer)
    restrict_due = db.Column(db.DateTime)
    recieve_email = db.Column(db.Integer)
    bio = db.Column(db.String(64))
    rec_list = db.Column(db.String(64))

    def __init__(self):
        self.user_role = 0
        self.theme_preference = 1
        self.recieve_email = 1

    def __init__(self, email, profile_pic):
        self.username = get_username_from_email(email)
        self.email = email
        self.profile_pic = profile_pic
        self.theme_preference = 1
        self.user_role = 0
        self.recieve_email = 1

    def get_json(self):
        return {
            'username': self.username,
            'email': self.email,
            'name': self.name,
            'phone': self.phone,
            'profile_pic': self.profile_pic,
            'bio': self.bio,
            'theme_preference': self.theme_preference,
            'user_role': self.user_role,
        }
    
    def existed_username(self, new_username):
        if Users.query.filter_by(username = new_username).first() == None:
            return True
        return False

    def update_username(self, new_username):
        if self.username != new_username and is_valid_username(new_username, 64):
            self.username = new_username
            return True
        return False

    def update_name(self, new_name):
        if self.name != new_name and is_valid_name(new_name):
            self.name = new_name
            return True
        return False

    def update_phone(self, new_phone):
        new_phone = validate_phone(new_phone)
        if self.phone != new_phone:
            self.phone = new_phone
            return True
        return False

    def update_profile_pic(self, new_pic_url):
        if self.profile_pic != new_pic_url and is_url_image(new_pic_url):
            self.profile_pic = new_pic_url
            return True
        return False

    def update_theme_preference(self, new_theme_pref):
        if self.theme_preference != new_theme_pref and isinstance(new_theme_pref, int):
            self.theme_preference = new_theme_pref
            return True
        return False

    def update_restrict_due(self, restrict_due):
        if self.restrict_due != restrict_due and is_valid_datetime(restrict_due):
            self.restrict_due = restrict_due
            return True
        return False

    def update_receive_email(self, receive_email):
        if self.recieve_email != receive_email and (receive_email == 0 or receive_email == 1):
            self.recieve_email = receive_email
            return True
        return False

    def update_bio(self, new_bio):
        if self.bio != new_bio and is_valid_text(new_bio):
            self.bio = new_bio
            return True
        return False
