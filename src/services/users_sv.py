import sqlalchemy

from init_app import db
from src.const import *
from src.controller.auth import get_current_user
from src.models.bookmarks_md import Bookmark
from src.models.collections_md import Collections
from src.models.noti_md import Notifications
from src.models.ratings_md import Ratings
from src.models.users_md import Users
from src.models.states_md import States
from src.models.subscription_md import Subscription
from src.services.collections_sv import get_own_collections

def add_user(user_json):
    user = Users()
    if user.existed_username(user_json[USERNAME]):
        user.username = user_json[USERNAME]
        user.password = user_json[PASSWORD]
        user.email = user_json[EMAIL]
        # user.phone = user_json[PHONE]

        db.session.add(user)
        db.session.commit()

        return OK_STATUS

    return BAD_REQUEST

def get_own_account():
    user = get_current_user()
    if user is None:
        return None, NOT_FOUND
    result = user.get_json()
    result.update({"collections": get_own_collections()})
    return result, OK_STATUS


def edit_own_account(new_info):
    username = new_info[USERNAME]
    name = new_info[NAME]
    phone = new_info[PHONE]
    profile_pic = new_info[PROFILE_PIC]
    theme_preference = new_info['theme']
    receive_email = new_info['receive_email']
    bio = new_info['bio']
    user = get_current_user()
    updated = False

    if user.update_username(username):
        updated = True

    if user.update_name(name):
        updated = True

    if user.update_phone(phone):
        updated = True

    if user.update_profile_pic(profile_pic):
        updated = True

    if user.update_theme_preference(theme_preference):
        updated = True

    if user.update_receive_email(receive_email):
        updated = True

    if user.update_bio(bio):
        updated = True

    if updated:
        db.session.commit()
        return OK_STATUS

    return NO_CONTENT


def remove_own_account():
    user = get_current_user()
    try:
        username = user.username

        all_colls = Collections.query.filter_by(username=username).all()
        all_noti = Notifications.query.filter_by(username=username).all()
        all_subs = Subscription.query.filter_by(username=username).all()
        all_bookmark = Bookmark.query.filter_by(username=username).all()
        all_rating = Ratings.query.filter_by(username=username).all()

        to_delete = all_noti+all_bookmark+all_rating+all_subs+all_colls
        for obj in to_delete:
            db.session.delete(obj)

        state = States.query.filter_by(state=user.login_state).first()

        db.session.delete(user)
        db.session.delete(state)

        db.session.commit()
        return OK_STATUS
    except:
        return SERVER_ERROR


def subscribe_to_author(author_id):
    user = get_current_user()
    new_subscription = Subscription()
    if new_subscription.update_username(user.username) and new_subscription.update_author_id(author_id):
        try:
            db.session.add(new_subscription)
            db.session.commit()
            return OK_STATUS
        except sqlalchemy.exc.IntegrityError:
            return CONFLICT
    return BAD_REQUEST


def unsubscribe_author(author_id):
    user = get_current_user()
    sub = Subscription.query.filter_by(
        username=user.username, author_id=author_id)
    try:
        db.session.delete(sub)
        db.session.commit()
        return OK_STATUS
    except:
        return BAD_REQUEST


def get_my_noti():
    user = get_current_user()
    all_noti = Notifications.query.filter_by(username=user.username)
    result = []
    for noti in all_noti:
        result.append(noti.get_json())
    if len(result) == 0:
        return None, NO_CONTENT
    return result, OK_STATUS
