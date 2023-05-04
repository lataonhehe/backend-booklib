from init_app import db
from src.const import *
from src.const import EMAIL
from src.controller.auth import admin_only
from src.models.users_md import Users
from src.utils import equal


@admin_only()
def get_user_list():
    users = Users.query.all()

    if users is None:
        return None, NOT_FOUND

    result = []
    try:
        for user in users:
            result.append(user.get_json())
        return result, OK_STATUS
    except:
        return None, SERVER_ERROR


def change_user_role(username, new_role):
    user = Users.query.filter_by(username=username).first()

    if user is None:
        return NOT_FOUND

    if equal(user.user_role, new_role):
        return CONFLICT

    if new_role == ADMIN or new_role == MUGGLE_USER:
        user.user_role = new_role
        db.session.commit()
        return OK_STATUS
    return BAD_REQUEST


def ban_user(username, restrict_due):
    user = Users.query.filter_by(username=username).first()
    if user is None:
        return NOT_FOUND

    if user.update_restrict_due(restrict_due):
        db.session.commit()
        return OK_STATUS
    return BAD_REQUEST


def remove_user(username):
    pass
