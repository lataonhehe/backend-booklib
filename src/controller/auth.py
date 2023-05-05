from datetime import datetime
from functools import wraps

from flask import redirect, request, g, abort
import logging
import jwt


from config.config import FRONTEND_URL, SECRET_KEY
from init_app import db
from src.const import *
from src.models.states_md import States
from src.models.users_md import Users
from src.utils import equal


def login_required():
    def wrapper(function):
        @wraps(function)
        def real_func(*args, **kwargs):
            state = request.args.get(STATE)
            # state = request.cookies.get(STATE)
            if not state:
                return {MESSAGE: "No state found. Login first."}, NON_AUTHORITATIVE
            else:
                token = jwt.decode(state, SECRET_KEY , algorithms=["HS256"])
                user = Users.query.filter_by(username=token[USERNAME]).first()
                if not user:
                    return {MESSAGE: "No user with this state."}, NON_AUTHORITATIVE

                if user.restrict_due is not None:
                    if user.restrict_due < datetime.today():
                        user.restrict_due = None
                        db.session.commit()
                    else:
                        return {MESSAGE: "Your account is restricted."}, FORBIDDEN

            return function(*args, **kwargs)
        return real_func
    return wrapper

# def login_required():
#     def wrapper(function):
#         @wraps(function)
#         def real_func(*args, **kwargs):
#             state = request.args.get(STATE)
#             # state = request.cookies.get(STATE)
#             print(request.args)
#             if not state:
#                 return {MESSAGE: "No state found. Login first."}, NON_AUTHORITATIVE
#             else:
#                 user = Users.query.filter_by(login_state=state).first()
#                 if not user:
#                     return {MESSAGE: "No user with this state."}, NON_AUTHORITATIVE

#                 if user.restrict_due is not None:
#                     if user.restrict_due < datetime.today():
#                         user.restrict_due = None
#                         db.session.commit()
#                     else:
#                         return {MESSAGE: "Your account is restricted."}, FORBIDDEN

#             return function(*args, **kwargs)
#         return real_func
#     return wrapper


def admin_only():
    def wrapper(function):
        @wraps(function)
        def real_func(*args, **kwargs):
            # state = request.get_json()[STATE]
            state = request.args.get(STATE)

            if not state:
                return {MESSAGE: "No state found in cookie. Login first."}, NON_AUTHORITATIVE
            else:
                token = jwt.decode(state, SECRET_KEY , algorithms=["HS256"])
                user = Users.query.filter_by(username=token[USERNAME]).first()
                if not user:
                    return {MESSAGE: "No user with this state."}, NON_AUTHORITATIVE
                if not equal(user.user_role, ADMIN):
                    return {MESSAGE: "You shall not pass! ('cause you're not authorized)"}, FORBIDDEN

            return function(*args, **kwargs)
        return real_func
    return wrapper


# def remove_current_state():
#     state = request.cookies.get(STATE)
#     state_db = States.query.filter_by(state=state).first()
#     if state_db:
#         db.session.delete(state_db)
#         db.session.commit()


def get_current_user():
    # state = request.cookies.get(STATE)
    state = request.args.get(STATE)
    if not state:
        return None
    token = jwt.decode(state, SECRET_KEY , algorithms=["HS256"])
    user = Users.query.filter_by(username= token[USERNAME]).first()
    
    return user


# def get_current_user():
#     # state = request.cookies.get(STATE)
#     state = request.args.get(STATE)
#     print(state)
#     if not state:
#         return None
#     user = Users.query.filter_by(login_state=state).first()
#     return user