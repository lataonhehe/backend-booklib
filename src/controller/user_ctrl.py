from flask import request
from flask_restful import Resource

from src.const import *
from src.controller.auth import login_required
from src.services.users_sv import *


class MyAccount(Resource):
    @login_required()
    def get(self):
        result, status = get_own_account()
        
        if status == OK_STATUS:
            return result, OK_STATUS
        elif status == NOT_FOUND:
            return {MESSAGE: "No user is found"}, NOT_FOUND
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def post(self):
        new_info = request.get_json()

        status = edit_own_account(new_info)

        if status == OK_STATUS:
            return {MESSAGE: "Your profile is updated"}, OK_STATUS
        elif status == NO_CONTENT:
            return {MESSAGE: "Your profile is the same. Please recheck your input"}, OK_STATUS
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def delete(self):
        status = remove_own_account()
        if status == OK_STATUS:
            return {MESSAGE: "Your account is deleted."}, OK_STATUS
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS


class MyNoti(Resource):
    @login_required()
    def get(self):
        result, status = get_my_noti()
        if status == OK_STATUS:
            return result, OK_STATUS
        elif status == NO_CONTENT:
            return {MESSAGE: "You don't have any news, go follow some authors, put some books into your collection"}, OK_STATUS
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS
