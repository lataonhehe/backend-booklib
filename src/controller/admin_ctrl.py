from flask import request
from flask_restful import Resource

from src.const import *
from src.controller.auth import admin_only
from src.services.admin_sv import *


class UserList(Resource):
    @admin_only()
    def get(self):
        result, status = get_user_list()
        if status == NOT_FOUND:
            return {MESSAGE: "No user is in database"}, NOT_FOUND
        elif status == OK_STATUS:
            return result, OK_STATUS
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS


class ChangeRole(Resource):
    @admin_only()
    def post(self):
        username = request.args.get(USERNAME)
        new_role = request.args.get(USER_ROLE)

        status = change_user_role(username, new_role)
        if status == NOT_FOUND:
            return {MESSAGE: "Can't find that user"}, NOT_FOUND
        elif status == CONFLICT:
            return {MESSAGE: "User already has this role"}, CONFLICT
        elif status == OK_STATUS:
            return {MESSAGE: "User's social status has changed!"}
        elif status == BAD_REQUEST:
            return {MESSAGE: "That's an invalid role..."}, BAD_REQUEST
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS


class BanUser(Resource):
    @admin_only()
    def post(self):
        restrict_info = request.get_json()
        username = restrict_info[USERNAME]
        restrict_due = restrict_info['restrict_due']

        status = ban_user(username, restrict_due)
        if status == OK_STATUS:
            return {MESSAGE: "This user is banned."}, OK_STATUS
        elif status == BAD_REQUEST:
            return {MESSAGE: "Please check the date you want this user to be unbanned"}, BAD_REQUEST
        elif status == NOT_FOUND:
            return {MESSAGE: "User not found"}, NOT_FOUND
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS
