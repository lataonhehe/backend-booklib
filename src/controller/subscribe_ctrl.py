from flask import request
from flask_restful import Resource

from src.const import *
from src.controller.auth import login_required
from src.services.users_sv import *


class Subscribe(Resource):
    @login_required()
    def post(self):
        author_id = request.args.get(AUTHOR_ID)
        status = subscribe_to_author(author_id)
        if status == OK_STATUS:
            return {MESSAGE: "Thank you for your subscription!"}, OK_STATUS
        elif status == BAD_REQUEST:
            return {MESSAGE: "You can't subscribe to this author (probably because this author is just your illusion...)"}, BAD_REQUEST
        elif status == CONFLICT:
            return {MESSAGE: "You're already subscribed to this author"}, CONFLICT
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def delete(self):
        author_id = request.args.get(AUTHOR_ID)
        status = unsubscribe_author(author_id)
        if status == OK_STATUS:
            return {MESSAGE: "Unsubscribed!"}, OK_STATUS
        elif status == BAD_REQUEST:
            return {MESSAGE: "Can't perform unsubscription"}, BAD_REQUEST
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS
