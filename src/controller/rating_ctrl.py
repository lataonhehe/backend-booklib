from flask import request
from flask_restful import Resource

from src.const import *
from src.controller.auth import admin_only, login_required
from src.services.ratings_sv import *


class MyRatings(Resource):
    @login_required()
    def get(self):

        result, status = get_own_ratings()

        if status == OK_STATUS:
            return result, OK_STATUS
        elif status == NOT_FOUND:
            return {MESSAGE: "You have no rating, go read some books!"}, NOT_FOUND
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def post(self):
        rating_json = request.get_json()
        status = post_my_rating(rating_json)

        if status == OK_STATUS:
            return {MESSAGE: "Thank you for your opinion."}, OK_STATUS
        elif status == CONFLICT:
            return {MESSAGE: "You already left a rating for this book"}, CONFLICT
        elif status == BAD_REQUEST:
            return {MESSAGE: "Please provide valid stars and content for your rating."}, BAD_REQUEST
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def put(self):
        rating_json = request.get_json()
        status = edit_my_rating(rating_json)

        if status == OK_STATUS:
            return {MESSAGE: "Your rating is updated"}, OK_STATUS
        elif status == NO_CONTENT:
            return {MESSAGE: "Your rating doesn't have any changes"}
        elif status == BAD_REQUEST:
            return {MESSAGE: "Please provide valid stars and content for your rating."}, BAD_REQUEST
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @admin_only()
    def delete(self):
        book_id = request.args.get(BOOK_ID)
        status = remove_rating(book_id)
        return status
