from flask import request
from flask_restful import Resource

from src.const import *
from src.controller.auth import login_required
from src.services.bookmark_sv import *


class MyBookmarks(Resource):
    @login_required()
    def get(self):
        book_id = request.args.get(BOOK_ID)
        result, status = get_bookmark(book_id)

        if status == OK_STATUS:
            return result, OK_STATUS
        elif status == NOT_FOUND:
            return {MESSAGE: "Can't find your bookmark or note"}, NOT_FOUND
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def post(self):
        json = request.get_json()
        bm_name = request.args.get(BOOKMARK_NAME)
        status = update_bookmark(json, bm_name)

        return status

    @login_required()
    def delete(self):
        book_id = request.args.get(BOOK_ID)
        bm_name = request.args.get(BOOKMARK_NAME)
        status = update_bookmark(book_id, bm_name)

        return status
