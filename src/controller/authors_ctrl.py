from flask import request
from flask_restful import Resource

from src.const import *
from src.controller.auth import admin_only
from src.services.authors_sv import *


# class AllAuthors(Resource):

#     def get(self, query_string):


class AuthorsSearch(Resource):

    def get(self):
        '''
        Search by author's name
        '''

        query_string = request.args.get(QUERY)

        result, status = search_by_name(query_string)

        if status == OK_STATUS:
            return result, OK_STATUS
        elif status == NOT_FOUND:
            return {MESSAGE: "No author found"}, NOT_FOUND


class AuthorInfo(Resource):

    def get(self):
        author_id = request.args.get(AUTHOR_ID)
        result, status = get_info(author_id)

        if status == OK_STATUS:
            return result, OK_STATUS
        elif status == NOT_FOUND:
            return {MESSAGE: "No author found"}, NOT_FOUND

    @admin_only()
    def post(self):
        author_info = request.get_json()
        result, status = add_author(author_info)

        if status == OK_STATUS:
            return result, OK_STATUS
        else:
            return {MESSAGE: "Please provide a valid name for author."}, BAD_REQUEST
