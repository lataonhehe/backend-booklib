from flask import request
from flask_restful import Resource

from src.const import *
from src.controller.auth import login_required
from src.services.collections_sv import *


class MyCollections(Resource):
    @login_required()
    def get(self, coll_name):
        result, status = get_own_collections()

        if status == OK_STATUS:
            return result, OK_STATUS
        elif status == NOT_FOUND:
            return {MESSAGE: "No collection found"}, NOT_FOUND
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def post(self, coll_name):
        json = request.get_json()
        status = create_collection(coll_name, json["books"])

        if status == OK_STATUS:
            return {MESSAGE: "Collection updated"}, OK_STATUS
        elif status == BAD_REQUEST:
            return {MESSAGE: "Invalid collname or book_ids"}, BAD_REQUEST
        elif status == NO_CONTENT:
            return {MESSAGE: "Nothing updated (invalid book_ids"}, OK_STATUS
        elif status == CONFLICT:
            return {MESSAGE: "Collection already exists"}, CONFLICT
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def patch(self, coll_name):
        new_name = request.args.get("new_name")
        status = edit_collection_name(coll_name, new_name)

        if status == OK_STATUS:
            return {MESSAGE: "{old_name}'s name is now {new_name}".format(coll_name, new_name)}, OK_STATUS
        elif status == NOT_FOUND:
            return {MESSAGE: "Can't find your collection"}, NOT_FOUND
        elif status == BAD_REQUEST:
            return {MESSAGE: "Please provide valid name for you collection"}, BAD_REQUEST
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def put(self, coll_name):
        book_id = request.args.get(BOOK_ID)
        status = remove_book_from_collection(coll_name, book_id)

        if status == OK_STATUS:
            return {MESSAGE: "Book is removed from your collection"}, OK_STATUS
        elif status == NOT_FOUND:
            return {MESSAGE: "Can't find collection (or book)"}, NOT_FOUND
        elif status == BAD_REQUEST:
            return {MESSAGE: "The collection name is invalid"}, BAD_REQUEST
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS

    @login_required()
    def delete(self, coll_name):
        status = delete_collection(coll_name)

        if status == OK_STATUS:
            return {MESSAGE: "Collection deleted"}, OK_STATUS
        elif status == NOT_FOUND:
            return {MESSAGE: "Can't find your collection"}, NOT_FOUND
        elif status == BAD_REQUEST:
            return {MESSAGE: "The collection name is invalid"}, BAD_REQUEST
        else:
            return NO_IDEA_WHAT_ERROR_THIS_IS
