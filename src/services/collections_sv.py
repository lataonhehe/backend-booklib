from init_app import db
from src.const import *
from src.controller.auth import get_current_user
from src.models.books_md import Books
from src.models.collections_md import Collections
from src.utils import is_valid_name


def get_own_collections():
    user = get_current_user()
    collection_names = db.session.query(Collections.coll_name.distinct()).filter_by(
        username=user.username).all()
    collection_list = []
    for coll_name in collection_names:
        collection = Collections.query.filter_by(
            username=user.username, coll_name=coll_name[0]).first()
        collection_list.append(collection.get_json(
            user.username, coll_name[0]))
    return collection_list, OK_STATUS


def create_collection(coll_name, book_ids):
    try:
        user = get_current_user()
        if not is_valid_name(coll_name):
            return BAD_REQUEST

        updated = False
        for book_id in book_ids:
            book = Books.query.get(book_id)
            if book:
                collection = Collections(user.username)
                collection.coll_name = coll_name
                collection.book_id = book_id
                db.session.add(collection)
                updated = True

        if updated:
            db.session.commit()
            return OK_STATUS
        return NO_CONTENT
    except:
        return CONFLICT


def edit_collection_name(coll_name, new_name):
    user = get_current_user()
    try:
        collections = Collections.query.filter_by(
            username=user.username, coll_name=coll_name)
        if collections and Collections.update_coll_name(user.username, coll_name, new_name):
            for collection in collections:
                collection.coll_name = coll_name
            db.session.commit()
            return OK_STATUS
        return NOT_FOUND
    except:
        return BAD_REQUEST


def remove_book_from_collection(coll_name, book_id):
    user = get_current_user()
    try:
        collection = Collections.query.filter_by(
            username=user.username, coll_name=coll_name, book_id=book_id).first()
        if collection:
            db.session.delete(collection)
            db.session.commit()
            return OK_STATUS
        return NOT_FOUND
    except:
        return BAD_REQUEST


def delete_collection(coll_name):
    user = get_current_user()
    try:
        collections = Collections.query.filter_by(
            username=user.username, coll_name=coll_name)
        if collections:
            for collection in collections:
                db.session.delete(collection)
            db.session.commit()
            return OK_STATUS
        return NOT_FOUND
    except:
        return BAD_REQUEST
