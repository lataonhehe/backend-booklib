from init_app import db
from src.const import *
from src.models.bookmarks_md import Bookmark
from src.controller.auth import get_current_user

BOOKMARK = 'bookmark'
NOTE = 'note'
LINE_POS = 'line_pos'


def get_bookmark(book_id):
    user = get_current_user()
    bookmarks = Bookmark.query.filter_by(
        username=user.username, book_id=book_id)

    result = []
    for bookmark in bookmarks:
        result.append(bookmark.get_json())

    if len(result) > 0:
        return result, OK_STATUS
    return None, NOT_FOUND


def update_bookmark(json, bm_name):
    user = get_current_user()
    print(bm_name)
    bookmark = Bookmark.query.filter_by(
        username=user.username, book_id=json[BOOK_ID], bm_name=bm_name).first()
    print(user.username, json[BOOK_ID], bm_name)
    if not bookmark:
        bookmark = Bookmark(user.username)

        if bookmark.update_book_id(json[BOOK_ID]):
            bookmark.bm_name = bm_name
            try:
                db.session.add(bookmark)
                db.session.commit()
            except:
                return CONFLICT
        else:
            return BAD_REQUEST

    if bm_name == BOOKMARK:
        if not bookmark.update_line_pos(json[LINE_POS]):
            return BAD_REQUEST
    elif bm_name == NOTE:
        if not bookmark.update_content(json[CONTENT]):
            return BAD_REQUEST

    db.session.commit()
    return OK_STATUS


def delete_bookmark(book_id, bm_name):
    user = get_current_user()
    try:
        bookmark = Bookmark.query.filter_by(
            username=user.username, book_id=book_id, bm_name=bm_name).first()

        if not bookmark:
            return NOT_FOUND

        db.session.delete(bookmark)
        db.session.commit()

        return OK_STATUS
    except:
        return BAD_REQUEST
