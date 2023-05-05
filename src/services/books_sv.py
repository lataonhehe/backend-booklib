import json
from datetime import datetime
from operator import itemgetter

from config.config import RECOMMEND_PATH
from init_app import db, mydb
from src.const import *
from src.controller.auth import get_current_user
from src.models.authors_books_md import BooksAuthors
from src.models.authors_md import Authors
from src.models.books_md import Books
from src.models.collections_md import Collections
from src.models.genres_md import Genres
from src.services.noti_sv import notify_authors_new_book, notify_book_update
from src.services.ratings_sv import get_own_ratings, get_ratings_by_stars
from src.utils import is_similar

MAX_RECOMMEND = 20
UPDATE_INTERVAL = 60  # (secs)
LAST_UPDATED = "last_updated"


def need_to_update(list_type):
    try:
        with open(RECOMMEND_PATH, 'r') as file:
            recommend = json.load(file)
        rec_list = recommend[list_type]
        duration = datetime.now() - \
            datetime.strptime(rec_list[LAST_UPDATED], DATETIME_FORMAT)
        if duration.total_seconds() > UPDATE_INTERVAL:
            rec_list[LAST_UPDATED] = datetime.today().strftime(DATETIME_FORMAT)
            return recommend
        return None
    except:
        return SERVER_ERROR


def update_popular_books():
    '''
    Update "popular" books based on:
    - id (newer -> higher id)
    - rating (at least 3.5), rating count
    - count in collection
    - popular author? (considering...)
    '''

    rec_json = need_to_update("popular")
    if rec_json == SERVER_ERROR:
        return SERVER_ERROR
    elif rec_json:
        popular_rec_json = rec_json["popular"]

        all_books = Books.query.all()
        books = []
        for index, book in enumerate(all_books):
            appears_in_colls = db.session.query(
                Collections.username.distinct()).filter_by(book_id=book.book_id).count()

            score = index/10 + book.current_rating + book.rating_count + appears_in_colls
            books.append((book.get_summary_json(), score))

        books.sort(key=itemgetter(1), reverse=True)

        popular_rec_json["books"] = [book[0] for book in books[:MAX_RECOMMEND]]
        with open(RECOMMEND_PATH, 'w') as file:
            json.dump(rec_json, file, indent=4)

    return OK_STATUS


def update_new_books():
    '''
    Update "new" books based on:
    - id (newer -> higher id)
    - rating (at least 3.5)
    '''

    rec_json = need_to_update("new")
    if rec_json == SERVER_ERROR:
        return SERVER_ERROR
    elif rec_json:
        popular_rec_json = rec_json["new"]

        all_books = Books.query.all()
        books = []
        for index, book in enumerate(all_books):
            score = index/5 + book.current_rating + book.rating_count/2
            books.append((book.get_summary_json(), score))

        books.sort(key=itemgetter(1), reverse=True)

        popular_rec_json["books"] = [book[0] for book in books[:MAX_RECOMMEND]]
        with open(RECOMMEND_PATH, 'w') as file:
            json.dump(rec_json, file, indent=4)

    return OK_STATUS


def update_personal_recommendation():
    '''
    Update personal recommendation based on:
    - id (newer -> higher id)
    - user ratings + collections -> favourite genre
    - subscribed authors
    - minus point if user rated or had this book in collection
    '''
    user = get_current_user()
    
    if user is None:
        return None, NO_CONTENT

    if user.rec_list is not None:
        rec_list = json.loads(user.rec_list)
        duration = datetime.now() - \
            datetime.strptime(rec_list[LAST_UPDATED], DATETIME_FORMAT)
        if duration.total_seconds() <= UPDATE_INTERVAL:
            return None, NO_CONTENT

    user.rec_list = {}
    user.rec_list[LAST_UPDATED] = datetime.today().strftime(DATETIME_FORMAT)

    user_ratings = get_own_ratings()

    all_books = Books.query.all()
    books = []
    for index, book in enumerate(all_books):

        score = index + book.current_rating + book.rating_count/2
        books.append((book.get_summary_json(), score))

    books.sort(key=itemgetter(1), reverse=True)

    user.rec_list["books"] = [book[0] for book in books[:MAX_RECOMMEND]]
    user.rec_list = json.dumps(user.rec_list)
    db.session.commit()

    return rec_list, OK_STATUS


def search_by_name(query):
    result = list()
    list_book = Books.query.filter(Books.title.like("%"+query+"%")).all()
    for book in list_book:
        result.append(book.get_summary_json())
    if len(result) == 0:
        return [], NOT_FOUND
    return result, OK_STATUS


def search_by_author(query):

    result = list()

    author_list = Authors.query.filter(Authors.author_name.like("%"+query+"%")).all()
    for author in author_list:
        id_list = BooksAuthors.query.filter_by(author_id = author.author_id).all()
        for id in id_list:
            book = Books.query.get(id.book_id)
            result.append(book.get_summary_json())

    if len(result) == 0:
        return [], NOT_FOUND
    return result, OK_STATUS


def filter_books(genres, min_year, max_year, min_pages, max_pages, min_rating, max_rating):
    if not (genres or min_year or min_rating or min_pages or max_pages):
        return None, NOT_FOUND

    all_books = Books.query.all()
    results = []

    for book in all_books:
        for genre in genres:
            if Genres.query.filter_by(genre=genre, book_id=book.book_id).first():
                results.append((book.get_summary_json(), book.public_year))

        if min_rating and min_rating.isnumeric() and book.current_rating >= float(min_rating):
            results.append((book.get_summary_json(), book.public_year))

        min_pages = int(min_pages) 
        max_pages = int(max_pages) 

        if min_pages:
            if book.page_count >= min_pages and (not max_pages or book.page_count <= min_pages):
                results.append((book.get_summary_json(), book.public_year))
        elif max_pages and book.page_count <= min_pages:
            results.append((book.get_summary_json(), book.public_year))

    if len(results) == 0:
        return None, NOT_FOUND

    if min_year == ASCEND:
        results.sort(key=itemgetter(1))
    elif min_year == DESCEND:
        results.sort(key=itemgetter(1), reverse=True)

    results = [result[0] for result in results]
    
    cur = mydb.cursor()
    args = [genres[0], min_year, max_year, min_pages, max_pages, min_rating, max_rating]
    cur.callproc('filter_book', args)

    for out in cur.stored_results():
        header = [x[0] for x in out.description]
        header.remove('author_id')
        header[2] = 'authors'
        res = out.fetchall()

    results = []
    for row in res:
        row = list(row)
        row[2] = [{row[2]: row[3]}]
        del row[3]
        row[4] = [row[4]]
        results.append(dict(zip(header, row)))

    return results, OK_STATUS


def get_detail_info(book_id):
    book = Books.query.filter_by(book_id=book_id).first()
    if book is None:
        return None, NOT_FOUND

    ratings = {"total": book.rating_count}
    for i in range(1, 6):
        ratings.update(get_ratings_by_stars(book_id, i))

    result = book.get_detail_json()
    result.update(ratings)

    return result, OK_STATUS


def add_book(json):
    book = Books()

    if book.is_valid_book(json[TITLE], json[PAGE_COUNT], json[PUBLIC_YEAR], json[CONTENT], json[DESCRIPT]):
        book.update_translator(json[TRANSLATOR])
        book.update_cover(json[COVER])
        book.update_republish_count(json[REPUBLISH_COUNT])

        db.session.add(book)
        db.session.commit()

        Genres.add_genres(book.book_id, json[GENRES])
        BooksAuthors.add_authors(book.book_id, json[AUTHORS])
        notify_authors_new_book(json[AUTHORS], book.book_id)

        return book.get_detail_json(), OK_STATUS

    return None, BAD_REQUEST


def edit_book_info(json):
    book = Books.query.filter_by(book_id=json[BOOK_ID]).first()
    updated = False

    if book.update_title(json[TITLE]):
        updated = True
    if book.update_page_count(json[PAGE_COUNT]):
        updated = True
    if book.update_public_year(json[PUBLIC_YEAR]):
        updated = True
    if book.update_content(json[CONTENT]):
        updated = True
    if book.update_descript(json[DESCRIPT]):
        updated = True
    if book.update_translator(json[TRANSLATOR]):
        updated = True
    if book.update_cover(json[COVER]):
        updated = True
    if book.update_republish_count(json[REPUBLISH_COUNT]):
        updated = True
    if Genres.update_genres(book.book_id, json[GENRES]):
        updated = True
    if BooksAuthors.update_authors(book.book_id, json[AUTHORS]):
        updated = True

    if updated:
        db.session.commit()
        notify_book_update(book.book_id)
        return book.get_detail_json(), OK_STATUS

    return None, BAD_REQUEST


def remove_book(book_id):
    book = Books.query.filter_by(book_id=book_id).first()
    if book is None:
        return NOT_FOUND
    try:
        db.session.delete(book)
        db.session.commit()
        return OK_STATUS
    except:
        return SERVER_ERROR
