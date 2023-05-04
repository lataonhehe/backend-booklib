from init_app import db
from src.const import *
from src.models.authors_md import Authors
from src.models.books_md import Books
from src.models.authors_books_md import BooksAuthors
from src.models.quotes_md import AuthorsQuotes
from src.models.subscription_md import Subscription
from src.utils import is_similar


def search_by_name(query):
    all_authors = Authors.query.all()
    result = []
    for author in all_authors:
        if is_similar(author.author_name, query):
            result.append(author.get_json())
    if len(result) == 0:
        return None, NOT_FOUND
    return result, OK_STATUS


def get_follower_list(author_id):
    subs = Subscription.query.filter_by(author_id=author_id)
    followers = []
    for sub in subs:
        followers.append(sub.username)


def get_book_list(author_id):
    result = []
    authors_books = BooksAuthors.query.filter_by(author_id=author_id)
    for author_book in authors_books:
        book = Books.query.filter_by(book_id=author_book.book_id).first()
        result.append(book.get_summary_json())
    return result


def get_info(author_id):
    author = Authors.query.get(author_id)
    if author is None:
        return None, NOT_FOUND

    result = author.get_json()
    result["followers"] = get_follower_list(author_id)
    result["books"] = get_book_list(author_id)
    quote = AuthorsQuotes.query.filter_by(author_id=author_id).first()
    if quote:
        result["quote"] = quote.get()
    else:
        result["quote"] = None
    return result, OK_STATUS


def add_author(author_info):
    new_author = Authors()

    if new_author.update_author_name(author_info["author_name"]):
        new_author.update_bio(author_info["bio"])
        new_author.update_profile_pic(author_info[PROFILE_PIC])
        new_author.update_social_account(author_info["social_account"])
        new_author.update_website(author_info["website"])

        db.session.add(new_author)
        db.session.commit()

        quote = AuthorsQuotes()
        quote.update_author_id(new_author.author_id)
        quote.update_quote(author_info["quote"])

        db.session.add(quote)
        db.session.commit()

        return new_author.get_json(), OK_STATUS

    return None, BAD_REQUEST
