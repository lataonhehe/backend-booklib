from datetime import datetime

from flask import request
from flask_mail import Mail, Message

from init_app import app, db
from src.const import *
from src.models.authors_md import Authors
from src.models.books_md import Books
from src.models.collections_md import Collections
from src.models.noti_md import Notifications
from src.models.subscription_md import Subscription
from src.models.users_md import Users

# EMAIL_SENDER = 'lam20020260@gmail.com'
BOOK_UPDATE_BODY = 'Yayyy a book in your collection is updated recently. Visit this link {url} to check it out.'
AUTHOR_NEWS_BODY = 'Your favorite author has a new masterpiece! Visit this link {url} to check it out.'

BOOK_UPDATE_NOTI = "{bookname} has some new updates!"
AUTHOR_NEW_BOOK_NOTI = "{author_name} has a new work!"
BOOK_DETAIL_PATH = "/books?book_id={id}"


def send_email(subject, recipients, body):
    with app.app_context():
        msg = Message(subject=subject, recipients=recipients, body=body)
        Mail.send(msg)


def notify_book_update(book_id):
    book = Books.query.filter_by(book_id=book_id).first()
    usernames = db.session.query(
        Collections.username.distinct()).filter_by(book_id=book_id).all()

    email_recipients = []
    for username in usernames:
        new_noti = Notifications(username[0], BOOK_UPDATE_NOTI.format(
            book.title), datetime.today(), BOOK_DETAIL_PATH.format(book_id))
        db.session.add(new_noti)
        user = Users.query.filter_by(username=username[0]).first()
        if user.recieve_email == YES_RECEIVE_EMAIL:
            email_recipients.append(user.email)

    db.session.commit()
    send_email(BOOK_UPDATE_NOTI.format(book.title),
               email_recipients, BOOK_UPDATE_BODY.format(request.full_path))


def notify_authors_new_book(author_ids, book_id):
    email_recipients = []
    for author_id in author_ids:
        author = Authors.query.filter_by(author_id=author_id).first()
        usernames = db.session.query(
            Subscription.username.distinct()).filter_by(author_id=author_id).all()

        for username in usernames:
            new_noti = Notifications(username[0], AUTHOR_NEW_BOOK_NOTI.format(
                author.author_name), datetime.today(), BOOK_DETAIL_PATH.format(book_id))
            db.session.add(new_noti)

            user = Users.query.filter_by(username=username[0]).first()
            if user.recieve_email == YES_RECEIVE_EMAIL:
                email_recipients.append(user.email)

        send_email(AUTHOR_NEW_BOOK_NOTI.format(author.author_name),
                   email_recipients, BOOK_UPDATE_BODY.format(request.full_path))

    db.session.commit()
