from init_app import db
from src.utils import is_valid_name
from src.const import GENRE_MAX_LENGTH

GENRES = ["Phiêu lưu", "Cổ điển", "Tội phạm, trinh thám", "Viễn tưởng",
          "Cổ tích, truyền thuyết", "Lịch sử", "Kinh dị", "Hài hước"]


class Genres(db.Model):
    book_id = db.Column(db.Integer, primary_key=True)
    genre = db.Column(db.String, primary_key=True)

    def __init__(self):
        self.book_id = None
        self.genre = None

    @staticmethod
    def add_genres(book_id, new_genres):
        if not isinstance(new_genres, list):
            return False

        for genre in new_genres:
            if genre not in GENRES:
                return False

        for genre in new_genres:
            new = Genres()
            new.book_id = book_id
            new.genre = genre
            db.session.add(new)

        db.session.commit()
        return True

    @staticmethod
    def update_genres(book_id, new_genres):
        if not isinstance(new_genres, list):
            return False

        books_genres = Genres.query.filter_by(book_id=book_id)
        current_genres = []
        for book_genre in books_genres:
            current_genres.append(book_genre.genre)
            db.session.delete(book_genre)

        current_genres.sort()
        new_genres.sort()
        if current_genres == new_genres:
            return False

        return Genres.add_genres(book_id, new_genres)
