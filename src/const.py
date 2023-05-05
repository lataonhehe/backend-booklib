ASCEND = 'asc'
DESCEND = 'des'
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

# general keys
EMAIL = 'email'
NAME = 'name'
PICTURE = 'picture'
CONTENT_TYPE = "content-type"

USER = 0
ADMIN = 1

# Response keywords
MESSAGE = 'message'

# HTTP codes
OK_STATUS = 200
NON_AUTHORITATIVE = 203
NO_CONTENT = 204
BAD_REQUEST = 400
UNAUTHORIZED = 401
FORBIDDEN = 403
NOT_FOUND = 404
CONFLICT = 409
URI_TOO_LONG = 414
SERVER_ERROR = 500
NO_IDEA_WHAT_ERROR_THIS_IS = {
    MESSAGE: "We've encountered a problem... Sorry ;-; "}, SERVER_ERROR


# database keywords
QUERY = 'query'
STATE = 'state'
USERNAME = 'username'
PASSWORD = 'password'
USER_ROLE = 'user_role'
PHONE = 'phone'
PROFILE_PIC = 'profile_pic'
YES_RECEIVE_EMAIL = 1
# author
AUTHOR_ID = 'author_id'
# book
BOOK_ID = 'book_id'
TITLE = 'title'
TRANSLATOR = 'translator'
COVER = 'cover'
PAGE_COUNT = 'page_count'
PUBLIC_YEAR = 'public_year'
CONTENT = 'content'
DESCRIPT = 'descript'
REPUBLISH_COUNT = 'republish_count'
GENRES = 'genres'
AUTHORS = 'authors'
BOOKMARK_NAME = 'bm_name'

# constraints for data fields
NAME_MAX_LENGTH = 70
STATE_LENGTH = 100
ID_MAX_LENGTH = 20
PHONE_LENGTH = 10
GENRE_MAX_LENGTH = 40
COLL_NAME_MAX_LENGTH = 50
IMAGE_FORMATS = ("image/png", "image/jpeg", "image/jpg")

# constraints
MIN_LEV_DIFF_PERCENT = 0.5
MAX_ID = 2147483647
MAX_TEXT_LENGTH = 65535
