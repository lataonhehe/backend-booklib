## Installation
```sh
git clone https://github.com/beckachuu/temp-backend.git
cd temp-backend
pip install -r requirements.txt
python Geeky.py
```
### Port: 5000

---

## Database diagram:

![db_diagram](https://user-images.githubusercontent.com/78261243/204224617-d6a3726a-2421-40bf-8246-d8ccf496d670.png)

---

## URLs:
(Fields that aren't mandatory: still need to be included, values can be set to null)

- GET /login
- GET /logout

---

### Account APIs
- GET /my_account
- POST /my_account: edit user info
> JSON structure:
  { "username": string,
    "name": string,
    "phone": string,
    "profile_pic": string,
    "theme": int (0 or 1),
    "receive_email": int (0 or 1)
    "bio": string }

- DELETE /my_account
- GET /my_notification

---

### Ratings APIs
- GET /my_ratings
- POST /my_ratings
> JSON structure:
  { "book_id": int (mandatory),
    "stars": int (mandatory),
    "content": string }
- PUT /my_ratings : edit rating
> JSON structure: same as above
- DELETE /my_ratings?book_id={int}: remove user rating from a book (admin only)

---

### Collections APIs
- GET /my_collections/all
- POST /my_collections/{string:collname}
> JSON structure:
> { "books": int[] (mandatory) }
- PATCH /my_collections/{string:collname}?new_name={string} : rename collection
- PUT /my_collections/{string:collname}?book_id={string} : remove book from collection
- DELETE /my_collections/{string:collname}

---

### Admin APIs
- GET /user_list
- POST /change_role?username={string}&user_role={int} (0: normal user, 1: admin)
- POST /ban_user?username={string}&restrict_due={datetime} (restrict_due format: Year-Month-Day Hour:Minute:Second)

---

### Books APIs
- GET / : main page (not finished)
- GET /books/search?query={string} : search books by authors or books name
- GET /books/filter : filter books
> Params (no param is mandatory):
  { "genres": strings (each string separated by a comma),
    "sort_by_year": 'asc'/'des',
    "min_rating": int,
    "min_pages": int,
    "max_pages": int }

- GET /books?book_id={int} : get detail info of a book
- POST /books : post a new book (admin only)
> JSON structure:
  { "title": string (mandatory),
    "translator": string,
    "cover": string,
    "page_count": int (mandatory),
    "public_year": int (mandatory),
    "content": string (mandatory),
    "descript": string (mandatory),
    "republish_count": int,
    "genres": string LIST (mandatory),
    "authors": int LIST (for author_id) (mandatory) }

- PUT /books : change detail for a book (admin only)
> JSON structure: same as above, plus "book_id" (POST /books), no field is mandatory
- DELETE /books?book_id={int}

---

#### Bookmarks and Notes APIs
- GET /my_bookmark?book_id={int} : get bookmark or note
- POST /my_bookmark?bm_name={"bookmark"/"note"}&state
> JSON structure (for update bookmark):
  { "book_id": int (mandatory),
    "line_pos": int }
> JSON structure (for update note):
  { "book_id": int (mandatory),
    "content": string }
- DELETE /my_bookmark?book_id={int}&bm_name={"bookmark"/"note"} : delete bookmark or note

---

#### Authors APIs
- GET /authors/search?query={string}
- GET /authors?author_id={int}
- POST /authors
> JSON structure:
  { "author_name": string (mandatory),
    "bio": string,
    "social_account": string,
    "website": string,
    "profile_pic": string,
    "quote": string }
- POST /subscribe?author_id={int}
- DELETE /subscribe?author_id={int} : unsubscribe