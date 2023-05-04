import sqlalchemy as sql
from src.utils import get_current_datetime
from init_app import db


class States(db.Model):
    state = db.Column(sql.String, primary_key=True)
    created_date = db.Column(sql.DateTime)

    def __init__(self, state):
        self.state = state
        self.created_date = get_current_datetime()
