from init_app import db
from src.const import DATETIME_FORMAT


class Notifications(db.Model):
    noti_id = db.Column(db.Integer, primary_key=True)
    noti_text = db.Column(db.String)
    noti_date = db.Column(db.DateTime)
    trigger_source = db.Column(db.String)
    username = db.Column(db.String, db.ForeignKey('users.username'))

    def __init__(self, username, noti_text, noti_date, trigger_source):
        self.noti_text = noti_text
        self.noti_date = noti_date
        self.trigger_source = trigger_source
        self.username = username

    def get_json(self):
        return {
            "noti_id": self.noti_id,
            "noti_date": self.noti_date.strftime(DATETIME_FORMAT),
            "noti_text": self.noti_text,
            "trigger_souce": self.trigger_source
        }
