from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
import mysql.connector

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="dtd2002",
    port="3308",
    database="w22g7_geek"
)

# app = Flask(__name__, template_folder=".\\build")
app = Flask(__name__)

app.config.from_pyfile('config/config.py')
app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
CORS(app, supports_credentials=True)

jwt = JWTManager(app)
bcryptPS = Bcrypt(app)

db = SQLAlchemy()
db.init_app(app)
