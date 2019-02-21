from flask import Flask
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__, static_url_path='/static')
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://blogz:blogz@localhost:8889/blogz'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)
app.secret_key = 'blogz'