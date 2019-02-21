from app import db
from hashutils import make_pw_hash

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120))
    body = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __init__(self, title, body, owner):
        self.title = title
        self.body = body
        self.owner = owner

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.VARCHAR(120), unique=True)
    pw_hash = db.Column(db.VARCHAR(120))
    blog = db.relationship('Blog', backref='owner')
    
    def __init__(self, username, password):
        self.username = username
        self.pw_hash = make_pw_hash(password)