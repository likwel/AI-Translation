from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, jsonify
from datetime import datetime, date, time
from flask_login import LoginManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///translations.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

class Translation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text_origin = db.Column(db.String(255))
    # text_target = db.Column(db.String(255))
    langue_origin = db.Column(db.String(255))
    langue_target = db.Column(db.String(255))
    translated_text = db.Column(db.String(255))
    translated_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<Translation {self.id}>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)


# Exécutez db.create_all() pour créer les tables dans la base de données
db.create_all()
