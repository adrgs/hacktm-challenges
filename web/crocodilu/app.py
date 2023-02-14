from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from database import db, User
from auth import register, login, logout

import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crocodilu.db'
app.config['SECRET_KEY'] = os.urandom(32)

login_manager = LoginManager()
login_manager.init_app(app)

db.init_app(app)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def index():
    if current_user.is_authenticated:
        return f'Hello {current_user.name}'
    else:
        return f'Hello guest'


app.add_url_rule('/register', methods=['GET', 'POST'], view_func=register)
app.add_url_rule('/login', methods=['GET', 'POST'], view_func=login)
app.add_url_rule('/logout', view_func=logout)

if __name__ == '__main__':
    app.run(port=5001, debug=True)