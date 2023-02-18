from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from database import db, User
from auth import register, login, logout, request_code, reset_password
from redis import Redis

import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crocodilu.db'
app.config['SECRET_KEY'] = os.urandom(32)

login_manager = LoginManager()
login_manager.init_app(app)

db.init_app(app)

redis = Redis(host=os.getenv('REDIS_HOST', 'localhost'),
              port=int(os.getenv('REDIS_PORT', '6379')),
              db=0)
redis.set('queued_count', 0)
redis.set('proceeded_count', 0)

with app.app_context():
    db.create_all()
    # create admin user
    if not User.query.filter(User.email.like('admin@hacktm.ro')).first():
        user = User(name='admin',
                    email='admin@hacktm.ro',
                    password=generate_password_hash(
                        os.getenv('ADMIN_PASSWORD', 'admin')),
                    active=True,
                    admin=True)
        db.session.add(user)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def index():
    return render_template('index.html')


app.add_url_rule('/request_code',
                 methods=['GET', 'POST'],
                 view_func=request_code)
app.add_url_rule('/reset_password',
                 methods=['GET', 'POST'],
                 view_func=reset_password)
app.add_url_rule('/register', methods=['GET', 'POST'], view_func=register)
app.add_url_rule('/login', methods=['GET', 'POST'], view_func=login)
app.add_url_rule('/logout', view_func=logout)

if __name__ == '__main__':
    app.run(port=5001, debug=True)