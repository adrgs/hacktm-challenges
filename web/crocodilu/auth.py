from database import db, User
from flask import Flask, request, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re


def is_valid_email(email: str) -> bool:
    if not email:
        return False
    email_pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")
    return email_pattern.match(email) is not None


def register():
    if request.method != 'POST':
        return render_template('register.html')

    name = request.form['name'].strip()
    email = request.form['email'].strip().lower()
    password = request.form['password']

    if not name or not email or not password:
        return render_template('register.html', error='Please fill all fields')

    if not is_valid_email(email):
        return render_template('register.html', error='Invalid email')

    if User.query.filter_by(email=email).first():
        return render_template('register.html', error='Email already exists')
    user = User(name=name,
                email=email,
                password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('login'))


def login():
    if request.method != 'POST':
        return render_template('login.html')

    email = request.form['email'].strip().lower()
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for('index'))
    else:
        return render_template('login.html', error='Invalid email or password')


@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))