# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import render_template, redirect, request, url_for, Response
from flask_login import (
    current_user,
    login_user,
    logout_user
)
from flask_dance.contrib.github import github
import bcrypt
import requests
from apps import db, login_manager
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm, UpdateAccountForm
from apps.authentication.models import Users

from apps.authentication.util import verify_pass


SITE_NAME = "http://localhost:5000/"

@blueprint.route("/",methods=['GET','POST', "HEAD"])
def index():
    global SITE_NAME
    if request.method=="GET":
        resp = requests.get(f"{SITE_NAME}")
        excluded_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        headers = [(name, value) for (name, value) in  resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        return response
    elif request.method=="POST":
        resp = requests.post(f"{SITE_NAME}",data=request.data)
        excluded_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        return response


@blueprint.route("/<path:path>",methods=["GET","POST","HEAD","PUT"])
def submit(path): #error 'did not return a valid response'
    global SITE_NAME
    if request.method=="GET":
        resp = requests.get(f"{SITE_NAME}{path}")
        excluded_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        headers = [(name, value) for (name, value) in  resp.raw.headers.items() if name.lower()]
        response = Response(resp.content, resp.status_code, headers)
        return response
    elif request.method=="POST":
        resp = requests.post(f"{SITE_NAME}{path}",data=request.form)
        excluded_headers = ["content-length"]
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower()]
        response = Response(resp., resp.status_code, headers)
        return response
    elif request.method =="HEAD":
        resp = requests.head(f"{SITE_NAME}{path}")
        excluded_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower()]
        response = Response(status=resp.status_code, headers=headers)
        return response
    elif request.method=="PUT":
        resp = requests.put(f"{SITE_NAME}{path}",data=request.form)
        excluded_headers = ["content-length"]
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower()]
        response = Response(resp.path, resp.content, headers=headers, status=resp.status_code)
        print(response,resp.content, request.form)
        print(headers)
        return response





# Login & Registration

@blueprint.route("/github")
def login_github():
    """ Github login """
    if not github.authorized:
        return redirect(url_for("github.login"))

    res = github.get("/user")
    return redirect(url_for('home_blueprint.index'))

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:

        # read form data
        user_id  = request.form['username'] # we can have here username OR email
        password = request.form['password']

        # Locate user
        user = Users.find_by_username(user_id)

        # if user not found
        if not user:

            user = Users.find_by_email(user_id)

            if not user:
                return render_template( 'accounts/login.html',
                                        msg='Unknown User or Email',
                                        form=login_form)

        # Check the password
        if verify_pass(password, user.password):

            login_user(user)
            return redirect(url_for('authentication_blueprint.route_default'))

        # Something (user or pass) is not ok
        return render_template('accounts/login.html',
                               msg='Wrong user or password',
                               form=login_form)

    if not current_user.is_authenticated:
        return render_template('accounts/login.html',
                               form=login_form)
    return redirect(url_for('home_blueprint.index'))


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']

        # Check usename exists
        user = Users.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Username already registered',
                                   success=False,
                                   form=create_account_form)

        # Check email exists
        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Email already registered',
                                   success=False,
                                   form=create_account_form)

        # else we can create the user
        user = Users(**request.form)
        db.session.add(user)
        db.session.commit()

        # Delete user from session
        logout_user()

        return render_template('accounts/register.html',
                               msg='User created successfully.',
                               success=True,
                               form=create_account_form)

    else:
        return render_template('accounts/register.html', form=create_account_form)


@blueprint.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    if request.method == 'GET':
        user = Users.query.get(id)
        return render_template ('accounts/update.html', user=user)
    if request.method =='POST':
        user = Users.query.get(id)
        user.username = request.form['username']
        user.email = request.form['email']
        db.session.commit()
        return redirect(url_for('authentication_blueprint.usertbl'))
    

@blueprint.route('/usertbl', methods=['GET'])
def usertbl():
   if request.method == "GET":
         return render_template("home/user_tbl.html", query=Users.query.all())


@blueprint.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    if request.method =="POST":
        user = Users.query.get(id)
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('authentication_blueprint.usertbl', user=user))

@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login'))



# Errors

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500
