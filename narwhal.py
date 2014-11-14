# Copyright (c) 2014, Austin Wagner
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.

from flask import Flask, redirect, request, session, render_template, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from oauth2client.client import OAuth2WebServerFlow
from sqlalchemy.exc import IntegrityError
from OAuth2RedditFlow import OAuth2RedditFlow
from random import SystemRandom
import string
from reddit import RedditRateLimiter
import logging
import logging.config
import os.path
from datetime import datetime
from flask.ext.kvsession import KVSessionExtension
from simplekv.db.sql import SQLAlchemyStore
import pytz
from passlib.hash import pbkdf2_sha512


logging_conf = '/etc/narwhal/logging.conf'
if os.path.exists(logging_conf):
    logging.config.fileConfig(logging_conf, disable_existing_loggers=False)

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)
kv_store = SQLAlchemyStore(db.engine, db.metadata, 'kvstore')
KVSessionExtension(kv_store, app)
random = SystemRandom()


class EmailError(Exception):
    pass


def send_verification_email():
    pass


def generate_verification_token():
    return ''.join(random.choice(string.ascii_uppercase + string.digits)
                   for _ in xrange(12))


class NarwhalAccount(db.Model):
    __tablename__ = 'NarwhalAccount'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    password = db.Column(db.Text)
    verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.Text)
    created_at = db.Column(db.DateTime(True))
    settings = db.relationship('AccountSettings', uselist=False, backref='narwhal_account',
                               cascade='all, delete, delete-orphan')
    google_account = db.relationship('GoogleAccount', uselist=False, backref='narwhal_account',
                                     cascade='all, delete, delete-orphan')
    reddit_accounts = db.relationship('RedditAccount', backref='narwhal_account', cascade='all, delete, delete-orphan')
    sent_posts = db.relationship('SentPost', lazy='dynamic', cascade='all, delete, delete-orphan')
    sent_pms = db.relationship('SentPrivateMessage', lazy='dynamic', cascade='all, delete, delete-orphan')

    def __init__(self, email, unhashed_password):
        self.email = email
        # passlib stores the salt and hashing method as part of the string so we don't need to store those separately
        self.password = pbkdf2_sha512.encrypt(unhashed_password, salt_size=64, rounds=app.config['HASH_ROUNDS'])
        self.created_at = datetime.now(pytz.utc)
        self.verification_token = generate_verification_token()
        print(self.id)

    def password_matches(self, unhashed_password):
        return pbkdf2_sha512.verify(unhashed_password, self.password)


class PasswordReset(db.Model):
    __tablename__ = 'PasswordReset'
    narwhal_id = db.Column(db.Integer, db.ForeignKey('NarwhalAccount.id'), primary_key=True)
    token = db.Column(db.Text)
    expires = db.Column(db.DateTime(True))


class GoogleAccount(db.Model):
    __tablename__ = 'GoogleAccount'
    narwhal_id = db.Column(db.Integer, db.ForeignKey('NarwhalAccount.id'), primary_key=True)
    id = db.Column(db.String(80))
    credentials = db.Column(db.PickleType)
    failed_at = db.Column(db.DateTime(True))

    def __init__(self, narwhal_id, google_id, credentials):
        self.narwhal_id = narwhal_id
        self.id = google_id
        self.credentials = credentials


class RedditAccount(db.Model):
    __tablename__ = 'RedditAccount'
    id = db.Column(db.String(80), primary_key=True)
    narwhal_id = db.Column(db.Integer, db.ForeignKey('NarwhalAccount.id'), primary_key=True)
    name = db.Column(db.String(256))
    credentials = db.Column(db.PickleType)
    failed_at = db.Column(db.DateTime(True))

    def __init__(self, reddit_id, narwhal_id, credentials, name):
        self.id = reddit_id
        self.narwhal_id = narwhal_id
        self.credentials = credentials
        self.name = name


class AccountSettings(db.Model):
    __tablename__ = 'AccountSettings'
    narwhal_id = db.Column(db.Integer, db.ForeignKey('NarwhalAccount.id'), primary_key=True)
    send_nsfw = db.Column(db.Boolean, default=False)
    send_pm = db.Column(db.Boolean, default=True)
    nsfw_overrides = db.Column(db.String(500), default='')
    post_limit = db.Column(db.Integer, default=15)
    group_posts = db.Column(db.Boolean, default=True)

    def __init__(self, narwhal_id):
        self.narwhal_id = narwhal_id


class SentPost(db.Model):
    __tablename__ = 'SentPost'
    narwhal_id = db.Column(db.Integer, db.ForeignKey('NarwhalAccount.id'), primary_key=True)
    post_id = db.Column(db.String(20), primary_key=True)

    def __init__(self, narwhal_id, post_id):
        self.narwhal_id = narwhal_id
        self.post_id = post_id


class SentPrivateMessage(db.Model):
    __tablename__ = 'SentPrivateMessage'
    narwhal_id = db.Column(db.Integer, db.ForeignKey('NarwhalAccount.id'), primary_key=True)
    pm_id = db.Column(db.String(20), primary_key=True)

    def __init__(self, narwhal_id, pm_id):
        self.narwhal_id = narwhal_id
        self.pm_id = pm_id


class ImageUrlCache(db.Model):
    __tablename__ = 'ImageUrlCache'
    post_id = db.Column(db.String(20), primary_key=True)
    url = db.Column(db.String(512))
    cached_at = db.Column(db.DateTime(True))

    def __init__(self, post_id, url):
        self.post_id = post_id
        self.url = url
        self.cached_at = datetime.now(pytz.utc)


def create_oauth_redirect_uri(location):
    return ('https://' if app.config['HTTPS'] else 'http://') + app.config['HOST_ADDRESS'] + '/' + location


reddit_flow = OAuth2RedditFlow(client_id=app.config['REDDIT_CLIENT_ID'],
                               client_secret=app.config['REDDIT_CLIENT_SECRET'],
                               redirect_uri=create_oauth_redirect_uri('reddit_authorize_callback'),
                               scope=['identity', 'privatemessages', 'read'],
                               user_agent=app.config['USER_AGENT'])
google_flow = OAuth2WebServerFlow(client_id=app.config['GOOGLE_CLIENT_ID'],
                                  client_secret=app.config['GOOGLE_CLIENT_SECRET'],
                                  redirect_uri=create_oauth_redirect_uri('google_authorize_callback'),
                                  scope=['profile',
                                         'https://www.googleapis.com/auth/glass.timeline'],
                                  user_agent=app.config['USER_AGENT'])
reddit = RedditRateLimiter()


@app.route('/')
def index():
    return render_template('welcome.html')


@app.route('/logout')
def logout():
    del session['user_id']
    return redirect(url_for('index'))


def generate_auth_url(flow):
    state = generate_csrf_token()
    session['state'] = state
    auth_url = flow.step1_get_authorize_url() + '&state=' + state
    if flow is reddit_flow:
        auth_url += '&duration=permanent'
    return auth_url


def validate_authorization(name):
    if request.args['state'] != session['state']:
        logger.warn('{0:s}: {3:s} authorization callback csrf mismatch. Got "{1:s}", expected "{2:s}"'
                    .format(request.remote_addr, request.args['state'], session['state'], name))
        abort(401)


# TODO: Implement remember cookie
@app.route('/login', methods=['GET', 'POST'])
def authenticate():
    error = False
    if request.method == 'POST':
        if request.form['csrf_token'] != session['csrf_token']:
            logger.warn('{0:s}: Settings page csrf mismatch. Got "{1:s}", expected "{2:s}"'
                        .format(request.remote_addr, request.form['csrf_token'], session['csrf_token']))
            return abort(401)

        if request.form['action'] == 'login':
            acct = NarwhalAccount.query.filter_by(email=request.form['email']).first()
            if acct is None or not acct.password_matches(request.form['password']):
                error = True
            elif not acct.verified:
                session['account_id'] = acct.id
                return redirect(url_for('verify_email'))
            else:
                session['account_id'] = acct.id
                return reddit_account_login(acct)
        else:
            session['email'] = request.form['email']
            session['password'] = request.form['password']
            return redirect(url_for('create_account'))

    session['csrf_token'] = generate_csrf_token()
    return render_template('login.html', error=error, csrf_token=session['csrf_token'])


@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    error = None
    if request.method == 'POST':
        if request.form['csrf_token'] != session['csrf_token']:
            logger.warn('{0:s}: Account creation csrf mismatch. Got "{1:s}", expected "{2:s}"'
                        .format(request.remote_addr, request.form['csrf_token'], session['csrf_token']))
            return abort(401)

        try:
            if request.form['password'] != request.form['password_verify']:
                error = 'password_mismatch'
            else:
                acct = NarwhalAccount(request.form['email'], request.form['password'])

                with db.session.begin():
                    db.session.add(acct)
                    db.session.commit()
                    db.session.add(AccountSettings(acct.id))
                    db.session.commit()

                session['account_id'] = acct.id
                return redirect(url_for('verify_email'))
        except IntegrityError:
            error = 'email_taken'
        except EmailError:  # TODO: Restrict to email sending errors
            error = 'invalid_email'

    session['csrf_token'] = generate_csrf_token()
    return render_template('create_account.html', email=session['email'],
                           password=session['password'], csrf_token=session['csrf_token'],
                           error=error)


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    try:
        acct = NarwhalAccount.query.filter_by(id=session['account_id']).first()
        if acct.verified:
            return reddit_account_login(acct)
    except (KeyError, AttributeError):
        return redirect(url_for('authenticate'))

    error = False
    if request.method == 'POST':
        if request.form['csrf_token'] != session['csrf_token']:
            logger.warn('{0:s}: Email verification csrf mismatch. Got "{1:s}", expected "{2:s}"'
                        .format(request.remote_addr, request.form['csrf_token'], session['csrf_token']))
            return abort(401)

        if request.form['action'] == 'resend':
            pass
        else:
            if acct.verification_token != request.form['token']:
                error = True
            else:
                acct.verified = True
                db.session.commit()
                return reddit_account_login(acct)

    session['csrf_token'] = generate_csrf_token()
    return render_template('verify_email.html', csrf_token=session['csrf_token'], error=error)


def reddit_account_login(acct):
    if len(acct.reddit_accounts) == 0:
        reddit_auth_url = generate_auth_url(reddit_flow)
        logger.info('{0:s}: Reddit authorization redirect to {1:s}'.format(request.remote_addr, reddit_auth_url))
        return redirect(reddit_auth_url)
    else:
        return google_account_login(acct)


def google_account_login(acct):
    if acct.google_account is None:
        google_auth_url = generate_auth_url(google_flow)
        logger.info('{0:s}: Google authorization redirect to {1:s}'.format(request.remote_addr, google_auth_url))
        return redirect(google_auth_url)
    else:
        return redirect(url_for('settings'))


@app.route('/google_authorize_callback')
def google_authorize_callback():
    validate_authorization('google')

    credentials = google_flow.step2_exchange(request.args)
    user_id = credentials.id_token['id']

    acct = NarwhalAccount.query.filter_by(id=session['account_id']).first()

    logger.debug('{0:s}: Saving Google authorization for user {1:s}'.format(request.remote_addr, acct.email))
    google_account = GoogleAccount(acct.id, user_id, credentials)
    db.session.add(google_account)
    db.session.commit()

    logger.info('{0:s}: Redirect to /settings'.format(request.remote_addr))
    return redirect(url_for('settings'))


@app.route('/reddit_authorize_callback')
def reddit_authorize_callback():
    validate_authorization('reddit')

    if request.args.get('error') == 'access_denied':
        logger.warn('{0:s}: Access denied from reddit oauth'.format(request.remote_addr))
        return redirect(url_for('authenticate'))

    credentials = reddit_flow.step2_exchange(request.args)
    user = reddit.get(credentials, '/api/v1/me')

    acct = NarwhalAccount.query.filter_by(id=session['account_id']).first()

    try:
        reddit_account = RedditAccount(user['id'], acct.id, credentials, user['name'])
        db.session.add(reddit_account)
        db.session.commit()
    except IntegrityError:
        return redirect(url_for('settings') + '?account_error_message=Account already linked.')

    return redirect(url_for('settings'))


@app.route('/manage_reddit_account', methods=['POST'])
def manage_reddit_account():
    if request.form['csrf_token'] != session['csrf_token']:
        logger.warn('{0:s}: Settings page csrf mismatch. Got "{1:s}", expected "{2:s}"'
                    .format(request.remote_addr, request.form['csrf_token'], session['csrf_token']))
        return abort(401)

    if request.form['action'] == 'add':
        logger.info('{0:s}: Adding Reddit account'.format(request.remote_addr))
        state = generate_csrf_token()
        session['state'] = state
        reddit_auth_url = reddit_flow.step1_get_authorize_url() + '&state=' + state + '&duration=permanent'
        logger.info('{0:s}: Reddit authorization redirect to {1:s}'.format(request.remote_addr, reddit_auth_url))
        return redirect(reddit_auth_url)
    else:
        reddit_id = request.form['action'].split('_', 1)[1]
        logger.info('{0:s}: Removing Reddit account {1:s}'.format(request.remote_addr, reddit_id))
        RedditAccount.query.filter_by(id=reddit_id).delete()
        db.session.commit()
        return redirect(url_for('settings'))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    error_message = None
    if request.method == 'POST':
        logger.debug('{0:s}: Settings POSTed. Data: {1:s}'.format(request.remote_addr, str(request.form)))
        if request.form['csrf_token'] != session['csrf_token']:
            logger.warn('{0:s}: Settings page csrf mismatch. Got "{1:s}", expected "{2:s}"'
                        .format(request.remote_addr, request.form['csrf_token'], session['csrf_token']))
            abort(401)

        try:
            try:
                post_limit = int(request.form.get('post_limit', 25))
            except ValueError:
                raise ValueError('Post limit must be a number.')

            if post_limit < 1 or post_limit > 25:
                raise ValueError('Post limit must be between 1 and 25.')

            if len(request.form.get('nsfw_overrides', '')) > 500:
                raise ValueError('NSFW Overrides is limited to 500 characters.')

            account_settings = AccountSettings.query.filter_by(google_id=session['user_id']).first()
            account_settings.send_nsfw = request.form.get('send_nsfw') is not None
            account_settings.nsfw_overrides = request.form.get('nsfw_overrides', '')
            account_settings.send_pm = request.form.get('send_pm') is not None
            account_settings.group_posts = request.form.get('group_posts') is not None
            account_settings.post_limit = post_limit
            db.session.commit()
        except ValueError as e:
            error_message = str(e)

    if 'user_id' not in session:
        return redirect(url_for('index'))

    account = GoogleAccount.query.filter_by(id=session['user_id']).first()

    session['csrf_token'] = generate_csrf_token()
    return render_template('settings.html', accounts=account.reddit_accounts,
                           send_nsfw=account.settings.send_nsfw,
                           send_pm=account.settings.send_pm,
                           nsfw_overrides=account.settings.nsfw_overrides,
                           post_limit=account.settings.post_limit,
                           group_posts=account.settings.group_posts,
                           csrf_token=session['csrf_token'], error_message=error_message,
                           success_message=error_message is None and request.method == 'POST',
                           account_error_message=request.args.get('account_error_message'),
                           email=account.email)


@app.route('/privacy')
def privacy_policy():
    return render_template('privacy.html')


def generate_csrf_token():
    return ''.join(random.choice(string.ascii_uppercase + string.digits)
                   for _ in xrange(32))


@app.errorhandler(500)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(401)
def error_page(e):
    return render_template('error_page.html', error_code=e.code), e.code


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    app.run('0.0.0.0', port=65010, debug=True)
