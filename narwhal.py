from flask import Flask, redirect, request, session, render_template, make_response, g, url_for
from oauth2client.client import OAuth2WebServerFlow
from psycopg2._psycopg import IntegrityError
from OAuth2RedditFlow import OAuth2RedditFlow
import random
import string
import psycopg2
import cPickle
from reddit import RedditRateLimiter
import logging
import psycopg2.extras
from psycopg2 import errorcodes

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_pyfile('config.py')

reddit_flow = OAuth2RedditFlow(client_id=app.config['REDDIT_CLIENT_ID'],
                               client_secret=app.config['REDDIT_CLIENT_SECRET'],
                               redirect_uri='http://' + app.config['HOST_ADDRESS'] + '/reddit_authorize_callback',
                               scope=['identity', 'privatemessages', 'read'],
                               user_agent=app.config['USER_AGENT'])
google_flow = OAuth2WebServerFlow(client_id=app.config['GOOGLE_CLIENT_ID'],
                                  client_secret=app.config['GOOGLE_CLIENT_SECRET'],
                                  redirect_uri='http://' + app.config['HOST_ADDRESS'] + '/google_authorize_callback',
                                  scope=['profile',
                                         'https://www.googleapis.com/auth/glass.timeline'],
                                  user_agent=app.config['USER_AGENT'])
reddit = RedditRateLimiter()


def connect_db():
    return psycopg2.connect(
        host=app.config['DATABASE_HOST'],
        database=app.config['DATABASE_DATABASE'],
        user=app.config['DATABASE_USER'],
        password=app.config['DATABASE_PASSWORD'],
        cursor_factory=psycopg2.extras.NamedTupleCursor)


def get_db():
    if not hasattr(g, 'pgdb'):
        g.pgdb = connect_db()

    return g.pgdb


@app.teardown_appcontext
def close_db(_):
    if hasattr(g, 'pgdb'):
        g.pgdb.close()


@app.route('/')
def authenticate():
    state = generate_csrf_token()
    session['state'] = state
    google_auth_url = google_flow.step1_get_authorize_url() + '&state=' + state
    logger.info('Host: {0:s} - Google authorization redirect to {1:s}'.format(request.host, google_auth_url))
    return redirect(google_auth_url)


@app.route('/google_authorize_callback')
def google_authorize_callback():
    if request.args['state'] != session['state']:
        logger.warn('Host: {0:s} - Google authorization callback csrf mismatch. Got "{1:s}", expected "{2:s}"'
                    .format(request.host, request.args['state'], session['state']))
        return make_response('Invalid state parameter', 401)

    credentials = google_flow.step2_exchange(request.args)
    user_id = credentials.id_token['id']
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT COUNT(1) FROM "GoogleAccount" WHERE id=%s', (user_id,))
    if cur.fetchone()[0] == 0:
        logger.debug('Host: {0:s} - Saving Google authorization for user {1:s}'.format(request.host, user_id))
        cur.execute('INSERT INTO "GoogleAccount" (id, credentials) VALUES (%s,%s)',
                    (user_id, psycopg2.Binary(cPickle.dumps(credentials, -1))))
        cur.execute('INSERT INTO "AccountSettings" (google_id) VALUES (%s)', (user_id,))
        db.commit()
    else:
        logger.debug('Host: {0:s} - Found Google authorization for user {1:s}'.format(request.host, user_id))

    session['user_id'] = user_id

    cur.execute('SELECT COUNT(1) FROM "RedditAccount" WHERE google_id=%s', (user_id,))
    if cur.fetchone()[0] == 0:
        state = generate_csrf_token()
        session['state'] = state
        reddit_auth_url = reddit_flow.step1_get_authorize_url() + '&state=' + state + '&duration=permanent'
        logger.info('Host: {0:s} - Reddit authorization redirect to {1:s}'.format(request.host, reddit_auth_url))
        return redirect(reddit_auth_url)

    logger.info('Host: {0:s} - Redirect to /settings'.format(request.host))
    return redirect(url_for('settings'))


@app.route('/reddit_authorize_callback')
def reddit_authorize_callback():
    if request.args['state'] != session['state']:
        logger.warn('Host: {0:s} - Reddit authorization callback csrf mismatch. Got "{1:s}", expected "{2:s}"'
                    .format(request.host, request.args['state'], session['state']))
        return make_response('Invalid state parameter', 401)

    if request.args.get('error') == 'access_denied':
        return redirect(url_for('settings'))

    credentials = reddit_flow.step2_exchange(request.args)
    user = reddit.get(credentials, '/api/v1/me')

    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            'INSERT INTO "RedditAccount" (id, "name", google_id, credentials) VALUES (%s,%s,%s,%s)',
            (user['id'], user['name'], session['user_id'],
             psycopg2.Binary(cPickle.dumps(credentials, -1))))
        db.commit()
    except IntegrityError as e:
        if e.pgcode[:2] == errorcodes.CLASS_INTEGRITY_CONSTRAINT_VIOLATION:
            return redirect(url_for('settings') + '?account_error_message=Account already linked.')

        raise

    return redirect(url_for('settings'))


@app.route('/manage_reddit_account', methods=['POST'])
def manage_reddit_account():
    if request.form['csrf_token'] != session['csrf_token']:
        logger.warn('Host: {0:s} - Settings page csrf mismatch. Got "{1:s}", expected "{2:s}"'
                    .format(request.host, request.form['csrf_token'], session['csrf_token']))
        return make_response('Invalid CSRF token', 401)

    if request.form['action'] == 'add':
        logger.info('Host: {0:s} - Adding Reddit account'.format(request.host))
        state = generate_csrf_token()
        session['state'] = state
        reddit_auth_url = reddit_flow.step1_get_authorize_url() + '&state=' + state + '&duration=permanent'
        logger.info('Host: {0:s} - Reddit authorization redirect to {1:s}'.format(request.host, reddit_auth_url))
        return redirect(reddit_auth_url)
    else:
        reddit_id = request.form['action'].split('_', 1)[1]
        logger.info('Host: {0:s} - Removing Reddit account {1:s}'.format(request.host, reddit_id))
        db = get_db()
        cur = db.cursor()
        cur.execute('DELETE FROM "RedditAccount" WHERE id=%s', (reddit_id,))
        db.commit()
        return redirect(url_for('settings'))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    error_message = None
    print(request.method)
    if request.method == 'POST':
        logger.debug('Host: {0:s} - Settings POSTed. Data: {1:s}'.format(request.host, str(request.form)))
        if request.form['csrf_token'] != session['csrf_token']:
            logger.warn('Host: {0:s} - Settings page csrf mismatch. Got "{1:s}", expected "{2:s}"'
                        .format(request.host, request.form['csrf_token'], session['csrf_token']))
            return make_response('Invalid CSRF token', 401)

        try:
            try:
                post_limit = int(request.form.get('post_limit', 25))
            except ValueError:
                raise ValueError('Post limit must be a number.')

            if post_limit < 1 or post_limit > 25:
                raise ValueError('Post limit must be between 1 and 25.')

            db = get_db()
            cur = db.cursor()
            cur.execute('UPDATE "AccountSettings" '
                        'SET (send_nsfw, send_pm, nsfw_overrides, post_limit, group_posts) = '
                        '(%s,%s,%s,%s,%s) WHERE google_id=%s',
                        (request.form.get('send_nsfw') is not None, request.form.get('send_pm') is not None,
                         request.form.get('nsfw_overrides', '').split(), post_limit,
                         request.form.get('group_posts') is not None, session['user_id']))
            db.commit()
        except ValueError as e:
            error_message = str(e)

    if 'user_id' not in session:
        logger.info('Host: {0:s} - Redirect to authenticate'.format(request.host))
        return redirect(url_for('authenticate'))
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT "name", id FROM "RedditAccount" WHERE google_id=%s', (session['user_id'],))
    accounts = cur.fetchall()
    if len(accounts) == 0:
        logger.info('Host: {0:s} - Redirect to authenticate'.format(request.host))
        return redirect(url_for('authenticate'))

    cur.execute('SELECT send_nsfw, send_pm, nsfw_overrides, post_limit, group_posts '
                'FROM "AccountSettings" WHERE google_id=%s', (session['user_id'],))
    acct_settings = cur.fetchone()

    session['csrf_token'] = generate_csrf_token()
    return render_template('settings.html', accounts=accounts, send_nsfw=acct_settings.send_nsfw,
                           send_pm=acct_settings.send_pm, nsfw_overrides=acct_settings.nsfw_overrides,
                           post_limit=acct_settings.post_limit, group_posts=acct_settings.group_posts,
                           csrf_token=session['csrf_token'], error_message=error_message,
                           success_message=error_message is None and request.method == 'POST',
                           account_error_message=request.args.get('account_error_message'))


def generate_csrf_token():
    return ''.join(random.choice(string.ascii_uppercase + string.digits)
                   for _ in xrange(32))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    app.run('0.0.0.0', port=65010, debug=True)
