# Copyright (c) 2014, Austin Wagner
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
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

from flask_script import Manager
import cPickle
from oauth2client.client import AccessTokenRefreshError
from reddit import RedditRateLimiter
from narwhal import app, get_db
from httplib2 import Http
from apiclient import discovery
import re
import logging
from uuid import uuid1


logger = logging.getLogger(__name__)
manager = Manager(app)


# Just check for common extensions
image_ext_regex = re.compile(r'\.(jpe?g|gif|png)$', re.IGNORECASE)
imgur_regex = re.compile(
    r'^(?:https?://)?(?:(?:www|i)\.)?imgur\.com/(?P<type>a/|gallery/)?(?P<id>\w+)(?:\.\w+)?', re.IGNORECASE)
imgur_album_regex = re.compile('<meta name="twitter:image0:src" content="(?P<url>[^"]+)"/>', re.IGNORECASE)


@manager.command
def test():
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT * FROM "SentPost"')
    print(cur.rowcount)


@manager.command
def send_updates():
    reddit = RedditRateLimiter()

    db = get_db()
    account_cursor = db.cursor()
    cursor = db.cursor()

    account_cursor.execute(
        'SELECT t1.*, s.send_nsfw, s.send_pm, s.nsfw_overrides, s.post_limit, s.group_posts FROM '
        '(SELECT g.id AS google_id, g.credentials AS google_credentials, '
        'array_agg(r.credentials) AS reddit_credentials, array_agg(r.id) AS reddit_ids, '
        'array_agg(r.name) AS reddit_names, g.name AS google_name '
        'FROM "GoogleAccount" g INNER JOIN "RedditAccount" r ON g.id = r.google_id '
        'GROUP BY g.id, g.credentials '
        'HAVING COUNT(r.id) > 0) t1 '
        'INNER JOIN "AccountSettings" s ON t1.google_id = s.google_id')

    for row in account_cursor:
        logger.info('Sending new posts for Google user {0:s}'.format(row.google_name))
        google_credentials = cPickle.loads(str(row.google_credentials))

        posts = {}
        pms = {}
        for i in xrange(len(row.reddit_credentials)):
            pickled_reddit_credentials = row.reddit_credentials[i]
            reddit_id = row.reddit_ids[i]
            reddit_name = row.reddit_names[i]
            logger.info('Getting new posts for reddit user {0:s}'.format(reddit_name))

            try:
                reddit_credentials = cPickle.loads(str(pickled_reddit_credentials))
                frontpage = reddit.get(reddit_credentials, '/hot.json?limit=' + str(row.post_limit))['data']['children']

                for post in (p['data'] for p in frontpage):
                    if should_send_post(post, row.send_nsfw, row.nsfw_overrides):
                        posts[post['id']] = post

                cursor.execute('SELECT post_id FROM "SentPost" '
                               'WHERE post_id=ANY(%s) AND google_id=%s', (posts.keys(), row.google_id))
                for post_id in (r.post_id for r in cursor):
                    del posts[post_id]

                if row.send_pm:
                    inbox = reddit.get(reddit_credentials, '/message/inbox.json')['data']['children']
                    for pm in (p['data'] for p in inbox):
                        if pm.get('new', False) and pm.get('name', '').split('_', 1)[0] == 't4':
                            pms[pm['id']] = pm

                    cursor.execute('SELECT pm_id FROM "SentPrivateMessage" '
                                   'WHERE pm_id=ANY(%s) AND google_id=%s', (pms.keys(), row.google_id))
                    for pm_id in (r.pm_id for r in cursor):
                        del pms[pm_id]
            except KeyError as e:
                if e.args[0] == 'access_token':
                    logger.warn(
                        'Failed to refresh a reddit token for reddit account {0:s} of Google user {1:s}. Removing...'
                        .format(reddit_name, row.google_name))
                    cursor.execute('DELETE FROM "RedditAccount" WHERE id=%s AND google_id=%s',
                                   (reddit_id, row.google_id))
                    db.commit()
                else:
                    raise

        send_notification = len(posts) + len(pms) == 1 or not row.group_posts
        bundle_id = uuid1().hex

        try:
            for post_id, post in posts.iteritems():
                add_post_to_timeline(google_credentials, post, bundle_id, send_notification)
                cursor.execute('INSERT INTO "SentPost" (google_id, post_id) VALUES (%s,%s)', (row.google_id, post_id))
                db.commit()

            for pm_id, pm in pms.iteritems():
                add_pm_to_timeline(google_credentials, pm, bundle_id, send_notification)
                cursor.execute('INSERT INTO "SentPrivateMessage" (google_id, pm_id) VALUES (%s,%s)',
                               (row.google_id, pm_id))
                db.commit()

            if row.group_posts and len(posts) + len(pms) > 1:
                send_bundle_cover(google_credentials, bundle_id, len(posts), len(pms), row.send_pm)
        except AccessTokenRefreshError:
            logger.warn(
                'Failed to refresh token for Google user {0:s}. Removing...'
                .format(row.google_name))
            cursor.execute('DELETE FROM "GoogleAccount" WHERE id=%s', (row.google_id,))
            db.commit()
            continue

        logger.info('Sent {0:d} posts and {1:d} PMs'.format(len(posts), len(pms)))


def add_post_to_timeline(credentials, post, bundle_id, send_notification):
    timeline_item = {
        'text': post['title'],
        'speakableType': 'Reddit post',
        'canonicalUrl': post['url'],
        'isBundleCover': False,
        'bundleId': bundle_id,
        'html': generate_post_html(post, post['subreddit']),
        'menuItems': [
            {
                'action': 'OPEN_URI',
                'payload': post['url']
            },
            {
                'action': 'READ_ALOUD'
            }
        ]
    }

    if not post['is_self']:
        timeline_item['menuItems'].insert(1, {
            'action': 'OPEN_URI',
            'payload': 'http://www.reddit.com' + post['permalink'],
            'values': [{'displayName': 'View comments'}]
        })
    else:
        timeline_item['menuItems'][0]['values'] = [{'displayName': 'View post'}]

    if send_notification:
        timeline_item['notification'] = {'level': 'DEFAULT'}

    logger.debug('Adding post to timeline: {0:s}, bundle: {1:s}'.format(str(timeline_item), bundle_id))
    http = credentials.authorize(Http())
    service = discovery.build('mirror', 'v1', http=http)
    service.timeline().insert(body=timeline_item).execute()


def generate_post_html(post, subreddit):
    url = None if post['is_self'] else get_image_url(post)

    if url is None:
        html = '<article>'
    else:
        html = ('<article class="photo"><img src="' + url + '" style="width: 100%"/>'
                '<div class="overlay-gradient-tall-dark"/>')

    html += ('<section><p class="text-auto-size">' + post['title'] + '</p></section>'
             '<footer>/r/' + subreddit + '</footer></article>')

    return html


def get_image_url(post):
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT url FROM "ImageUrlCache" WHERE post_id=%s', (post['id'],))
    url = cur.fetchone()
    if url is not None:
        logger.debug('Cache hit for {0:s}'.format(post['id']))
        return url[0]

    logger.debug('Cache miss for {0:s}'.format(post['id']))
    imgur_match = imgur_regex.search(post['url'])
    if imgur_match:
        if imgur_match.group('type') is not None:
            url = get_imgur_cover_url(post['url'])
        else:
            # Extension doesn't matter to Imgur but it needs to have one
            # 'l' indicates large thumbnail
            url = 'https://i.imgur.com/' + imgur_match.group('id') + 'l.jpg'
    elif image_ext_regex.search(post['url']):
        url = post['url']
    else:
        url = None

    cur.execute('INSERT INTO "ImageUrlCache" (post_id, url) VALUES (%s,%s)', (post['id'], url))
    db.commit()
    return url


def get_imgur_cover_url(album_url):
    http = Http()
    resp, content = http.request(album_url)
    if resp != 200:
        return None

    match = imgur_album_regex.search(content)
    if not match:
        return None

    return match.group('url_no_ext') + 'l.jpg'


def add_pm_to_timeline(credentials, pm, bundle_id, send_notification):
    timeline_item = {
        'title': pm['subject'],
        'text': pm['body'],
        'html': generate_pm_html(pm),
        'speakableType': 'Reddit PM',
        'isBundleCover': False,
        'bundleId': bundle_id,
        'menuItems': [
            {
                'action': 'READ_ALOUD'
            },
            {
                'action': 'OPEN_URI',
                'payload': 'http://www.reddit.com/message/messages/' + pm['id'],
                'values': [{'displayName': 'View in Browser'}]
            }
        ]
    }

    if send_notification:
        timeline_item['notification'] = {'level': 'DEFAULT'}

    logger.debug('Adding PM to timeline: {0:s}, bundle: {1:s}'.format(str(timeline_item), bundle_id))
    http = credentials.authorize(Http())
    service = discovery.build('mirror', 'v1', http=http)
    service.timeline().insert(body=timeline_item).execute()


def generate_pm_html(pm):
    return ('<article class="author">'
            '<div class="overlay-full"/>'
            '<header>'
            '<img src="http://i.imgur.com/MSuFUq6.png"/>'
            '<h1>' + pm['author'] + '</h1>'
            '<h2>' + pm['subject'] + '</h2>'
            '</header><section><p class="text-auto-size">' + pm['body'] + '</p></section></article>')


def send_bundle_cover(credentials, bundle_id, post_count, pm_count, send_pm):
    timeline_item = {
        'html': generate_cover_html(post_count, pm_count, send_pm),
        'isBundleCover': True,
        'bundleId': bundle_id,
        'notification': {
            'level': 'DEFAULT'
        }
    }

    logger.debug('Adding cover to timeline: {0:s}'.format(bundle_id))
    http = credentials.authorize(Http())
    service = discovery.build('mirror', 'v1', http=http)
    service.timeline().insert(body=timeline_item).execute()


def generate_cover_html(post_count, pm_count, send_pm):
    return ('<article style="left: 0px; visibility: visible;">'
            '<section><div class="layout-figure"><div class="align-center">'
            '<img src="' + app.config['BUNDLE_COVER_LOGO_URL'] + '" width="190" height="190">'
            '</div><div><div class="text-large">'
            '<p class="green">' + pluralize_new('Post', post_count) + '</p>'
            '<p class="red">' + pluralize_new('PM', pm_count) if send_pm else '' + '</p>'
            '</div></div></div></section></article>')


def pluralize_new(item_type, amount):
    return (
        ('No' if amount == 0 else str(amount)) +
        ' New ' + item_type + ('' if amount == 1 else 's'))


def should_send_post(post, send_nsfw, nsfw_overrides):
    nsfw_overrides = [x.lower() for x in nsfw_overrides]
    return not ((not send_nsfw and post['over_18'] and post['subreddit'].lower() not in nsfw_overrides)
                or post['stickied'])


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    manager.run()