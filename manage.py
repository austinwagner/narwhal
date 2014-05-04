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

from flask_script import Manager
from oauth2client.client import AccessTokenRefreshError
from reddit import RedditRateLimiter
from narwhal import app, db, GoogleAccount, SentPost, SentPrivateMessage, ImageUrlCache
from httplib2 import Http
from apiclient import discovery
import re
import logging
import logging.config
from uuid import uuid1
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)
manager = Manager(app)


# Just check for common extensions
image_ext_regex = re.compile(r'\.(jpe?g|gif|png)$', re.IGNORECASE)
imgur_regex = re.compile(
    r'^(?:https?://)?(?:(?:www|i)\.)?imgur\.com/(?P<type>a/|gallery/)?(?P<id>\w+)(?:\.\w+)?', re.IGNORECASE)
imgur_album_regex = re.compile('<meta name="twitter:image0:src" content="(?P<url>[^"]+)"/>', re.IGNORECASE)


@manager.command
def init_db():
    db.create_all()


@manager.command
def send_updates(logging_config=None):
    if logging_config is None:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.config.fileConfig(logging_config, disable_existing_loggers=False)

    reddit = RedditRateLimiter()
    for account in GoogleAccount.query.all():
        logger.info('Sending new posts for Google user {0:s}'.format(account.email))

        posts = {}
        pms = {}
        for reddit_account in account.reddit_accounts:
            logger.info('Getting new posts for reddit user {0:s}'.format(reddit_account.name))

            try:
                frontpage = reddit.get(reddit_account.credentials, '/hot.json?limit=' +
                                       str(account.settings.post_limit))['data']['children']

                for post in (p['data'] for p in frontpage):
                    if should_send_post(post, account.settings.send_nsfw,
                                        account.settings.nsfw_overrides):
                        posts[post['id']] = post

                ids = account.sent_posts.filter(SentPost.post_id.in_(posts.keys())).all() if len(posts) > 0 else []
                for post_id in (r.post_id for r in ids):
                    del posts[post_id]

                if account.settings.send_pm:
                    inbox = reddit.get(reddit_account.credentials, '/message/inbox.json')['data']['children']
                    for pm in (p['data'] for p in inbox):
                        if pm.get('new', False) and pm.get('name', '').split('_', 1)[0] == 't4':
                            pms[pm['id']] = pm

                    ids = account.sent_pms.filter(SentPrivateMessage.pm_id.in_(pms.keys())).all() \
                        if len(pms) > 0 else []
                    for pm_id in (r.pm_id for r in ids):
                        del pms[pm_id]

                    if reddit_account.failed_at is not None:
                        reddit_account.failed_at = None
                        db.session.commit()
            except KeyError as e:
                if e.args[0] == 'access_token':
                    if reddit_account.failed_at is None:
                        reddit_account.failed_at = datetime.now(pytz.utc)
                        db.session.commit()
                    logger.warn(
                        'Failed to refresh a reddit token for reddit account {0:s} of Google user {1:s}. '
                        'First failure at: {2:s}'
                        .format(reddit_account.name, account.email, reddit_account.failed_at.isoformat()))
                else:
                    raise

        send_notification = len(posts) + len(pms) == 1 or not account.settings.group_posts
        bundle_id = uuid1().hex

        try:
            for post_id, post in posts.iteritems():
                add_post_to_timeline(account.credentials, post, bundle_id, send_notification)
                db.session.add(SentPost(account.id, post_id))
                db.session.commit()

            for pm_id, pm in pms.iteritems():
                add_pm_to_timeline(account.credentials, pm, bundle_id, send_notification)
                db.session.add(SentPrivateMessage(account.id, pm_id))
                db.session.commit()

            if account.settings.group_posts and len(posts) + len(pms) > 1:
                send_bundle_cover(account.credentials, bundle_id, len(posts), len(pms), account.settings.send_pm)

            if account.failed_at is not None:
                account.failed_at = None
                db.session.commit()
        except AccessTokenRefreshError:
            if account.failed_at is None:
                account.failed_at = datetime.now(pytz.utc)
                db.session.commit()
            logger.warn(
                'Failed to refresh token for Google user {0:s}. First failure at: {1:s}'
                .format(account.email, account.failed_at.isoformat()))
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
        html = u'<article>'
    else:
        html = (u'<article class="photo"><img src="{0:s}" style="width: 100%"/>'
                u'<div class="overlay-gradient-tall-dark"/>'.format(url))

    html += (
        u'<section><p class="text-auto-size">{0:s}</p></section>'
        u'<footer>/r/{1:s}</footer></article>'.format(post['title'], subreddit))

    return html


def get_image_url(post):
    url = ImageUrlCache.query.filter_by(post_id=post['id']).first()
    if url is not None:
        logger.debug('Cache hit for {0:s}'.format(post['id']))
        return url

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

    db.session.add(ImageUrlCache(post['id'], url))
    db.session.commit()
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
    return (
        u'<article class="author">'
        u'<div class="overlay-full"/>'
        u'<header>'
        u'<img src="http://i.imgur.com/MSuFUq6.png"/>'
        u'<h1>{0:s}</h1>'
        u'<h2>{1:s}</h2>'
        u'</header><section><p class="text-auto-size">{2:s}</p></section></article>'.format(
            pm['author'], pm['subject'], pm['body']
        ))


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
    return (
        u'<article style="left: 0px; visibility: visible;">'
        u'<section><div class="layout-figure"><div class="align-center">'
        u'<img src="{0:s}" width="190" height="190">'
        u'</div><div><div class="text-large">'
        u'<p class="green">{1:s}</p>'
        u'<p class="red">{2:s}</p>'
        u'</div></div></div></section></article>'.format(
            app.config['BUNDLE_COVER_LOGO_URL'],
            pluralize_new('Post', post_count),
            pluralize_new('PM', pm_count) if send_pm else ''
        ))


def pluralize_new(item_type, amount):
    return (
        ('No' if amount == 0 else str(amount)) +
        ' New ' + item_type + ('' if amount == 1 else 's'))


def should_send_post(post, send_nsfw, nsfw_overrides):
    nsfw_overrides = [x.lower() for x in nsfw_overrides.split()]
    return not ((not send_nsfw and post['over_18'] and post['subreddit'].lower() not in nsfw_overrides)
                or post['stickied'])


if __name__ == "__main__":
    manager.run()