from flask_script import Manager
import cPickle
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
    post_cursor = db.cursor()
    pm_cursor = db.curosr()
    send_post_update_cursor = db.cursor()

    account_cursor.execute(
        'SELECT g.credentials as google_credentials, r.credentials as reddit_credentials, g.id as google_id, '
        's.send_nsfw, s.send_pm, s.nsfw_overrides, s.post_limit, r.id as reddit_id, s.group_posts '
        'FROM "GoogleAccount" g INNER JOIN "RedditAccount" r ON g.id = r.google_id '
        'INNER JOIN "AccountSettings" s ON g.id = s.google_id')

    for row in account_cursor:
        logger.info('Sending new posts for Google user {0:s} for Reddit ID {1:s}'.format(row.google_id, row.reddit_id))
        google_credentials = cPickle.loads(str(row.google_credentials))
        reddit_credentials = cPickle.loads(str(row.reddit_credentials))
        frontpage = reddit.get(reddit_credentials, '/hot.json?limit=' + str(row.post_limit))['data']['children']

        posts = {post['data']['id']: post['data'] for post in frontpage
                 if should_send_post(post['data'], row.send_nsfw, row.nsfw_overrides)}

        post_cursor.execute('SELECT i.id FROM UNNEST(%s) AS i(id) LEFT JOIN "SentPost" s ON i.id = s.post_id '
                            'WHERE s.post_id IS NULL', (posts.keys(),))
        post_count = 0 if post_cursor.rowcount == -1 else post_cursor.rowcount

        pm_count = 0
        if row.send_pm:
            inbox = reddit.get(reddit_credentials, '/message/inbox.json')['data']['children']
            pms = {pm['data']['id']: pm['data'] for pm in inbox
                   if pm['data'].get('new', False) and pm['data'].get('name', '').split('_', 1)[0] == 't4'}
            pm_cursor.execute('SELECT i.id '
                              'FROM UNNEST(%s) AS i(id) LEFT JOIN "SentPrivateMessage" s ON i.id = s.pm_id '
                              'WHERE s.pm_id IS NULL', (pms.keys(),))
            pm_count = 0 if pm_cursor.rowcount == -1 else pm_cursor.rowcount

        send_notification = pm_count + post_count == 1 or not row.group_posts

        bundle_id = uuid1().hex
        for post_id in post_cursor:
            add_post_to_timeline(google_credentials, posts[post_id[0]], bundle_id, send_notification)
            send_post_update_cursor.execute(
                'INSERT INTO "SentPost" (google_id, post_id) VALUES (%s,%s)', (row.google_id, post_id[0]))
            db.commit()

        if row.send_pm:
            for pm_id in pm_cursor:
                add_pm_to_timeline(google_credentials, pms[pm_id[0]], bundle_id, send_notification)
                send_post_update_cursor.execute(
                    'INSERT INTO "SentPrivateMessage" (google_id, pm_id) VALUES (%s,%s)', (row.google_id, pm_id[0]))
                db.commit()

        if row.group_posts and post_count + pm_count > 1:
            send_bundle_cover(google_credentials, bundle_id, post_count, pm_count, row.send_pm)

        logger.info('Sent {0:d} posts and {1:d} PMs'.format(post_count, pm_count))


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
            '<img src="http://www.redditstatic.com/about/assets/reddit-alien.png" width="158" height="220">'
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