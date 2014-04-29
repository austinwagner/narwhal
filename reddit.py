from httplib2 import Http
from oauth2client.anyjson import simplejson
import logging
from datetime import datetime, timedelta
import time

logger = logging.getLogger(__name__)


class RedditRateLimiter(object):
    def __init__(self):
        self.last_call = datetime.min
        self.rate = timedelta(seconds=2)

    def get(self, credentials, action):
        http = Http()
        http = credentials.authorize(http)
        headers = {
            'Authorization': 'bearer ' + credentials.access_token
        }

        time_diff = datetime.now() - self.last_call
        if time_diff < self.rate:
            time.sleep(time_diff.total_seconds())

        headers, content = http.request('https://oauth.reddit.com' + action, headers=headers)
        return simplejson.loads(content)

