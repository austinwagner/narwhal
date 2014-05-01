# Copyright (C) 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oauth2client import util
from oauth2client.client import Flow, FlowExchangeError, OAuth2Credentials, _parse_exchange_token_response, \
    _extract_id_token, _update_query_params
import logging
import urllib
import httplib2
import datetime
from base64 import b64encode


logger = logging.getLogger(__name__)


class OAuth2RedditFlow(Flow):
    """Does the Web Server Flow for OAuth 2.0.

    OAuth2WebServerFlow objects may be safely pickled and unpickled.
    """

    @util.positional(4)
    def __init__(self, client_id, client_secret, scope,
                 redirect_uri=None,
                 user_agent=None,
                 auth_uri='https://ssl.reddit.com/api/v1/authorize',
                 token_uri='https://ssl.reddit.com/api/v1/access_token',
                 revoke_uri=None,
                 **kwargs):
        """Constructor for OAuth2WebServerFlow.

        The kwargs argument is used to set extra query parameters on the
        auth_uri. For example, the access_type and approval_prompt
        query parameters can be set via kwargs.

        Args:
          client_id: string, client identifier.
          client_secret: string client secret.
          scope: string or iterable of strings, scope(s) of the credentials being
            requested.
          redirect_uri: string, Either the string 'urn:ietf:wg:oauth:2.0:oob' for
            a non-web-based application, or a URI that handles the callback from
            the authorization server.
          user_agent: string, HTTP User-Agent to provide for this application.
          auth_uri: string, URI for authorization endpoint. For convenience
            defaults to Google's endpoints but any OAuth 2.0 provider can be used.
          token_uri: string, URI for token endpoint. For convenience
            defaults to Google's endpoints but any OAuth 2.0 provider can be used.
          revoke_uri: string, URI for revoke endpoint. For convenience
            defaults to Google's endpoints but any OAuth 2.0 provider can be used.
          **kwargs: dict, The keyword arguments are all optional and required
                            parameters for the OAuth calls.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scopes_to_string(scope)
        self.redirect_uri = redirect_uri
        self.user_agent = user_agent
        self.auth_uri = auth_uri
        self.token_uri = token_uri
        self.revoke_uri = revoke_uri
        self.params = {
            'access_type': 'offline',
            'response_type': 'code',
        }
        self.params.update(kwargs)

    @util.positional(1)
    def step1_get_authorize_url(self, redirect_uri=None):
        """Returns a URI to redirect to the provider.

        Args:
          redirect_uri: string, Either the string 'urn:ietf:wg:oauth:2.0:oob' for
            a non-web-based application, or a URI that handles the callback from
            the authorization server. This parameter is deprecated, please move to
            passing the redirect_uri in via the constructor.

        Returns:
          A URI as a string to redirect the user to begin the authorization flow.
        """
        if redirect_uri is not None:
            logger.warning(('The redirect_uri parameter for'
                            'OAuth2WebServerFlow.step1_get_authorize_url is deprecated. Please'
                            'move to passing the redirect_uri in via the constructor.'))
            self.redirect_uri = redirect_uri

        if self.redirect_uri is None:
            raise ValueError('The value of redirect_uri must not be None.')

        query_params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope,
        }
        query_params.update(self.params)
        return _update_query_params(self.auth_uri, query_params)

    @util.positional(2)
    def step2_exchange(self, code, http=None):
        """Exchanges a code for OAuth2Credentials.

        Args:
          code: string or dict, either the code as a string, or a dictionary
            of the query parameters to the redirect_uri, which contains
            the code.
          http: httplib2.Http, optional http instance to use to do the fetch

        Returns:
          An OAuth2Credentials object that can be used to authorize requests.

        Raises:
          FlowExchangeError if a problem occured exchanging the code for a
          refresh_token.
        """

        if not (isinstance(code, str) or isinstance(code, unicode)):
            if 'code' not in code:
                if 'error' in code:
                    error_msg = code['error']
                else:
                    error_msg = 'No code was supplied in the query parameters.'
                raise FlowExchangeError(error_msg)
            else:
                code = code['code']

        body = urllib.urlencode({
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope
        })
        headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + b64encode(self.client_id + ':' + self.client_secret)
        }

        if self.user_agent is not None:
            headers['user-agent'] = self.user_agent

        if http is None:
            http = httplib2.Http()

        resp, content = http.request(self.token_uri, method='POST', body=body,
                                     headers=headers)
        d = _parse_exchange_token_response(content)
        if resp.status == 200 and 'access_token' in d:
            access_token = d['access_token']
            refresh_token = d.get('refresh_token', None)
            token_expiry = None
            if 'expires_in' in d:
                token_expiry = datetime.datetime.utcnow() + datetime.timedelta(
                    seconds=int(d['expires_in']))

            if 'id_token' in d:
                d['id_token'] = _extract_id_token(d['id_token'])

            logger.info('Successfully retrieved access token')
            return OAuth2RedditCredentials(access_token, self.client_id,
                                           self.client_secret, refresh_token, token_expiry,
                                           self.token_uri, self.user_agent,
                                           revoke_uri=self.revoke_uri,
                                           id_token=d.get('id_token', None),
                                           token_response=d)
        else:
            logger.info('Failed to retrieve access token: %s' % content)
            if 'error' in d:
                # you never know what those providers got to say
                error_msg = unicode(d['error'])
            else:
                error_msg = 'Invalid response: %s.' % str(resp.status)
            raise FlowExchangeError(error_msg)


class OAuth2RedditCredentials(OAuth2Credentials):
    def _generate_refresh_request_headers(self):
        """Generate the headers that will be used in the refresh request."""
        headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + b64encode(self.client_id + ':' + self.client_secret)
        }

        if self.user_agent is not None:
            headers['user-agent'] = self.user_agent

        return headers


def scopes_to_string(scopes):
    if isinstance(scopes, basestring):
        return scopes
    else:
        return ','.join(scopes)