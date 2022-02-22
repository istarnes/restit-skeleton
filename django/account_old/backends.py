from urllib.parse import urlencode
from urllib.request import Request, urlopen

import json

from django.conf import settings
# from social.backends.google import GoogleOAuth2
from social_core.backends.google import GoogleOAuth2

from account.models import Member

# GoogleOAuth2Extended = GoogleOAuth2
# GoogleOAuth2.name = 'google'

class GoogleOAuth2Extended(GoogleOAuth2):
    """Google OAuth2 authentication backend"""
    name = 'google'

    def get_user_details(self, response):
        """return more details if possible"""
        print("GOT TO USER DETAILS!!!!")
        email = None
        if 'email' in response:
            email = response['email']
        elif 'emails' in response:
            email = response['emails'][0]['value']
        else:
            email = ''
        res = {}
        if isinstance(response.get('name'), dict):
            names = response.get('name') or {}
            name, given_name, family_name = (
                response.get('displayName', ''),
                names.get('givenName', ''),
                names.get('familyName', ''))
            fullname, first_name, last_name = self.get_user_names(name, given_name, family_name)
            image = response.get("image") or {}
            return {'username': email.split('@', 1)[0],
                        'email': email,
                        'gender': response.get('gender'),
                        'fullname': fullname,
                        'first_name': first_name,
                        'last_name': last_name,
                        'picture': image.get('url'),
                        'link': response.get('url'),
                        'audience': response.get('circledByCount'),
                        'verified_email': response.get('verified'),
                        'id': response.get('id')
                    }

        name, given_name, family_name = (
            response.get('name', ''),
            response.get('given_name', ''),
            response.get('family_name', '')
        )

        fullname, first_name, last_name = self.get_user_names(name, given_name, family_name)

        return {'username': email.split('@', 1)[0],
            'email': email,
            'gender': response.get('gender'),
            'fullname': fullname,
            'first_name': first_name,
            'last_name': last_name,
            'picture': response.get('picture'),
            'link': response.get('link'),
            'verified_email': response.get('verified_email'),
            'id': response.get('id')
        }

# @classmethod
# def extra_data(cls, user, uid, response, details=None):
# 	"""Return access_token and extra defined names to store in
# 	extra_data field"""
# 	data = {'access_token': response.get('access_token', '')}
# 	name = cls.name.replace('-', '_').upper()
# 	names = (cls.EXTRA_DATA or []) + self.setting(name + '_EXTRA_DATA', [])
# 	for entry in names:
# 		if len(entry) == 2:
# 			(name, alias), discard = entry, False
# 		elif len(entry) == 3:
# 			name, alias, discard = entry
# 		elif len(entry) == 1:
# 			name = alias = entry
# 		else:  # ???
# 			continue

# 		value = response.get(name)
# 		if discard and not value:
# 			continue
# 		data[alias] = value

# if "refresh_token" not in data or data["refresh_token"] in [None, ""]:
# 	if user:
# 		member = Member.getByUser(user)
# 		data["refresh_token"] = member.getProperty("google_refresh_token", None)
# return data

# def auth_extra_arguments(self):
# backend_name = self.name.upper().replace('-', '_')
# extra_arguments = self.setting("GOOGLE_OAUTH_EXTRA_ARGUMENTS", {})
# for key, value in extra_arguments.iteritems():
# 	if key in self.data:
# 		extra_arguments[key] = self.data[key]
# 	elif value:
# 		extra_arguments[key] = value
# return extra_arguments

# 	def user_data(self, access_token, *args, **kwargs):
# 		"""Return user data from Google API"""
# 		data = urlencode({'oauth_token': access_token})
# 		request = Request('https://www.googleapis.com/userinfo/v2/me?' + data, headers={'Authorization': data})
# 		try:
# 			u_data = json.loads(urlopen(request).read())
# 			u_data["access_token"] = access_token
# 			if "mobile_token" in kwargs:
# 				u_data["mobile_token"] = kwargs["mobile_token"]
# 			elif "refresh_token" in kwargs:
# 				u_data["refresh_token"] = kwargs["refresh_token"]
# 			return u_data
# 		except (ValueError, IOError):
# 			print "ERROR LOADING DATA"
# 		return None

# BACKENDS = {
# 	'google': GoogleOAuth2Extended,
# }
