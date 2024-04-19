#!/usr/bin/env python3
""" basic auth module
"""

import base64
from .auth import Auth
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """BasicAuth class"""
    def __init__(self) -> None:
        super().__init__()

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extract base64 authorization header method"""
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith('Basic '):
            return None

        return authorization_header.split(' ')[1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """Decode base64 authorization header method"""
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """Extract user credentials method"""
        if decoded_base64_authorization_header is None:
            return (None, None)

        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)

        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        
        return decoded_base64_authorization_header.split(':', 1)

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd:
                                     str) -> TypeVar('User'):
        """User object from credentials method"""
        user = None
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({"email": user_email})
        if not users:
            return None
        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user
        
    def current_user(self, request=None) -> TypeVar('User'):
        """Current user method"""
        Auth_header = self.authorization_header(request)
        if Auth_header is not None:
            token = self.extract_base64_authorization_header(Auth_header)
            if token is not None:
                decoded_token = self.decode_base64_authorization_header(token)
                if decoded_token is not None:
                    user_email, user_pwd = self.extract_user_credentials(decoded_token)
                    if user_email is not None:
                        return self.user_object_from_credentials(user_email, user_pwd)
        return
