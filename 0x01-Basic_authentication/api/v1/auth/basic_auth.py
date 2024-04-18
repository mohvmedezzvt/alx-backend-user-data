#!/usr/bin/env python3
""" basic auth module
"""

import base64
import email
from .auth import Auth
from models.base import Base
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

        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """Decode base64 authorization header method"""
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            return base64.b64decode(
                base64_authorization_header).decode('utf-8')
        except Exception as e:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """Extract user credentials method"""
        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        return tuple(decoded_base64_authorization_header.split(':', 1))

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

        try:
            users = User.search({'email': user_email})
            user = users[0] if user else None
            if user:
                password = user.password
                if password:
                    if user.is_valid_password(password):
                        return user
                else:
                    return None

        except Exception as e:
            raise e
