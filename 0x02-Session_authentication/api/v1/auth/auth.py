#!/usr/bin/env python3
""" Auth module"""

from flask import request
from os import getenv
from typing import List, TypeVar


class Auth:
    """Auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check if a path requires authentication."""
        if bool(path and excluded_paths):
            path = path + '/' if path[-1] != '/' else path
            for excluded_path in excluded_paths:
                if excluded_path.endswith('*') and path.startswith(
                   excluded_path[:-1]):
                    return False
                if excluded_path == path:
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """Authorization header method"""
        if bool(request and 'Authorization' in request.headers.keys()):
            return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user method"""
        return None
    
    def session_cookie(self, request=None) -> str:
        """Session cookie method"""
        if request:
            return request.cookies.get(getenv('SESSION_NAME'))
