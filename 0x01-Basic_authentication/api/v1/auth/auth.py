#!/usr/bin/env python3
""" Auth module"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require auth method"""
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        if path.endswith('/'):
            path = path[:-1]

        for excluded_path in excluded_paths:
            if excluded_path.endswith('/'):
                excluded_path = excluded_path[:-1]

            if path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Authorization header method"""
        if request is None or 'Authorization' not in request.headers:
            return None

        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user method"""
        return None
