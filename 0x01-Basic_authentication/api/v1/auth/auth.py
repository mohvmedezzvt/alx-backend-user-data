#!/usr/bin/env python3
""" Auth module"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check if a path requires authentication."""
        if path is None or excluded_paths is None or not excluded_paths:
            return True
        
        for excluded_path in excluded_paths:
            if excluded_path.endswith("*") and path.startswith(excluded_path[:-1]):
                return False
            elif path == excluded_path:
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
