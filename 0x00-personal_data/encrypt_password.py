#!/usr/bin/env python3
""" Encrypting passwords
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """ Returns a salted, hashed password
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validates that the provided password matches the hashed password
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
