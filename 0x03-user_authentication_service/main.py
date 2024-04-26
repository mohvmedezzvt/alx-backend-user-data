#!/usr/bin/env python3
"""
Main file
"""

import requests

BASE_URL = 'http://localhost:5000'

EMAIL = 'guillaume@holberton.io'
PASSWD = 'b4l0u'
NEW_PASSWD = 't4rt1fl3tt3'


def register_user(email: str, password: str) -> None:
    """Register a user"""
    url = f'{BASE_URL}/users'
    payload = {'email': email, 'password': password}
    response = requests.post(url, data=payload)
    assert response.status_code == 200


def log_in_wrong_password(email: str, password: str) -> None:
    """Log in with wrong password"""
    url = f'{BASE_URL}/sessions'
    payload = {'email': email, 'password': password}
    response = requests.post(url, data=payload)
    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """Log in"""
    url = f'{BASE_URL}/sessions'
    payload = {'email': email, 'password': password}
    response = requests.post(url, data=payload)
    assert response.status_code == 200
    return response.cookies['session_id']


def profile_unlogged() -> None:
    """Profile unlogged"""
    url = f'{BASE_URL}/profile'
    response = requests.get(url)
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """Profile logged"""
    url = f'{BASE_URL}/profile'
    cookies = {'session_id': session_id}
    response = requests.get(url, cookies=cookies)
    assert response.status_code == 200
    assert response.json()['email'] == EMAIL


def log_out(session_id: str) -> None:
    """Log out"""
    url = f'{BASE_URL}/sessions'
    cookies = {'session_id': session_id}
    response = requests.delete(url, cookies=cookies)
    assert response.status_code == 200


def reset_password_token(email: str) -> str:
    """Get reset password token"""
    url = f'{BASE_URL}/reset_password'
    payload = {'email': email}
    response = requests.post(url, data=payload)
    assert response.status_code == 200
    return response.json()['reset_token']


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Update password"""
    url = f'{BASE_URL}/reset_password'
    payload = {'email': email,
               'reset_token': reset_token,
               'new_password': new_password}
    response = requests.put(url, data=payload)
    assert response.status_code == 200


if __name__ == '__main__':
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
