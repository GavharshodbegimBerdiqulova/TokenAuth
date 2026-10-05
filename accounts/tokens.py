import datetime

import jwt
from django.conf import settings


def _create(user, token_type, lifetime):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        'user_id': user.id,
        'type': token_type,
        'iat': now,
        'exp': now + lifetime,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


def create_access_token(user):
    return _create(user, 'access', datetime.timedelta(minutes=settings.JWT_ACCESS_LIFETIME_MIN))


def create_refresh_token(user):
    return _create(user, 'refresh', datetime.timedelta(days=settings.JWT_REFRESH_LIFETIME_DAYS))


def decode_token(token, expected_type):
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    if payload.get('type') != expected_type:
        raise jwt.InvalidTokenError('Token turi noto\'g\'ri')
    return payload
