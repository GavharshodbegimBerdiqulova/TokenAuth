import jwt
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from .tokens import decode_token

User = get_user_model()


class JWTAuthentication(BaseAuthentication):

    def authenticate(self, request):
        header = get_authorization_header(request).split()
        if not header or header[0].lower() != b'bearer':
            return None
        if len(header) != 2:
            raise AuthenticationFailed('Authorization header noto\'g\'ri')

        try:
            payload = decode_token(header[1].decode(), 'access')
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token muddati tugagan')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Token yaroqsiz')

        try:
            user = User.objects.get(id=payload['user_id'], is_active=True)
        except User.DoesNotExist:
            raise AuthenticationFailed('Foydalanuvchi topilmadi')
        return (user, payload)

    def authenticate_header(self, request):
        return 'Bearer'
