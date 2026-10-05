import jwt
from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .permissions import IsAdmin
from .serializers import (ChangePasswordSerializer, LoginSerializer, RefreshSerializer,
                          RegisterSerializer, UserSerializer)
from .tokens import create_access_token, create_refresh_token, decode_token

User = get_user_model()


def token_pair(user):
    return {'access': create_access_token(user), 'refresh': create_refresh_token(user)}


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(**serializer.validated_data)
        if user is None:
            return Response({'detail': 'Login yoki parol noto\'g\'ri'},
                            status=status.HTTP_401_UNAUTHORIZED)
        return Response(token_pair(user))


class RefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            payload = decode_token(serializer.validated_data['refresh'], 'refresh')
            user = User.objects.get(id=payload['user_id'], is_active=True)
        except (jwt.InvalidTokenError, User.DoesNotExist):
            return Response({'detail': 'Refresh token yaroqsiz'},
                            status=status.HTTP_401_UNAUTHORIZED)
        return Response({'access': create_access_token(user)})


class MeView(APIView):
    def get(self, request):
        return Response(UserSerializer(request.user).data)


class ChangePasswordView(APIView):
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not request.user.check_password(serializer.validated_data['old_password']):
            return Response({'detail': 'Eski parol noto\'g\'ri'},
                            status=status.HTTP_400_BAD_REQUEST)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        return Response({'detail': 'Parol o\'zgartirildi'})


class UserListView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        return Response(UserSerializer(User.objects.all(), many=True).data)
