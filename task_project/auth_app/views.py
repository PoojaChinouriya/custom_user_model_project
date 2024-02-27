from rest_framework import generics, status, views
from rest_framework.response import Response
from .serializers import UserSerializer
from .models import User
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
import jwt
import logging
from rest_framework_simplejwt.tokens import RefreshToken
from task_project.utils import send_email
from rest_framework.permissions import IsAuthenticated
from .permissions import IsOwner, IsManagerOrTeamLeader
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import NotAuthenticated, PermissionDenied

success_logger = logging.getLogger('success_logger')
error_logger = logging.getLogger('error_logger')


class UserRegister(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            obj = serializer.save()
            success_logger.info(f'User created with username {obj.username}')
            token = RefreshToken.for_user(user=obj).access_token
            domain = get_current_site(request=request).domain
            relativeLink = reverse('activate-account', args=(str(token),))
            absurl = f'http://{domain}{relativeLink}'
            subject = "Account Activation Link"
            body = "Hello %s,\n\tPlease click on the link below to activate your account.\n%s"%(obj.username,absurl,)
            send_email(subject=subject, body=body, recipient_list=[obj.email,])
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(e)
            error_logger.error(f'Error saving the user data {serializer.errors}')
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class UserListAPI(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(self.get_queryset(), many=True)
            success_logger.info('Users Fetched Successfully')
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            error_logger.error('Error fetching users data')
            return Response(data={'detail': 'Error Fetching users'}, status=status.HTTP_400_BAD_REQUEST)


class UserDetailsAPI(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwner]

    def get(self, request, *args, **kawargs):
        try:
            obj = self.get_object()
            serializer = self.get_serializer(obj)
            success_logger.info("User details fetched successfully")
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        except PermissionDenied as e:
            return Response(data={'detail': 'Permission Denied'}, status=status.HTTP_403_FORBIDDEN)
        except NotAuthenticated as e:
            return Response(data={'detail': 'Not Authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(e)
            error_logger.error('Error Fetching user details')
            return Response(data={'detail':'Not found'}, status=status.HTTP_404_NOT_FOUND)
        
    
    def patch(self, request, *args, **kwargs):
        try:
            obj = self.get_object()
            serializer = self.get_serializer(data=request.data, instance=obj, partial=True)
            serializer.is_valid(raise_exception=True)
            obj = serializer.save()
            success_logger.info(f"User {obj.username} updated successfully")
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        except PermissionDenied as e:
            return Response(data={'detail': 'Permission Denied'}, status=status.HTTP_403_FORBIDDEN)
        except NotAuthenticated as e:
            return Response(data={'detail': 'Not Authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            error_logger.error('Error Updating user details')
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def put(self, request, *args, **kwargs):
        try:
            obj = self.get_object()
            serializer = self.get_serializer(data=request.data, instance=obj)
            serializer.is_valid(raise_exception=True)
            obj = serializer.save()
            success_logger.info(f"User {obj.username} updated successfully")
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        except PermissionDenied as e:
            return Response(data={'detail': 'Permission Denied'}, status=status.HTTP_403_FORBIDDEN)
        except NotAuthenticated as e:
            return Response(data={'detail': 'Not Authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            error_logger.error('Error Updating user details')
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AccountVerify(views.APIView):

    def get(self, request, token=None):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY,algorithms=['HS256'])
            user = User.objects.get(pk=payload.get('user_id'))
            user.is_active = True
            user.save()
            return Response(data={'detail': 'Account activated successfully'}, status=status.HTTP_200_OK)
        except jwt.DecodeError:
            return Response(data={'detail': 'Token in expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response(data={'detail': 'Link in expired'}, status=status.HTTP_400_BAD_REQUEST)