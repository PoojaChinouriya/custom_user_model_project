from django.urls import path
from .views import AccountVerify, UserRegister, UserDetailsAPI, UserListAPI

urlpatterns = [
    path('user/', UserRegister.as_view(), name='user-register'),
    path('verify/<token>/', AccountVerify.as_view(), name='activate-account'),
    path('user/<int:pk>/', UserDetailsAPI.as_view(), name='user-details'),
    path('users/', UserListAPI.as_view(), name='user-details'),
]