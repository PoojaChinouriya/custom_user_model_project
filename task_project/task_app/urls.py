from django.urls import path
from .views import TaskAPI, TaskDetailsAPI

urlpatterns = [
    path('tasks/', TaskAPI.as_view()),
    path('tasks/<int:pk>/', TaskDetailsAPI.as_view()),
]