from rest_framework import generics
from .serializers import TaskCreateSerializer, TaskUpdateSerializer
from .models import Task
from .permissions import IsManagerOrTeamLeader, IsTaskAssignedTo
from rest_framework_simplejwt.authentication import JWTAuthentication

class TaskAPI(generics.ListCreateAPIView):
    serializer_class = TaskCreateSerializer
    queryset = Task.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsManagerOrTeamLeader]


class TaskDetailsAPI(generics.RetrieveUpdateAPIView):
    serializer_class = TaskUpdateSerializer
    queryset = Task.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsTaskAssignedTo]
