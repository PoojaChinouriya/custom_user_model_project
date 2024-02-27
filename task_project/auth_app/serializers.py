from rest_framework import serializers
from django.contrib.auth import get_user_model
from task_app.serializers import TaskListSerializer

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    assigned_tasks = TaskListSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'first_name', 'last_name', 'email', 'contact', 'profile_pic',
                  'address', 'pincode', 'city', 'role', 'gender', 'company', 'assigned_tasks')
        

    def create(self, validated_data):
        obj = User.objects.create_user(**validated_data)
        obj.is_active = False
        obj.save()
        return obj