from rest_framework import serializers
from .models import Task
from datetime import datetime


class TaskListSerializer(serializers.ModelSerializer):
    task_deadline = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    task_assigned_date = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    task_completed_date = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    class Meta:
        model = Task
        fields = '__all__'

class TaskCreateSerializer(serializers.ModelSerializer):
    task_created_by = serializers.HiddenField(default=serializers.CurrentUserDefault())
    task_deadline = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    task_assigned_date = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    class Meta:
        model = Task
        exclude = ('task_completed_date', 'task_status')


class TaskUpdateSerializer(serializers.ModelSerializer):
    task_assigned_to = serializers.HiddenField(default=serializers.CurrentUserDefault())
    task_assigned_date = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    task_completed_date = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    class Meta:
        model = Task
        exclude = ('task_created_by', 'task_deadline')

    def update(self, instance, validated_data):
        if validated_data.get('task_status') == 'completed':
            validated_data['task_completed_date'] = datetime.now()
        return super().update(instance, validated_data)
    