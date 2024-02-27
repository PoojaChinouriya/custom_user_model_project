from django.db import models


class Task(models.Model):
    TASK_STATUS = [
        ('pending', 'pending'),
        ('completed', 'completed'),
        ('in progress', 'in progress'),
    ]
    task_id = models.BigAutoField(primary_key=True)
    task_name = models.CharField(max_length=50)
    task_description = models.TextField()
    task_status = models.CharField(max_length=20, choices=TASK_STATUS, default="pending")
    task_created_by = models.ForeignKey('auth_app.User', on_delete=models.CASCADE, related_name="created_tasks")
    task_assigned_to = models.ForeignKey('auth_app.User', on_delete=models.CASCADE, related_name="assigned_tasks")
    task_assigned_date = models.DateTimeField(auto_now_add=True)
    task_completed_date = models.DateTimeField(blank=True, null=True)
    task_deadline = models.DateTimeField()
