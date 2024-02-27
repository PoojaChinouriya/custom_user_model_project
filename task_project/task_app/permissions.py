from rest_framework import permissions


class IsManagerOrTeamLeader(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and (request.user.role == 'manager' or request.user.role == 'team_leader'))
    

class IsTaskAssignedTo(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        return bool(request.user and request.user.is_authenticated and (request.user == obj.task_assigned_to))