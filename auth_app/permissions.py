from rest_framework import permissions
   
class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated and request.user.role=='Admin':
            return True
        return False
    
    # def has_object_permission(self, request, view, obj):
    #     if request.user and request.user.is_authenticated and request.user.role=='Admin':
    #         return True
    #     return bool(request.user == obj.user)

class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated and request.user.role=='Manager':
            return True
        return False
    
    # def has_object_permission(self, request, view, obj): # delte, update
    #     if request.user and request.user.is_authenticated and request.user.role=='Manager':
    #         return True
    #     return bool(request.user == obj.user)

class IsEmployee(permissions.BasePermission):
    def has_permission(self, request, view):
        print(request.user, 'Employee')
        if request.user and request.user.is_authenticated and request.user.role=='Employee':
            return True
        return False
    
    # def has_object_permission(self, request, view, obj): # delte, update
    #     method = ['GET']
    #     print(permissions.SAFE_METHODS)
    #     print(request.user, 'object_permi ALL')
    #     if request.user and request.user.is_authenticated and request.user.role=='Employee':
    #         return True
    #     return bool(request.user == obj.user)

