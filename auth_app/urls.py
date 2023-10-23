from django.urls import path
from auth_app.views import * 

urlpatterns = [
    path('register/', UserApi.as_view()),
    path('login/', LoginView.as_view()),
    path('verify/<str:email>/', two_step_otp_Verify),
    path('logout/', Logout.as_view()),
    path('request-reset-password/', ResetPasswordApiView.as_view(), name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckApiView.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/', SetNewPasswordApiView.as_view(), name='password-reset-complete'),
    path('update-user/', UpdateCustomUser.as_view()),
    path('home/', AdminApi.as_view()),
    path('home/', ManagerApi.as_view()),
    path('home/', EmployeeApi.as_view()),
    
]