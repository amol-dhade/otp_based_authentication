from django.shortcuts import render
from .models import CustomUser
from .serializers import UserSerializer, ResetPasswordSerializer, SetNewPasswordSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import random
from django.contrib.auth import authenticate, login, logout
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from .permissions import IsAdmin, IsManager, IsEmployee
from django.http import JsonResponse
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, smart_bytes, force_str, DjangoUnicodeDecodeError, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from twilio.rest import Client
from .utils import send_otp_via_sms, send_password_reset_link_via_email



class UserApi(APIView):
    def post(self, request):
        data = request.data 
        serializer = UserSerializer(data=data)
        if serializer.is_valid(): #check the data is valid 
            serializer.save()
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request, format=None):
        data = request.data
        response = Response()       
        email = data.get('email', None)
        password = data.get('password', None)
        user = authenticate(email=email,password=password) #check the user is authenticated
        print(user)
        if user is not None:
            if user.is_active:
                otp = random.randrange(1000, 9999)
                print(otp)
                user.otp = otp
                user.save(update_fields=['otp',]) 
                phone_number = user.phone_number
                print(phone_number)
                send_otp_via_sms(phone_number, otp)
                return Response({"send":"Two step verification OTP successfully send!!!"},status = status.HTTP_200_OK) 
            else:
                return Response({"No active" : "This account is not active!!"},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"Invalid" : "Invalid username or password!!"},status=status.HTTP_404_NOT_FOUND)
        
@api_view(['POST'])
@permission_classes([AllowAny,])
def two_step_otp_Verify(request,email):
    data = request.data 
    otp = data.get('otp')
    try:
        user = CustomUser.objects.get(email=email)
        if user.otp == int(otp):
            login(request, user)
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            return Response(data={"access_token":access_token}, status=status.HTTP_200_OK)
        else:
            return Response({"Time out" : "Given otp is expired!!"}, status=status.HTTP_408_REQUEST_TIMEOUT)
    except:
        return Response(data="this is json response")
          
class Logout(APIView):
    def get(self, request):
        logout(request)
        print(request.user.is_authenticated)
        return Response({'msg':'logout successfully'})
    
class ResetPasswordApiView(APIView):
    #serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny]
    def post(self, request):
        data={'request':request,'data':request.data}
        serilaizer = ResetPasswordSerializer(data=data)
        email = request.data['email']
        if CustomUser.objects.filter(email=email).exists():
            user = CustomUser.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            print("uidb64 decode", force_str(urlsafe_base64_decode(uidb64)))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain 
            relativelink = reverse('password-reset-confirm', kwargs={'uidb64':uidb64, 'token':token})
            absurl = 'http://'+current_site+relativelink
            email_body = 'Hi '+user.first_name+'\nuse link below to verify your email\n'+absurl
            data = {'email_body':email_body, 'to_email':user.email,'email_subject':'reset your password'}
            send_password_reset_link_via_email(data)
            print(data)
            return Response({'success':'we have sent link to reset your password'})
        return Response({'error':'This account is not active'})
    
            
class PasswordTokenCheckApiView(APIView):
    def get(self, request, uidb64, token):
        try:
            id = force_str(urlsafe_base64_decode(uidb64))
            print("user id", id)
            user = CustomUser.objects.get(id=str(id))
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error':'Token is not valid please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)      
            return Response({'success':True, 'message':'Credentials valid', 'uidb64':uidb64,'token':token}, status=status.HTTP_200_OK)
                     
        except DjangoUnicodeDecodeError as e:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error':'Token is not valid please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
            
class PasswordTokenCheckApiView(APIView):
    def get(self, request, uidb64, token):
        try:
            #id = smart_str(urlsafe_base64_decode(uidb64))
            id = force_str(urlsafe_base64_decode(uidb64))
            print("user id", id)
            user = CustomUser.objects.get(id=str(id))
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error':'Token is not valid please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
                
            return Response({'success':True, 'message':'Credentials valid', 'uidb64':uidb64,'token':token}, status=status.HTTP_200_OK)
            
            
        except DjangoUnicodeDecodeError as e:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error':'Token is not valid please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
            
class SetNewPasswordApiView(APIView):
    serializer_class = SetNewPasswordSerializer 
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)       
        return Response({'success':True, 'message':'Password reset success'}, status=status.HTTP_200_OK)

class UpdateCustomUser(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def patch(self, request):
        obj = CustomUser.objects.get(email=request.user.email)
        serializer = UserSerializer(data=request.data, instance=obj, partial=True)
        print("user info",request.user.email)
        print(serializer)
        if serializer.is_valid():
            serializer.save()
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)
        return Response(data={'msg':'provide valid details'}, status=status.HTTP_400_BAD_REQUEST)

class AdminApi(APIView): #only Admin can access this view
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdmin,IsAuthenticated]
    def get(self,request):
        return Response(data={'msg':'Welcome Admin'})
    
class ManagerApi(APIView): #only Manager and Admin can access this view
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsManager, IsAdmin, IsAuthenticated]
    def get(self,request):
        return Response(data={'msg':'Welcome Manager'})
    
class EmployeeApi(APIView): #only Employee and Admin can access this view
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmployee, IsAdmin, IsAuthenticated]
    def get(self,request):
        return Response(data={'msg':'Welcome Employee'})
    

    
    




            

                
        

    

        
            
        
      
       
       
    

    



