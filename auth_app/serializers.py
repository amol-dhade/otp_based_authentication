from rest_framework import serializers
from .models import CustomUser
from rest_framework.exceptions import AuthenticationFailed
from django.utils.encoding import smart_str, smart_bytes, force_str, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser 
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'password', 'role']
        
    def create(self, validated_data):
        return CustomUser.objects.create_user(**validated_data)
    
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    class Meta:
        fields = ['email']
        
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    
    class Meta:
        fields = ['password', 'token', 'uidb64']
        
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            
            id = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(id=id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed(' The reset link is invalid', 401)
            
            user.set_password(password)
            user.save()
        except Exception as e:
            raise AuthenticationFailed('the reset link is invalid', 401)
        return super().validate(attrs)
            
        

    