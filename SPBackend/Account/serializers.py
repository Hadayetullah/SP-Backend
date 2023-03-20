from rest_framework import serializers
from Account.models import User
from Account.utils import Util

from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['name', 'email', 'phone', 'password', 'password2']
        extra_kwargs = {
            'password': {
            'write_only': True,
            'style':{'input_type': 'password'}
            }
        }

    # Validating Password and Confirm Password while Registration
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
    


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']



class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=128, style={'input_type':'password'}, write_only=True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs
    


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']
    
    def validate(self, attrs):
        email = attrs.get('email')
        user = User.objects.filter(email=email)
        if user.exists():
            user = user[0]
            # print(user, user.id)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = 'http://localhost:3000/reset-password/' + uid + '/' + token
            # print(link)

            # Email Send
            body = '<h5 style="font-size:18px;font-weight:bold">Click the below button to reset your password</h5>' + '<div style="margin-left: 10%;"><a style="background:#606060;color:white;font-size:18px;font-weight:bold;cursor:pointer;padding:5px 20px;text-decoration:none" href="' + link + '">Click Here</a></div>'
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'from_email': "nurul0.amin0@gmail.com",
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError("You are not a Registered User")
        

       
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=128, style={'input_type':'password'}, write_only=True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError("Password and Confirm Password doesn't match")
            
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Token is not valid or expired")
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as indentifier:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
    

    
# {
# "name":"a",
# "email":"c@gmail.com",
# "phone":"01846857388",
# "password":"abc@12345"
# }

# {
# "email":"c@gmail.com",
# "password":"abc@12345"
# }

# {
# "email":"hadayetullah002@gmail.com"
# }