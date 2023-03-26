from django.utils import timezone
from uuid import uuid4
from rest_framework import serializers
from Account.models import User, Token
from Account.utils import Util

from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator



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
        user = User.objects.create_user(**validated_data)
        key = str(uuid4())   
        # print("Key1: ", key)
        token = Token.objects.create(user=user, key=key, expires_at=timezone.now() + timezone.timedelta(minutes=5))
        token.save()
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token_generator = default_token_generator.make_token(user)
        link = 'http://localhost:3000/authenticate/' + uid + "/" + token_generator + "/" + key
        # print("Token Link: ", link)
        # Send Email
        body = '<h5 style="font-size:18px;font-weight:bold">Click the below button for verification</h5>' + '<div style="width:100%;"><a style="background:#606060;display:inline-block;margin-left:10%;color:white;font-size:18px;font-weight:bold;cursor:pointer;padding:12px 20px 8px;text-decoration:none;border-radius:3px;" href="' + link + '"><span style="line-height:24px;">Verify</span></a></div>'
        data = {
            'subject': 'User Verification',
            'body': body,
            'from_email': "nurul0.amin0@gmail.com",
            'to_email': user.email
        }
        Util.send_email(data)
        return user
    
    

class UserRegistrationVerificatioSerializer(serializers.Serializer):
    is_verified = serializers.BooleanField()
    class Meta:
        fields = ['is_verified']

    def validate(self, attrs):
        is_verified = attrs.get('is_verified')
        uid = self.context.get('uid')
        token = self.context.get('token')
        key = self.context.get('key')

        id = smart_str(urlsafe_base64_decode(uid))
        user = User.objects.get(id=id)
        token_obj = Token.objects.get(user=user, key=key)

        if is_verified == False:
            raise serializers.ValidationError("Something went wrong!")
        elif token_obj is not None:
            if token_obj.is_valid():
                if default_token_generator.check_token(user, token):
                    user.is_verified = is_verified
                    user.save()
                    return attrs
                else:
                    raise serializers.ValidationError("Request is not valid or Request time expired")
            else:
                raise serializers.ValidationError("Request Time Expired!")
        else:
            raise serializers.ValidationError("Well, Hello - Who are u?")
        # return attrs


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']

    def validate(self, attrs):
        email = attrs.get('email')
        user = User.objects.get(email=email)
        if user is not None:
            if user.is_verified != True:
                key = str(uuid4())   
                token = Token.objects.create(user=user, key=key, expires_at=timezone.now() + timezone.timedelta(minutes=5))
                token.save()
                uid = urlsafe_base64_encode(force_bytes(user.id))
                token_generator = default_token_generator.make_token(user)
                link = 'http://localhost:3000/authenticate/' + uid + "/" + token_generator + "/" + key
                # print("Token Link: ", link)
                # Send Email
                body = '<h5 style="font-size:18px;font-weight:bold">Click the below button for verification</h5>' + '<div style="width:100%;"><a style="background:#606060;display:inline-block;margin-left:10%;color:white;font-size:18px;font-weight:bold;cursor:pointer;padding:12px 20px 8px;text-decoration:none;border-radius:3px;" href="' + link + '"><span style="line-height:24px;">Verify</span></a></div>'
                data = {
                    'subject': 'User Verification',
                    'body': body,
                    'from_email': "nurul0.amin0@gmail.com",
                    'to_email': user.email
                }
                Util.send_email(data)
                raise serializers.ValidationError("You are not verified user. Check your email inbox or spam to verify your account.")
        return attrs



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
            body = '<h5 style="font-size:18px;font-weight:bold">Click the below button to reset your password</h5>' + '<div style="width:100%;"><a style="background:#606060;display:inline-block;margin-left:10%;color:white;font-size:18px;font-weight:bold;cursor:pointer;padding:12px 20px 8px;text-decoration:none;border-radius:3px;" href="' + link + '"><span style="line-height:24px;">Click Here</span></a></div>'
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
            raise serializers.ValidationError("Something went wrong")
    

    
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