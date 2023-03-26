from django.utils.encoding import smart_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import authenticate

from rest_framework.views import APIView
from rest_framework.response import Response
# from rest_framework import authentication, permissions
from rest_framework import status
from Account.serializers import UserRegistrationSerializer, UserRegistrationVerificatioSerializer, UserLoginSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer,UserPasswordResetSerializer
from Account.renderers import CustomizeMasseges
from Account.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated



# Generate token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }




# Create your views here.
class UserRegistrationView(APIView):
    renderer_classes = [CustomizeMasseges]
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save() 
            return Response({'msg':"A verification mail has been sent to your email. Please check your email."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class UserRegistrationVerificatioView(APIView):
    renderer_classes = [CustomizeMasseges]
    def post(self, request, uid, token, key, format=None):
        serializer = UserRegistrationVerificatioSerializer(data=request.data, context={"uid": uid, "token": token, "key": key})
        if serializer.is_valid(raise_exception=True):
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            token = get_tokens_for_user(user)
            return Response({"token": token, "msg":"Registration Verification Successful"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    renderer_classes = [CustomizeMasseges]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token':token, 'msg':'Logged in successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors':['Invalid Email or Password']}},
                                status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserChangePasswordView(APIView):
    renderer_classes = [CustomizeMasseges]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
        # print(request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class SendPasswordResetEmailView(APIView):
    renderer_classes = [CustomizeMasseges]
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password Reset Link Sent. Please Check your Email'},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserPasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
        if serializer.is_valid(raise_exception=True):
            # id = smart_str(urlsafe_base64_decode(uid))
            # user = User.objects.get(id=id)
            # token = get_tokens_for_user(user)
            return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)