from django.urls import path
from Account.views import UserRegistrationView, UserRegistrationVerificatioView, UserLoginView, UserChangePasswordView, SendPasswordResetEmailView,UserPasswordResetView


urlpatterns = [
    path('registration/', UserRegistrationView.as_view(), name='registration'),
    path('authenticate/<uid>/<token>/<key>/', UserRegistrationVerificatioView.as_view(), name='authenticate'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset'),
]
