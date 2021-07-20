from django import forms
# from django.contrib.auth.models import User


class LoginForm(forms.Form):
    uname = forms.CharField(widget=forms.TextInput(
        attrs={'class': "form-control mt-3",
               'placeholder': "username or email"})
    )
    pwd = forms.CharField(widget=forms.PasswordInput(
        attrs={'class': "form-control mt-3", 'placeholder': "password"})
    )


class RegisterForm(forms.Form):
    icode = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': "form-control mt-3",
                                      'placeholder': "invite code"})
    )
    uname = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={'id': "uname_reg", 'class': "form-control mt-3",
                   'placeholder': "username"})
    )
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={'id': "email_reg", 'class': "form-control mt-3",
                   'placeholder': "email"})
    )
    pwd = forms.CharField(
        required=False,
        widget=forms.PasswordInput(
            attrs={'id': "pwd_reg", 'class': "form-control mt-3",
                   'placeholder': "password"})
    )
    chk_pwd = forms.CharField(
        required=False,
        widget=forms.PasswordInput(
            attrs={'class': "form-control mt-3",
                   'placeholder': "confirm password"})
    )


class ConfirmCodeForm(forms.Form):
    verification_code = forms.CharField(
        max_length=20,
        widget=forms.TextInput(
            attrs={'class': "form-control mt-3",
                   'placeholder': "confirm code"})
    )
    # class Meta:
    #     model = User
    #     fields = ['username', 'email', 'password']
