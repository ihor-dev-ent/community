from django.urls import path

from . import views

app_name = 'comm_app'
urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.user_login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.user_logout, name='logout'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('generate_code/', views.generate_invite_code, name='generate_code'),
    path('skip_code/', views.skip_invite_code, name='skip_code'),
    path('confirm_code/', views.confirm_code, name='confirm_code'),
    path('confirm_code/<str:vcode>', views.confirm_verification_code, name='confirm_ver_code'),
	path('password_reset/', views.password_reset, name='password_reset'),
    path('top_ten_users', views.top_ten_users, name='top_ten_users'),
]