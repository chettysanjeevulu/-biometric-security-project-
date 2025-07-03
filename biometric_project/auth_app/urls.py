from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.register_user, name='register_user'),
    path('login/', views.login_user, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_user, name='logout_user'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),
    path('management-login/', views.admin_login, name='admin_login'),
    path('management-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('management-logout/', views.admin_logout, name='admin_logout'),
    path('management/activities/', views.view_user_activities, name='view_user_activities'),
    path('management/logs/', views.log_dashboard, name='log_dashboard'),
    path('auth-server/login/', views.auth_serv_login, name='auth_serv_login'),
    path('auth-server/dashboard/', views.auth_serv_dashboard, name='auth_serv_dashboard'),
    path('auth-server/logout/', views.auth_serv_logout, name='auth_serv_logout'),
    path('resource-server/login/', views.resource_serv_login, name='resource_serv_login'),
    path('resource-server/dashboard/', views.resource_serv_dashboard, name='resource_serv_dashboard'),
    path('resource-server/logout/', views.logout_resource_serv, name='logout_resource_serv'),
]