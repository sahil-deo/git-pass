from django.urls import path 
from . import views 

urlpatterns = [
    path('passwords/', views.passwords, name="Passwords"),
    path('', views.home, name="Home"),
    path('new/', views.newpassword, name="New-Password"),

]