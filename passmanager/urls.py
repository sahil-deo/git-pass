from django.urls import path 
from . import views 

urlpatterns = [
    path('passwords/', views.passwords, name="Passwords")
]