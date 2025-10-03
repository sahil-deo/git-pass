from django.urls import path 
from . import views 

urlpatterns = [
    path('passwords/', views.passwords, name="Passwords"),
    path('', views.home, name="Home"),
    path('new/', views.newpassword, name="New-Password"),
    path('passwords/update/<int:id>', views.update, name="Edit-Password"),
    path('passwords/delete/<int:id>', views.delete, name="Delete-Password"),
    path('passwords/deleteall/', views.deleteall, name="Delete-All"),
    path('settings/', views.settings, name="Settings"),
    path('passwords/upload/', views.upload_csv, name="Upload"),
    path('logout/', views.logout, name="Logout"),
    path('instructions/', views.instructions, name = "Instructions"),
    path('settings/reset-master/', views.reset_master, name="Reset-Master"),
    path('passwords/backup/', views.create_backup, name="Backup"),

    # Notes URLs
    path('notes/', views.notes, name="Notes"),
    path('notes/new/', views.newnote, name="New-Note"),
    path('notes/update/<int:id>', views.update_note, name="Edit-Note"),
    path('notes/delete/<int:id>', views.delete_note, name="Delete-Note"),
]