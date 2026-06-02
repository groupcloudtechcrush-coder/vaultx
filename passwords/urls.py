from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path('', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),

    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),

    # Credential CRUD
    path('credentials/add/', views.add_credential, name='add_credential'),
    path('credentials/<int:pk>/delete/', views.delete_credential, name='delete_credential'),

    # Secure AJAX endpoints
    path('credentials/<int:pk>/reveal/', views.reveal_password, name='reveal_password'),
    path('generate-password/', views.generate_password, name='generate_password'),
]
