from django.contrib.auth.views import LogoutView
from django.urls import path
from . import views

urlpatterns = [
    path('registro/', views.registro, name='registro_usuario'),
    path('activation_sent/', views.activation_sent, name='activation_sent'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('login/', views.inicio_sesion, name='inicio_sesion'),



    path('recuperar_contraseña/', views.password_reset, name='password_reset'),
    path('recuperar_contraseña/done/', views.password_reset_done, name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('reset/done/', views.password_reset_complete, name='password_reset_complete'),



    path('panel/', views.panel_principal, name='panel_principal'),

    path('logout/', LogoutView.as_view(), name='logout'),
    
]
