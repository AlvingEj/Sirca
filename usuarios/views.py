from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse

from django.contrib.auth import authenticate, login
from django.contrib import messages

from django.contrib.auth.decorators import login_required

from django.contrib.auth.forms import PasswordResetForm


from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes, force_str


from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm

from django.contrib.auth import get_user_model




DOMINIO_PERMITIDO = ['gmail.com', 'sena.com']

def registro(request):
    
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST.get('confirm_password')

        # Verificar que las contraseñas coincidan
        if password != confirm_password:
            messages.error(request, "Las contraseñas no coinciden")
            return render(request, 'usuarios/registro.html')
        
        # Obtener el dominio del correo electrónico
        dominio = email.split('@')[-1]

        # Verificar si el dominio es permitido
        if dominio not in DOMINIO_PERMITIDO:
            messages.error(request, f"Solo se permiten correos electrónicos de dominio {', '.join(DOMINIO_PERMITIDO)}")
            return render(request, 'usuarios/registro.html')

        user = User.objects.create_user(username=username, email=email, password=password)
        user.is_active = False
        user.save()
        
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        activation_link = request.build_absolute_uri(f'/activate/{uid}/{token}/')
        
        subject = 'Activa tu cuenta'
        message = render_to_string('usuarios/activation_email.html', {'activation_link': activation_link})
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        
        return redirect('activation_sent')
    return render(request, 'usuarios/registro.html')

# Vista para la activación de cuentas
def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect('inicio_sesion')
    else:
        return HttpResponse('El enlace de activación no es válido o ha expirado.')

def activation_sent(request):
    return render(request, 'usuarios/activation_sent.html')

def inicio_sesion(request):
    if request.user.is_authenticated:
        return redirect('panel_principal')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('panel_principal')
        else:
            messages.error(request, 'Nombre de usuario o contraseña incorrectos.')
            return redirect('inicio_sesion')

    return render(request, 'usuarios/inicio_sesion.html')


User = get_user_model()

def password_reset(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            associated_users = User.objects.filter(email=email)
            if associated_users.exists():
                for user in associated_users:
                    subject = "Restablecimiento de contraseña"
                    email_template_name = 'usuarios/recuperar/password_reset_email.html'
                    c = {
                        "email": user.email,
                        'domain': request.get_host(),
                        'site_name': 'Tu sitio',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        'user': user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email_message = render_to_string(email_template_name, c)
                    send_mail(subject, email_message, settings.DEFAULT_FROM_EMAIL, [user.email])
                messages.success(request, 'Se ha enviado un correo electrónico con instrucciones para restablecer tu contraseña.')
            else:
                messages.error(request, 'No hay usuarios asociados con esta dirección de correo electrónico.')
            return redirect('password_reset_done')
    else:
        form = PasswordResetForm()
    
    return render(request, 'usuarios/recuperar/password_reset_form.html', {'form': form})

def password_reset_done(request):
    return render(request, 'usuarios/recuperar/password_reset_done.html')

def password_reset_confirm(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Tu contraseña ha sido restablecida con éxito.')
                return redirect('password_reset_complete')
        else:
            form = SetPasswordForm(user)
        return render(request, 'usuarios/recuperar/password_reset_confirm.html', {'form': form})
    else:
        messages.error(request, 'El enlace de recuperación de contraseña es inválido o ha expirado.')
        return redirect('password_reset')
        
def password_reset_complete(request):
    return render(request, 'usuarios/recuperar/password_reset_complete.html')


@login_required
def panel_principal(request):
    if request.method == 'POST':
        # Lógica de autenticación
        return redirect('panel_principal')
    return render(request, 'usuarios/panel/panel_principal.html')

    
