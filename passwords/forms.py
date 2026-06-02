from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import StoredCredential


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={
        'class': 'w-full bg-slate-800 border border-slate-600 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors',
        'placeholder': 'you@example.com',
    }))

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        field_class = 'w-full bg-slate-800 border border-slate-600 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors'
        placeholders = {
            'username': 'Choose a username',
            'password1': 'Create a strong password',
            'password2': 'Confirm your password',
        }
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = field_class
            if field_name in placeholders:
                field.widget.attrs['placeholder'] = placeholders[field_name]
            field.help_text = None


class LoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        field_class = 'w-full bg-slate-800 border border-slate-600 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors'
        self.fields['username'].widget.attrs.update({'class': field_class, 'placeholder': 'Username'})
        self.fields['password'].widget.attrs.update({'class': field_class, 'placeholder': 'Password'})


class CredentialForm(forms.ModelForm):
    plain_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full bg-slate-800 border border-slate-600 text-white rounded-lg px-4 py-3 pr-12 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors',
            'placeholder': 'Enter or generate a password',
            'id': 'id_plain_password',
        }),
        label='Password',
        required=True,
    )

    class Meta:
        model = StoredCredential
        fields = ['website_name', 'website_url', 'username_or_email']
        widgets = {
            'website_name': forms.TextInput(attrs={
                'class': 'w-full bg-slate-800 border border-slate-600 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors',
                'placeholder': 'e.g. GitHub',
            }),
            'website_url': forms.URLInput(attrs={
                'class': 'w-full bg-slate-800 border border-slate-600 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors',
                'placeholder': 'https://github.com',
            }),
            'username_or_email': forms.TextInput(attrs={
                'class': 'w-full bg-slate-800 border border-slate-600 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors',
                'placeholder': 'username or email',
            }),
        }
