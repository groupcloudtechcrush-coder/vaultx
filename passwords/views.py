"""
views.py — VaultX Password Manager
====================================
All sensitive operations are performed server-side. Passwords travel over
HTTPS only and are never logged or cached. The decryption endpoint is
protected by @login_required and an ownership check so users can only
decrypt their own credentials.
"""

import json
import secrets
import string

from cryptography.fernet import InvalidToken
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_protect

from .crypto import encrypt_password, decrypt_password
from .forms import RegisterForm, LoginForm, CredentialForm
from .models import StoredCredential


# ---------------------------------------------------------------------------
# Auth Views
# ---------------------------------------------------------------------------

def register_view(request):
    """User registration — standard Django form processing."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, f'Welcome to VaultX, {user.username}!')
            return redirect('dashboard')
    else:
        form = RegisterForm()

    return render(request, 'registration/register.html', {'form': form})


def login_view(request):
    """User login."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('dashboard')
    else:
        form = LoginForm()

    return render(request, 'registration/login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login')


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@login_required
def dashboard(request):
    """
    Render the main vault dashboard.

    Retrieves only the credentials belonging to the current user — the
    queryset is filtered by `user=request.user` so cross-user data leakage
    is structurally impossible at the ORM level.

    Passwords are NOT decrypted here; each card shows masked dots by default.
    Decryption happens on-demand via the `reveal_password` AJAX endpoint.
    """
    credentials = StoredCredential.objects.filter(user=request.user)
    form = CredentialForm()
    return render(request, 'passwords/dashboard.html', {
        'credentials': credentials,
        'form': form,
    })


# ---------------------------------------------------------------------------
# Add / Delete Credential
# ---------------------------------------------------------------------------

@login_required
@require_POST
@csrf_protect
def add_credential(request):
    """
    Accept a POST with plain-text password, encrypt it, persist the record.

    The plain password is read from the form, passed through `encrypt_password`
    (Fernet AES-128-CBC + HMAC-SHA256), and only the resulting ciphertext token
    is written to the database. The plain password is then discarded from memory
    as soon as the function returns.
    """
    form = CredentialForm(request.POST)
    if form.is_valid():
        plain_pw: str = form.cleaned_data['plain_password']

        # --- ENCRYPTION STEP ---
        # encrypt_password derives a per-user Fernet key from the master secret
        # + user PK, then returns the Fernet ciphertext token (a string).
        cipher_text: str = encrypt_password(plain_pw, request.user.id)

        # Save the credential — plain_pw is NOT stored anywhere
        credential = form.save(commit=False)
        credential.user = request.user
        credential.encrypted_password = cipher_text
        credential.save()

        messages.success(request, f'"{credential.website_name}" added to your vault.')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f'{field}: {error}')

    return redirect('dashboard')


@login_required
@require_POST
@csrf_protect
def delete_credential(request, pk):
    """Delete a credential — only the owner can delete their own records."""
    credential = get_object_or_404(StoredCredential, pk=pk, user=request.user)
    name = credential.website_name
    credential.delete()
    messages.success(request, f'"{name}" removed from your vault.')
    return redirect('dashboard')


# ---------------------------------------------------------------------------
# Secure On-Demand Decryption  (AJAX endpoint)
# ---------------------------------------------------------------------------

@login_required
@require_GET
def reveal_password(request, pk):
    """
    Decrypt and return a single password as JSON — called via AJAX fetch().

    Security layers:
      1. @login_required          — anonymous users get redirected to login.
      2. get_object_or_404(..., user=request.user)
                                  — a logged-in user can only decrypt records
                                    they own; any attempt to fetch another
                                    user's credential returns HTTP 404.
      3. InvalidToken catch       — if the ciphertext is tampered with or the
                                    key derivation produces a wrong key,
                                    Fernet raises InvalidToken and we return
                                    HTTP 400 instead of crashing.
      4. No logging of plain text — the decrypted value is placed directly
                                    into the JSON response dict and never
                                    written to any log, cache, or DB field.

    Returns:
        200 { "password": "<plain text>" }
        400 { "error": "Decryption failed." }
        404 (if credential not found or wrong owner)
    """
    # Step 1 — Ownership-safe lookup: 404 if wrong user tries to access
    credential = get_object_or_404(
        StoredCredential,
        pk=pk,
        user=request.user   # <-- enforces ownership at DB query level
    )

    try:
        # Step 2 — Derive the per-user Fernet key and decrypt the token.
        # _derive_user_key runs PBKDF2-HMAC-SHA256 (390k iterations) using
        # the master FERNET_SECRET_KEY and the user's PK as salt.
        plain_password: str = decrypt_password(
            credential.encrypted_password,  # ciphertext token from DB
            request.user.id                 # used to re-derive the same key
        )
    except InvalidToken:
        # Step 3 — Fernet's HMAC check failed — data may have been tampered
        # with, or the master key changed. Return 400 without leaking details.
        return JsonResponse({'error': 'Decryption failed.'}, status=400)

    # Step 4 — Return the plain password to the authenticated, authorised user
    return JsonResponse({'password': plain_password})


# ---------------------------------------------------------------------------
# Password Generator  (AJAX endpoint)
# ---------------------------------------------------------------------------

@login_required
@require_GET
def generate_password(request):
    """
    Generate a cryptographically secure random password using `secrets`.

    `secrets` uses the OS CSPRNG (/dev/urandom on Linux, CryptGenRandom on
    Windows) — it is categorically more secure than `random` which uses a
    Mersenne Twister (predictable PRNG, not suitable for security).

    Query params:
        length      int  (default 16, min 8, max 128)
        upper       bool (include uppercase, default true)
        digits      bool (include digits, default true)
        symbols     bool (include symbols, default true)
    """
    try:
        length = max(8, min(128, int(request.GET.get('length', 16))))
    except ValueError:
        length = 16

    include_upper   = request.GET.get('upper',   'true').lower() == 'true'
    include_digits  = request.GET.get('digits',  'true').lower() == 'true'
    include_symbols = request.GET.get('symbols', 'true').lower() == 'true'

    # Build character pool — always include lowercase as a baseline
    pool = string.ascii_lowercase
    if include_upper:
        pool += string.ascii_uppercase
    if include_digits:
        pool += string.digits
    if include_symbols:
        pool += string.punctuation

    # secrets.choice() draws from the OS CSPRNG — safe for password generation
    password = ''.join(secrets.choice(pool) for _ in range(length))

    return JsonResponse({'password': password})
def opay():
    print("hello world")
 