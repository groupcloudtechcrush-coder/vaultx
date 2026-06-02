from django.db import models
from django.contrib.auth.models import User


class StoredCredential(models.Model):
    """
    Stores an encrypted credential for a user.
    The encrypted_password field contains a Fernet-encrypted ciphertext string.
    The raw password is NEVER stored — only the ciphertext produced by Fernet.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='credentials'
    )
    website_name = models.CharField(max_length=100)
    website_url = models.URLField(blank=True)
    username_or_email = models.CharField(max_length=150)

    # Fernet produces a URL-safe base64-encoded token, but the underlying
    # encryption is AES-128-CBC + HMAC-SHA256 — far stronger than raw base64.
    encrypted_password = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Stored Credential'
        verbose_name_plural = 'Stored Credentials'

    def __str__(self):
        return f"{self.website_name} — {self.username_or_email}"
