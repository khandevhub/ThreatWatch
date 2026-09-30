"""Secure loading and validation for the local ingest bearer token."""
import os

MIN_TOKEN_LENGTH = 32
MAX_TOKEN_LENGTH = 4096


class SecretConfigurationError(ValueError):
    """Raised when token sources or token material are misconfigured."""


def validate_ingest_token(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise SecretConfigurationError('INGEST_TOKEN must be text')
    token = value.strip()
    if len(token) < MIN_TOKEN_LENGTH or len(token) > MAX_TOKEN_LENGTH:
        raise SecretConfigurationError(
            f'INGEST_TOKEN must contain {MIN_TOKEN_LENGTH} to {MAX_TOKEN_LENGTH} characters')
    if any(not 33 <= ord(char) <= 126 for char in token):
        raise SecretConfigurationError('INGEST_TOKEN must use printable ASCII without spaces')
    return token


def load_ingest_token(environ=None):
    environ = os.environ if environ is None else environ
    value = environ.get('INGEST_TOKEN')
    secret_file = environ.get('INGEST_TOKEN_FILE')
    if value and secret_file:
        raise SecretConfigurationError('Configure only one ingest token source')
    if secret_file:
        try:
            with open(secret_file, 'r', encoding='utf-8') as stream:
                value = stream.read(MAX_TOKEN_LENGTH + 1)
        except OSError as exc:
            raise SecretConfigurationError('Unable to read INGEST_TOKEN_FILE') from exc
        if len(value) > MAX_TOKEN_LENGTH:
            raise SecretConfigurationError('INGEST_TOKEN_FILE exceeds the maximum token size')
    if value is None or value == '':
        return None
    return validate_ingest_token(value)
