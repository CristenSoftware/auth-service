import pytest
from datetime import datetime, timedelta
from jose import JWTError

from auth import (
    get_password_hash, verify_password, create_access_token,
    verify_token, ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM
)


class TestPasswordHashing:
    """Testes para funções de hash de senha"""

    def test_get_password_hash(self):
        """Testa se a função gera um hash válido"""
        password = "test_password123"
        hashed = get_password_hash(password)

        assert hashed is not None
        assert hashed != password  # Hash deve ser diferente da senha original
        assert len(hashed) > 0

    def test_get_password_hash_different_passwords(self):
        """Testa se senhas diferentes geram hashes diferentes"""
        password1 = "password123"
        password2 = "password456"

        hash1 = get_password_hash(password1)
        hash2 = get_password_hash(password2)

        assert hash1 != hash2

    def test_get_password_hash_same_password_different_hashes(self):
        """Testa se a mesma senha gera hashes diferentes (salt)"""
        password = "test_password123"

        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)

        # Com salt, os hashes devem ser diferentes mesmo para a mesma senha
        assert hash1 != hash2

    def test_verify_password_correct(self):
        """Testa verificação de senha correta"""
        password = "test_password123"
        hashed = get_password_hash(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Testa verificação de senha incorreta"""
        password = "test_password123"
        wrong_password = "wrong_password"
        hashed = get_password_hash(password)

        assert verify_password(wrong_password, hashed) is False

    def test_verify_password_empty_password(self):
        """Testa verificação com senha vazia"""
        password = "test_password123"
        hashed = get_password_hash(password)

        assert verify_password("", hashed) is False

    def test_verify_password_empty_hash(self):
        """Testa verificação com hash vazio"""
        password = "test_password123"

        assert verify_password(password, "") is False


class TestTokenGeneration:
    """Testes para geração de tokens JWT"""

    def test_create_access_token_basic(self):
        """Testa criação básica de token"""
        data = {"sub": "test@example.com", "app_key": "test-app-key"}
        token = create_access_token(data)

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_access_token_with_expiration(self):
        """Testa criação de token com expiração customizada"""
        data = {"sub": "test@example.com", "app_key": "test-app-key"}
        expires_delta = timedelta(minutes=30)

        token = create_access_token(data, expires_delta)

        assert token is not None
        assert isinstance(token, str)

    def test_create_access_token_different_data(self):
        """Testa se dados diferentes geram tokens diferentes"""
        data1 = {"sub": "user1@example.com", "app_key": "app1-key"}
        data2 = {"sub": "user2@example.com", "app_key": "app2-key"}

        token1 = create_access_token(data1)
        token2 = create_access_token(data2)

        assert token1 != token2

    def test_create_access_token_empty_data(self):
        """Testa criação de token com dados vazios"""
        data = {}
        token = create_access_token(data)

        assert token is not None
        assert isinstance(token, str)


class TestTokenVerification:
    """Testes para verificação de tokens JWT"""

    def test_verify_token_valid(self):
        """Testa verificação de token válido"""
        email = "test@example.com"
        app_key = "test-app-key"
        data = {"sub": email, "app_key": app_key}

        token = create_access_token(data)
        verified_email, verified_app_key = verify_token(token)

        assert verified_email == email
        assert verified_app_key == app_key

    def test_verify_token_invalid(self):
        """Testa verificação de token inválido"""
        invalid_token = "invalid.token.here"

        email, app_key = verify_token(invalid_token)

        assert email is None
        assert app_key is None

    def test_verify_token_expired(self):
        """Testa verificação de token expirado"""
        data = {"sub": "test@example.com", "app_key": "test-app-key"}
        expires_delta = timedelta(seconds=-1)  # Token já expirado

        token = create_access_token(data, expires_delta)
        email, app_key = verify_token(token)

        assert email is None
        assert app_key is None

    def test_verify_token_missing_sub(self):
        """Testa verificação de token sem campo 'sub'"""
        data = {"app_key": "test-app-key"}  # Faltando 'sub'

        token = create_access_token(data)
        email, app_key = verify_token(token)

        assert email is None
        assert app_key is None

    def test_verify_token_missing_app_key(self):
        """Testa verificação de token sem campo 'app_key'"""
        data = {"sub": "test@example.com"}  # Faltando 'app_key'

        token = create_access_token(data)
        email, app_key = verify_token(token)

        assert email is None
        assert app_key is None

    def test_verify_token_empty_string(self):
        """Testa verificação de token vazio"""
        email, app_key = verify_token("")

        assert email is None
        assert app_key is None

    def test_verify_token_none(self):
        """Testa verificação de token None"""
        email, app_key = verify_token(None)

        assert email is None
        assert app_key is None


class TestTokenExpiration:
    """Testes relacionados à expiração de tokens"""

    def test_default_expiration_time(self):
        """Testa se o tempo de expiração padrão está correto"""
        # Verificar se a constante está definida
        assert ACCESS_TOKEN_EXPIRE_MINUTES is not None
        assert isinstance(ACCESS_TOKEN_EXPIRE_MINUTES, int)
        assert ACCESS_TOKEN_EXPIRE_MINUTES > 0

    def test_token_valid_within_expiration(self):
        """Testa se token é válido dentro do tempo de expiração"""
        data = {"sub": "test@example.com", "app_key": "test-app-key"}
        expires_delta = timedelta(minutes=1)  # Token válido por 1 minuto

        token = create_access_token(data, expires_delta)
        email, app_key = verify_token(token)

        assert email == "test@example.com"
        assert app_key == "test-app-key"

    def test_token_structure(self):
        """Testa se o token tem a estrutura JWT correta"""
        data = {"sub": "test@example.com", "app_key": "test-app-key"}
        token = create_access_token(data)

        # Token JWT deve ter 3 partes separadas por pontos
        parts = token.split('.')
        assert len(parts) == 3


class TestConstants:
    """Testes para constantes do módulo auth"""

    def test_secret_key_exists(self):
        """Testa se SECRET_KEY está definida"""
        assert SECRET_KEY is not None
        assert isinstance(SECRET_KEY, str)
        assert len(SECRET_KEY) > 0

    def test_algorithm_exists(self):
        """Testa se ALGORITHM está definido"""
        assert ALGORITHM is not None
        assert isinstance(ALGORITHM, str)
        assert ALGORITHM == "HS256"

    def test_access_token_expire_minutes_exists(self):
        """Testa se ACCESS_TOKEN_EXPIRE_MINUTES está definido"""
        assert ACCESS_TOKEN_EXPIRE_MINUTES is not None
        assert isinstance(ACCESS_TOKEN_EXPIRE_MINUTES, int)


class TestEdgeCases:
    """Testes para casos extremos"""

    def test_very_long_password(self):
        """Testa hash de senha muito longa"""
        long_password = "a" * 1000
        hashed = get_password_hash(long_password)

        assert verify_password(long_password, hashed) is True

    def test_password_with_special_characters(self):
        """Testa senha com caracteres especiais"""
        special_password = "p@ssw0rd!@#$%^&*()_+{}[]|\\:;\"'<>?,./"
        hashed = get_password_hash(special_password)

        assert verify_password(special_password, hashed) is True

    def test_password_with_unicode_characters(self):
        """Testa senha com caracteres Unicode"""
        unicode_password = "pássword123áéíóú"
        hashed = get_password_hash(unicode_password)

        assert verify_password(unicode_password, hashed) is True

    def test_token_with_special_characters_in_data(self):
        """Testa criação de token com caracteres especiais nos dados"""
        data = {
            "sub": "tëst@example.com",
            "app_key": "tëst-äpp-kéy"
        }
        token = create_access_token(data)

        email, app_key = verify_token(token)
        assert email == "tëst@example.com"
        assert app_key == "tëst-äpp-kéy"


class TestSecurity:
    """Testes relacionados à segurança"""

    def test_password_hash_not_reversible(self):
        """Testa se o hash da senha não é reversível"""
        password = "test_password123"
        hashed = get_password_hash(password)

        # Não deve ser possível extrair a senha original do hash
        assert password not in hashed
        assert len(hashed) > len(password)

    def test_token_contains_no_sensitive_data(self):
        """Testa se o token não contém dados sensíveis em texto plano"""
        password = "sensitive_password"
        data = {"sub": "test@example.com", "app_key": "test-app-key"}

        token = create_access_token(data)

        # Token não deve conter a senha em texto plano
        assert password not in token

        # Token deve estar codificado (não deve conter email diretamente visível)
        assert "test@example.com" not in token

    def test_different_tokens_for_same_user_different_times(self):
        """Testa se tokens diferentes são gerados para o mesmo usuário em momentos diferentes"""
        data = {"sub": "test@example.com", "app_key": "test-app-key"}

        token1 = create_access_token(data)

        # Pequena pausa para garantir timestamps diferentes
        import time
        time.sleep(0.1)

        token2 = create_access_token(data)

        # Tokens devem ser diferentes devido aos timestamps diferentes
        assert token1 != token2
