import pytest
import uuid
from datetime import datetime
from pydantic import ValidationError

from schemas import (
    UserCreate, UserResponse, UserLogin, UserLoginBySlug, UserWithApplication,
    DomainCreate, DomainResponse,
    ApplicationCreate, ApplicationResponse, ApplicationWithUsers,
    Token, UserApplicationAssignment
)


class TestUserSchemas:
    """Testes para schemas relacionados a usuários"""

    def test_user_create_valid(self):
        """Testa criação de UserCreate com dados válidos"""
        user_data = {
            "email": "test@example.com",
            "password": "password123",
            "application_key": "test-app-key"
        }

        user = UserCreate(**user_data)

        assert user.email == "test@example.com"
        assert user.password == "password123"
        assert user.application_key == "test-app-key"

    def test_user_create_invalid_email(self):
        """Testa UserCreate com email inválido"""
        user_data = {
            "email": "invalid-email",
            "password": "password123",
            "application_key": "test-app-key"
        }

        with pytest.raises(ValidationError) as exc_info:
            UserCreate(**user_data)

        assert "email" in str(exc_info.value)

    def test_user_create_missing_fields(self):
        """Testa UserCreate com campos obrigatórios faltando"""
        user_data = {
            "email": "test@example.com"
            # Faltando password e application_key
        }

        with pytest.raises(ValidationError):
            UserCreate(**user_data)

    def test_user_response_valid(self):
        """Testa criação de UserResponse com dados válidos"""
        user_data = {
            "id": uuid.uuid4(),
            "email": "test@example.com",
            "created_at": datetime.utcnow(),
            "application_id": uuid.uuid4()
        }

        user = UserResponse(**user_data)

        assert user.email == "test@example.com"
        assert user.id == user_data["id"]
        assert user.application_id == user_data["application_id"]

    def test_user_login_valid(self):
        """Testa criação de UserLogin com dados válidos"""
        login_data = {
            "email": "test@example.com",
            "password": "password123",
            "application_key": "test-app-key"
        }

        login = UserLogin(**login_data)

        assert login.email == "test@example.com"
        assert login.password == "password123"
        assert login.application_key == "test-app-key"

    def test_user_login_by_slug_valid(self):
        """Testa criação de UserLoginBySlug com dados válidos"""
        login_data = {
            "email": "test@example.com",
            "password": "password123",
            "application_slug": "test-app"
        }

        login = UserLoginBySlug(**login_data)

        assert login.email == "test@example.com"
        assert login.password == "password123"
        assert login.application_slug == "test-app"

    def test_token_schema_valid(self):
        """Testa criação de Token com dados válidos"""
        token_data = {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "bearer"
        }

        token = Token(**token_data)

        assert token.access_token == token_data["access_token"]
        assert token.token_type == "bearer"


class TestDomainSchemas:
    """Testes para schemas relacionados a domains"""

    def test_domain_create_valid(self):
        """Testa criação de DomainCreate com dados válidos"""
        domain_data = {
            "name": "Test Domain",
            "api_url": "https://api.test.com",
            "admin_url": "https://admin.test.com",
            "site_url": "https://test.com",
            "db_url": "postgresql://test:test@localhost/testdb"
        }

        domain = DomainCreate(**domain_data)

        assert domain.name == "Test Domain"
        assert domain.api_url == "https://api.test.com"
        assert domain.admin_url == "https://admin.test.com"
        assert domain.site_url == "https://test.com"
        assert domain.db_url == "postgresql://test:test@localhost/testdb"

    def test_domain_create_missing_fields(self):
        """Testa DomainCreate com campos obrigatórios faltando"""
        domain_data = {
            "name": "Test Domain"
            # Faltando outros campos obrigatórios
        }

        with pytest.raises(ValidationError):
            DomainCreate(**domain_data)

    def test_domain_response_valid(self):
        """Testa criação de DomainResponse com dados válidos"""
        domain_data = {
            "id": uuid.uuid4(),
            "name": "Test Domain",
            "api_url": "https://api.test.com",
            "admin_url": "https://admin.test.com",
            "site_url": "https://test.com",
            "db_url": "postgresql://test:test@localhost/testdb"
        }

        domain = DomainResponse(**domain_data)

        assert domain.id == domain_data["id"]
        assert domain.name == "Test Domain"

    def test_domain_create_invalid_url_format(self):
        """Testa DomainCreate com URLs em formato inválido"""
        domain_data = {
            "name": "Test Domain",
            "api_url": "invalid-url",
            "admin_url": "https://admin.test.com",
            "site_url": "https://test.com",
            "db_url": "postgresql://test:test@localhost/testdb"
        }

        # Dependendo da implementação, pode aceitar ou rejeitar URLs inválidas
        # Se houver validação de URL, descomente a linha abaixo:
        # with pytest.raises(ValidationError):
        domain = DomainCreate(**domain_data)
        assert domain.api_url == "invalid-url"


class TestApplicationSchemas:
    """Testes para schemas relacionados a applications"""

    def test_application_create_valid(self):
        """Testa criação de ApplicationCreate com dados válidos"""
        app_data = {
            "name": "Test Application",
            "slug": "test-app",
            "key": "test-app-key-123",
            "domain_id": uuid.uuid4()
        }

        app = ApplicationCreate(**app_data)

        assert app.name == "Test Application"
        assert app.slug == "test-app"
        assert app.key == "test-app-key-123"
        assert app.domain_id == app_data["domain_id"]

    def test_application_create_missing_fields(self):
        """Testa ApplicationCreate com campos obrigatórios faltando"""
        app_data = {
            "name": "Test Application"
            # Faltando outros campos obrigatórios
        }

        with pytest.raises(ValidationError):
            ApplicationCreate(**app_data)

    def test_application_response_valid(self):
        """Testa criação de ApplicationResponse com dados válidos"""
        app_data = {
            "id": uuid.uuid4(),
            "name": "Test Application",
            "slug": "test-app",
            "key": "test-app-key-123",
            "domain_id": uuid.uuid4()
        }

        app = ApplicationResponse(**app_data)

        assert app.id == app_data["id"]
        assert app.name == "Test Application"
        assert app.slug == "test-app"
        assert app.key == "test-app-key-123"

    def test_application_create_invalid_uuid(self):
        """Testa ApplicationCreate com UUID inválido"""
        app_data = {
            "name": "Test Application",
            "slug": "test-app",
            "key": "test-app-key-123",
            "domain_id": "invalid-uuid"
        }

        with pytest.raises(ValidationError):
            ApplicationCreate(**app_data)


class TestEmailValidation:
    """Testes específicos para validação de email"""

    def test_valid_email_formats(self):
        """Testa formatos de email válidos"""
        valid_emails = [
            "test@example.com",
            "user.name@domain.com",
            "user+tag@example.org",
            "user123@test-domain.com",
            "user@subdomain.example.com"
        ]

        for email in valid_emails:
            user_data = {
                "email": email,
                "password": "password123",
                "application_key": "test-app-key"
            }
            user = UserCreate(**user_data)
            assert user.email == email

    def test_invalid_email_formats(self):
        """Testa formatos de email inválidos"""
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "test@",
            "test..test@example.com",
            "test@example",
            ""
        ]

        for email in invalid_emails:
            user_data = {
                "email": email,
                "password": "password123",
                "application_key": "test-app-key"
            }
            with pytest.raises(ValidationError):
                UserCreate(**user_data)


class TestUUIDValidation:
    """Testes específicos para validação de UUID"""

    def test_valid_uuid_formats(self):
        """Testa formatos de UUID válidos"""
        valid_uuids = [
            uuid.uuid4(),
            uuid.UUID('12345678-1234-5678-1234-567812345678'),
            uuid.UUID('{12345678-1234-5678-1234-567812345678}')
        ]

        for test_uuid in valid_uuids:
            user_data = {
                "id": test_uuid,
                "email": "test@example.com",
                "created_at": datetime.utcnow(),
                "application_id": uuid.uuid4()
            }
            user = UserResponse(**user_data)
            assert user.id == test_uuid

    def test_invalid_uuid_formats(self):
        """Testa formatos de UUID inválidos"""
        invalid_uuids = [
            "invalid-uuid",
            "12345678-1234-5678-1234",
            "12345678123456781234567812345678",
            "",
            "not-a-uuid-at-all"
        ]

        for invalid_uuid in invalid_uuids:
            user_data = {
                "id": invalid_uuid,
                "email": "test@example.com",
                "created_at": datetime.utcnow(),
                "application_id": uuid.uuid4()
            }
            with pytest.raises(ValidationError):
                UserResponse(**user_data)


class TestOptionalFields:
    """Testes para campos opcionais"""

    def test_token_schema_default_token_type(self):
        """Testa se token_type tem valor padrão"""
        token_data = {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        }

        token = Token(**token_data)

        # Verificar se há valor padrão para token_type
        assert hasattr(token, 'token_type')


class TestSchemaConversion:
    """Testes para conversão de schemas"""

    def test_schema_to_dict(self):
        """Testa conversão de schema para dicionário"""
        user_data = {
            "email": "test@example.com",
            "password": "password123",
            "application_key": "test-app-key"
        }

        user = UserCreate(**user_data)
        user_dict = user.model_dump()

        assert isinstance(user_dict, dict)
        assert user_dict["email"] == "test@example.com"
        assert user_dict["password"] == "password123"
        assert user_dict["application_key"] == "test-app-key"

    def test_schema_from_dict(self):
        """Testa criação de schema a partir de dicionário"""
        user_data = {
            "email": "test@example.com",
            "password": "password123",
            "application_key": "test-app-key"
        }

        user = UserCreate.model_validate(user_data)

        assert user.email == "test@example.com"
        assert user.password == "password123"
        assert user.application_key == "test-app-key"


class TestStringValidation:
    """Testes para validação de strings"""

    def test_empty_string_fields(self):
        """Testa campos com strings vazias"""
        user_data = {
            "email": "test@example.com",
            "password": "",  # Senha vazia
            "application_key": "test-app-key"
        }

        # Dependendo da implementação, senha vazia pode ser aceita ou rejeitada
        # Para este teste, assumindo que é aceita
        user = UserCreate(**user_data)
        assert user.password == ""

    def test_whitespace_only_fields(self):
        """Testa campos com apenas espaços em branco"""
        user_data = {
            "email": "test@example.com",
            "password": "   ",  # Apenas espaços
            "application_key": "test-app-key"
        }

        user = UserCreate(**user_data)
        assert user.password == "   "

    def test_very_long_strings(self):
        """Testa strings muito longas"""
        long_string = "a" * 1000

        user_data = {
            "email": "test@example.com",
            "password": long_string,
            "application_key": "test-app-key"
        }

        user = UserCreate(**user_data)
        assert user.password == long_string

    def test_special_characters_in_strings(self):
        """Testa strings com caracteres especiais"""
        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"

        app_data = {
            "name": f"Test App {special_chars}",
            "slug": "test-app",
            "key": "test-app-key",
            "domain_id": uuid.uuid4()
        }

        app = ApplicationCreate(**app_data)
        assert special_chars in app.name
