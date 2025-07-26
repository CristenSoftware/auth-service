import pytest
import uuid
from sqlalchemy.orm import Session

from crud import (
    create_user, get_user_by_email_and_application_key,
    get_user_by_email_and_application, get_user_by_email_and_application_slug,
    authenticate_user_by_key, authenticate_user_by_slug,
    create_domain, get_domain_by_id, get_domains,
    create_application, get_application_by_slug, get_application_by_key,
    get_applications, get_users_by_application
)
from schemas import UserCreate, DomainCreate, ApplicationCreate
from models import User, Domain, Application


class TestUserCRUD:
    """Testes para operações CRUD de usuários"""

    def test_create_user_success(self, db_session, sample_application):
        """Testa criação de usuário com sucesso"""
        user_create = UserCreate(
            email="test@example.com",
            password="password123",
            application_key=sample_application.key
        )

        user = create_user(db_session, user_create)

        assert user.email == "test@example.com"
        assert user.application_id == sample_application.id
        assert user.senha_hash is not None
        assert user.senha_hash != "password123"  # Deve estar hasheada

    def test_create_user_invalid_application(self, db_session):
        """Testa criação de usuário com aplicação inexistente"""
        user_create = UserCreate(
            email="test@example.com",
            password="password123",
            application_key="invalid-key"
        )

        with pytest.raises(ValueError, match="Application with key 'invalid-key' not found"):
            create_user(db_session, user_create)

    def test_get_user_by_email_and_application_key(self, db_session, sample_user, sample_application):
        """Testa busca de usuário por email e chave da aplicação"""
        user = get_user_by_email_and_application_key(
            db_session,
            email=sample_user.email,
            application_key=sample_application.key
        )

        assert user is not None
        assert user.id == sample_user.id
        assert user.email == sample_user.email

    def test_get_user_by_email_and_application_key_not_found(self, db_session, sample_application):
        """Testa busca de usuário inexistente"""
        user = get_user_by_email_and_application_key(
            db_session,
            email="nonexistent@example.com",
            application_key=sample_application.key
        )

        assert user is None

    def test_get_user_by_email_and_application(self, db_session, sample_user, sample_application):
        """Testa busca de usuário por email e ID da aplicação"""
        user = get_user_by_email_and_application(
            db_session,
            email=sample_user.email,
            application_id=sample_application.id
        )

        assert user is not None
        assert user.id == sample_user.id

    def test_get_user_by_email_and_application_slug(self, db_session, sample_user, sample_application):
        """Testa busca de usuário por email e slug da aplicação"""
        user = get_user_by_email_and_application_slug(
            db_session,
            email=sample_user.email,
            application_slug=sample_application.slug
        )

        assert user is not None
        assert user.id == sample_user.id

    def test_authenticate_user_by_key_success(self, db_session, sample_user, sample_application):
        """Testa autenticação de usuário por chave com sucesso"""
        user = authenticate_user_by_key(
            db_session,
            email=sample_user.email,
            password="password123",
            application_key=sample_application.key
        )

        assert user is not None
        assert user.id == sample_user.id

    def test_authenticate_user_by_key_wrong_password(self, db_session, sample_user, sample_application):
        """Testa autenticação com senha incorreta"""
        user = authenticate_user_by_key(
            db_session,
            email=sample_user.email,
            password="wrongpassword",
            application_key=sample_application.key
        )

        assert user is None

    def test_authenticate_user_by_slug_success(self, db_session, sample_user, sample_application):
        """Testa autenticação de usuário por slug com sucesso"""
        user = authenticate_user_by_slug(
            db_session,
            email=sample_user.email,
            password="password123",
            application_slug=sample_application.slug
        )

        assert user is not None
        assert user.id == sample_user.id


class TestDomainCRUD:
    """Testes para operações CRUD de domains"""

    def test_create_domain_success(self, db_session):
        """Testa criação de domain com sucesso"""
        domain_create = DomainCreate(
            name="Test Domain",
            api_url="https://api.test.com",
            admin_url="https://admin.test.com",
            site_url="https://test.com",
            db_url="postgresql://test:test@localhost/testdb"
        )

        domain = create_domain(db_session, domain_create)

        assert domain.name == "Test Domain"
        assert domain.api_url == "https://api.test.com"
        assert domain.admin_url == "https://admin.test.com"
        assert domain.site_url == "https://test.com"
        assert domain.db_url == "postgresql://test:test@localhost/testdb"
        assert domain.id is not None

    def test_get_domain_by_id_success(self, db_session, sample_domain):
        """Testa busca de domain por ID com sucesso"""
        domain = get_domain_by_id(db_session, domain_id=sample_domain.id)

        assert domain is not None
        assert domain.id == sample_domain.id
        assert domain.name == sample_domain.name

    def test_get_domain_by_id_not_found(self, db_session):
        """Testa busca de domain inexistente"""
        fake_id = uuid.uuid4()
        domain = get_domain_by_id(db_session, domain_id=fake_id)

        assert domain is None

    def test_get_domains_empty(self, db_session):
        """Testa listagem de domains quando está vazia"""
        domains = get_domains(db_session)

        assert domains == []

    def test_get_domains_with_data(self, db_session, sample_domain):
        """Testa listagem de domains com dados"""
        domains = get_domains(db_session)

        assert len(domains) == 1
        assert domains[0].id == sample_domain.id

    def test_get_domains_pagination(self, db_session):
        """Testa paginação na listagem de domains"""
        # Criar múltiplos domains
        for i in range(5):
            domain = Domain(
                name=f"Domain {i}",
                api_url=f"https://api{i}.test.com",
                admin_url=f"https://admin{i}.test.com",
                site_url=f"https://test{i}.com",
                db_url=f"postgresql://test{i}:test@localhost/testdb{i}"
            )
            db_session.add(domain)
        db_session.commit()

        # Testar skip e limit
        domains = get_domains(db_session, skip=0, limit=3)
        assert len(domains) == 3

        domains = get_domains(db_session, skip=3, limit=3)
        assert len(domains) == 2


class TestApplicationCRUD:
    """Testes para operações CRUD de applications"""

    def test_create_application_success(self, db_session, sample_domain):
        """Testa criação de aplicação com sucesso"""
        app_create = ApplicationCreate(
            name="Test App",
            slug="test-app",
            key="test-app-key",
            domain_id=sample_domain.id
        )

        app = create_application(db_session, app_create)

        assert app.name == "Test App"
        assert app.slug == "test-app"
        assert app.key == "test-app-key"
        assert app.domain_id == sample_domain.id
        assert app.id is not None

    def test_get_application_by_slug_success(self, db_session, sample_application):
        """Testa busca de aplicação por slug com sucesso"""
        app = get_application_by_slug(db_session, slug=sample_application.slug)

        assert app is not None
        assert app.id == sample_application.id
        assert app.slug == sample_application.slug

    def test_get_application_by_slug_not_found(self, db_session):
        """Testa busca de aplicação por slug inexistente"""
        app = get_application_by_slug(db_session, slug="nonexistent-slug")

        assert app is None

    def test_get_application_by_key_success(self, db_session, sample_application):
        """Testa busca de aplicação por chave com sucesso"""
        app = get_application_by_key(db_session, key=sample_application.key)

        assert app is not None
        assert app.id == sample_application.id
        assert app.key == sample_application.key

    def test_get_application_by_key_not_found(self, db_session):
        """Testa busca de aplicação por chave inexistente"""
        app = get_application_by_key(db_session, key="nonexistent-key")

        assert app is None

    def test_get_applications_empty(self, db_session):
        """Testa listagem de aplicações quando está vazia"""
        apps = get_applications(db_session)

        assert apps == []

    def test_get_applications_with_data(self, db_session, sample_application):
        """Testa listagem de aplicações com dados"""
        apps = get_applications(db_session)

        assert len(apps) == 1
        assert apps[0].id == sample_application.id

    def test_get_users_by_application_empty(self, db_session, sample_application):
        """Testa busca de usuários de uma aplicação sem usuários"""
        users = get_users_by_application(
            db_session, application_id=sample_application.id)

        assert users == []

    def test_get_users_by_application_with_users(self, db_session, sample_application, sample_user):
        """Testa busca de usuários de uma aplicação com usuários"""
        users = get_users_by_application(
            db_session, application_id=sample_application.id)

        assert len(users) == 1
        assert users[0].id == sample_user.id
        assert users[0].application_id == sample_application.id


class TestRelationships:
    """Testes para relacionamentos entre entidades"""

    def test_domain_application_relationship(self, db_session, sample_domain, sample_application):
        """Testa relacionamento entre domain e application"""
        # Buscar domain e verificar aplicações relacionadas
        domain = get_domain_by_id(db_session, sample_domain.id)
        assert len(domain.applications) == 1
        assert domain.applications[0].id == sample_application.id

    def test_application_user_relationship(self, db_session, sample_application, sample_user):
        """Testa relacionamento entre application e user"""
        # Buscar aplicação e verificar usuários relacionados
        app = get_application_by_slug(db_session, sample_application.slug)
        assert len(app.users) == 1
        assert app.users[0].id == sample_user.id

    def test_user_application_relationship(self, db_session, sample_user, sample_application):
        """Testa relacionamento entre user e application"""
        # Buscar usuário e verificar aplicação relacionada
        user = get_user_by_email_and_application_key(
            db_session,
            sample_user.email,
            sample_application.key
        )
        assert user.application.id == sample_application.id
        assert user.application.slug == sample_application.slug


class TestConstraints:
    """Testes para constraints do banco de dados"""

    def test_unique_email_per_application(self, db_session, sample_application):
        """Testa constraint de email único por aplicação"""
        # Criar primeiro usuário
        user_create = UserCreate(
            email="test@example.com",
            password="password123",
            application_key=sample_application.key
        )
        create_user(db_session, user_create)

        # Tentar criar segundo usuário com mesmo email na mesma aplicação
        with pytest.raises(Exception):  # Pode ser IntegrityError ou similar
            create_user(db_session, user_create)

    def test_same_email_different_applications(self, db_session, sample_domain):
        """Testa que o mesmo email pode existir em aplicações diferentes"""
        # Criar duas aplicações
        app1 = Application(
            name="App 1",
            slug="app-1",
            key="app-1-key",
            domain_id=sample_domain.id
        )
        app2 = Application(
            name="App 2",
            slug="app-2",
            key="app-2-key",
            domain_id=sample_domain.id
        )
        db_session.add(app1)
        db_session.add(app2)
        db_session.commit()

        # Criar mesmo email em aplicações diferentes
        user1_create = UserCreate(
            email="test@example.com",
            password="password123",
            application_key=app1.key
        )
        user2_create = UserCreate(
            email="test@example.com",
            password="password123",
            application_key=app2.key
        )

        user1 = create_user(db_session, user1_create)
        user2 = create_user(db_session, user2_create)

        assert user1.email == user2.email
        assert user1.application_id != user2.application_id

    def test_unique_application_slug(self, db_session, sample_domain):
        """Testa constraint de slug único para aplicações"""
        # Criar primeira aplicação
        app1 = Application(
            name="App 1",
            slug="unique-slug",
            key="app-1-key",
            domain_id=sample_domain.id
        )
        db_session.add(app1)
        db_session.commit()

        # Tentar criar segunda aplicação com mesmo slug
        app2 = Application(
            name="App 2",
            slug="unique-slug",  # Mesmo slug
            key="app-2-key",
            domain_id=sample_domain.id
        )
        db_session.add(app2)

        with pytest.raises(Exception):  # Deve dar erro de constraint
            db_session.commit()

    def test_unique_application_key(self, db_session, sample_domain):
        """Testa constraint de key única para aplicações"""
        # Criar primeira aplicação
        app1 = Application(
            name="App 1",
            slug="app-1",
            key="unique-key",
            domain_id=sample_domain.id
        )
        db_session.add(app1)
        db_session.commit()

        # Tentar criar segunda aplicação com mesma key
        app2 = Application(
            name="App 2",
            slug="app-2",
            key="unique-key",  # Mesma key
            domain_id=sample_domain.id
        )
        db_session.add(app2)

        with pytest.raises(Exception):  # Deve dar erro de constraint
            db_session.commit()
