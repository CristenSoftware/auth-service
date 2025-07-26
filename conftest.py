import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import uuid

from database import Base, get_db
from main import app
from models import Domain, Application, User
from auth import get_password_hash


# Configuração do banco de dados em memória para testes
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session")
def db_engine():
    """Cria o engine do banco para a sessão de teste"""
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(db_engine):
    """Cria uma sessão de banco para cada teste"""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """Cria um cliente de teste FastAPI"""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_domain(db_session):
    """Cria um domain de exemplo para testes"""
    domain = Domain(
        id=uuid.uuid4(),
        name="Test Domain",
        api_url="https://api.test.com",
        admin_url="https://admin.test.com",
        site_url="https://test.com",
        db_url="postgresql://test:test@localhost/testdb"
    )
    db_session.add(domain)
    db_session.commit()
    db_session.refresh(domain)
    return domain


@pytest.fixture
def sample_application(db_session, sample_domain):
    """Cria uma aplicação de exemplo para testes"""
    application = Application(
        id=uuid.uuid4(),
        name="Test Application",
        slug="test-app",
        key="test-app-key-123",
        domain_id=sample_domain.id
    )
    db_session.add(application)
    db_session.commit()
    db_session.refresh(application)
    return application


@pytest.fixture
def sample_user(db_session, sample_application):
    """Cria um usuário de exemplo para testes"""
    user = User(
        id=uuid.uuid4(),
        email="test@example.com",
        senha_hash=get_password_hash("password123"),
        application_id=sample_application.id
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(client, sample_application):
    """Gera headers de autenticação para testes que precisam de token"""
    # Primeiro registra um usuário
    user_data = {
        "email": "auth_test@example.com",
        "password": "password123",
        "application_key": sample_application.key
    }
    client.post("/auth/register", json=user_data)

    # Faz login para obter token
    login_response = client.post("/auth/login", json=user_data)
    token = login_response.json()["access_token"]

    return {"Authorization": f"Bearer {token}"}
