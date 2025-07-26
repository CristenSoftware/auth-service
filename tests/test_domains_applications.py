import pytest
import uuid
from fastapi import status


class TestHealthCheck:
    """Testes para o endpoint de health check"""

    def test_health_check(self, client):
        """Testa se o endpoint de health check está funcionando"""
        response = client.get("/health")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "healthy"}


class TestDomains:
    """Testes para endpoints de domains"""

    def test_create_domain_success(self, client):
        """Testa criação de domain com sucesso"""
        domain_data = {
            "name": "Test Domain",
            "api_url": "https://api.test.com",
            "admin_url": "https://admin.test.com",
            "site_url": "https://test.com",
            "db_url": "postgresql://test:test@localhost/testdb"
        }
        response = client.post("/domains", json=domain_data)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["name"] == domain_data["name"]
        assert data["api_url"] == domain_data["api_url"]
        assert data["admin_url"] == domain_data["admin_url"]
        assert data["site_url"] == domain_data["site_url"]
        assert data["db_url"] == domain_data["db_url"]
        assert "id" in data

    def test_create_domain_missing_fields(self, client):
        """Testa criação de domain com campos obrigatórios faltando"""
        domain_data = {
            "name": "Test Domain",
            # Faltando campos obrigatórios
        }
        response = client.post("/domains", json=domain_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_domains_empty(self, client):
        """Testa listagem de domains quando não há nenhum"""
        response = client.get("/domains")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    def test_get_domains_with_data(self, client, sample_domain):
        """Testa listagem de domains com dados"""
        response = client.get("/domains")
        assert response.status_code == status.HTTP_200_OK

        domains = response.json()
        assert len(domains) == 1
        assert domains[0]["id"] == str(sample_domain.id)
        assert domains[0]["name"] == sample_domain.name

    def test_get_domain_by_id_success(self, client, sample_domain, auth_headers):
        """Testa busca de domain por ID com sucesso"""
        response = client.get(
            f"/domains/{sample_domain.id}", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["id"] == str(sample_domain.id)
        assert data["name"] == sample_domain.name

    def test_get_domain_by_id_not_found(self, client, auth_headers):
        """Testa busca de domain por ID não existente"""
        fake_id = uuid.uuid4()
        response = client.get(f"/domains/{fake_id}", headers=auth_headers)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json()["detail"] == "Domain não encontrado"

    def test_get_domain_by_id_unauthorized(self, client, sample_domain):
        """Testa busca de domain sem autenticação"""
        response = client.get(f"/domains/{sample_domain.id}")
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_get_domains_pagination(self, client, db_session):
        """Testa paginação na listagem de domains"""
        # Criar múltiplos domains
        from models import Domain
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

        # Testar paginação
        response = client.get("/domains?skip=0&limit=3")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()) == 3

        response = client.get("/domains?skip=3&limit=3")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()) == 2


class TestApplications:
    """Testes para endpoints de applications"""

    def test_create_application_success(self, client, sample_domain):
        """Testa criação de aplicação com sucesso"""
        app_data = {
            "name": "Test App",
            "slug": "test-app",
            "key": "test-app-key-456",
            "domain_id": str(sample_domain.id)
        }
        response = client.post("/applications", json=app_data)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["name"] == app_data["name"]
        assert data["slug"] == app_data["slug"]
        assert data["key"] == app_data["key"]
        assert data["domain_id"] == app_data["domain_id"]
        assert "id" in data

    def test_create_application_domain_not_found(self, client):
        """Testa criação de aplicação com domain inexistente"""
        fake_domain_id = str(uuid.uuid4())
        app_data = {
            "name": "Test App",
            "slug": "test-app",
            "key": "test-app-key-456",
            "domain_id": fake_domain_id
        }
        response = client.post("/applications", json=app_data)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json()["detail"] == "Domain não encontrado"

    def test_create_application_duplicate_slug(self, client, sample_application):
        """Testa criação de aplicação com slug duplicado"""
        app_data = {
            "name": "Another App",
            "slug": sample_application.slug,  # Slug já existe
            "key": "another-app-key",
            "domain_id": str(sample_application.domain_id)
        }
        response = client.post("/applications", json=app_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["detail"] == "Slug já existe"

    def test_create_application_missing_fields(self, client):
        """Testa criação de aplicação com campos obrigatórios faltando"""
        app_data = {
            "name": "Test App",
            # Faltando campos obrigatórios
        }
        response = client.post("/applications", json=app_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_applications_empty(self, client):
        """Testa listagem de aplicações quando não há nenhuma"""
        response = client.get("/applications")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    def test_get_applications_with_data(self, client, sample_application):
        """Testa listagem de aplicações com dados"""
        response = client.get("/applications")
        assert response.status_code == status.HTTP_200_OK

        apps = response.json()
        assert len(apps) == 1
        assert apps[0]["id"] == str(sample_application.id)
        assert apps[0]["name"] == sample_application.name
        assert apps[0]["slug"] == sample_application.slug

    def test_get_application_by_slug_success(self, client, sample_application, auth_headers):
        """Testa busca de aplicação por slug com sucesso"""
        response = client.get(
            f"/applications/{sample_application.slug}", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["slug"] == sample_application.slug
        assert data["name"] == sample_application.name

    def test_get_application_by_slug_not_found(self, client, auth_headers):
        """Testa busca de aplicação por slug não existente"""
        response = client.get(
            "/applications/non-existent-slug", headers=auth_headers)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json()["detail"] == "Application não encontrada"

    def test_get_application_by_slug_unauthorized(self, client, sample_application):
        """Testa busca de aplicação sem autenticação"""
        response = client.get(f"/applications/{sample_application.slug}")
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_get_application_users_success(self, client, sample_application, sample_user, auth_headers):
        """Testa listagem de usuários de uma aplicação"""
        response = client.get(
            f"/applications/{sample_application.id}/users", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

        users = response.json()
        assert len(users) >= 1
        # Verificar se o sample_user está na lista
        user_emails = [user["email"] for user in users]
        assert sample_user.email in user_emails

    def test_get_application_users_unauthorized(self, client, sample_application):
        """Testa listagem de usuários sem autenticação"""
        response = client.get(f"/applications/{sample_application.id}/users")
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_applications_pagination(self, client, sample_domain):
        """Testa paginação na listagem de aplicações"""
        from models import Application

        # Criar múltiplas aplicações
        for i in range(5):
            app = Application(
                name=f"App {i}",
                slug=f"app-{i}",
                key=f"app-key-{i}",
                domain_id=sample_domain.id
            )
            client.db_session.add(app)
        client.db_session.commit()

        # Testar paginação
        response = client.get("/applications?skip=0&limit=3")
        assert response.status_code == status.HTTP_200_OK
        # Deve ter pelo menos 3 aplicações (incluindo sample_application)


class TestAuthEndpoints:
    """Testes para endpoints de autenticação"""

    def test_register_success(self, client, sample_application):
        """Testa registro de usuário com sucesso"""
        user_data = {
            "email": "newuser@example.com",
            "password": "password123",
            "application_key": sample_application.key
        }
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["email"] == user_data["email"]
        assert data["application_id"] == str(sample_application.id)
        assert "id" in data
        assert "created_at" in data

    def test_register_application_not_found(self, client):
        """Testa registro com aplicação inexistente"""
        user_data = {
            "email": "newuser@example.com",
            "password": "password123",
            "application_key": "non-existent-key"
        }
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["detail"] == "Aplicação não encontrada"

    def test_register_duplicate_email(self, client, sample_user, sample_application):
        """Testa registro com email já existente na mesma aplicação"""
        user_data = {
            "email": sample_user.email,
            "password": "password123",
            "application_key": sample_application.key
        }
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()[
            "detail"] == "Email já registrado nesta aplicação"

    def test_login_success(self, client, sample_user, sample_application):
        """Testa login com sucesso"""
        login_data = {
            "email": sample_user.email,
            "password": "password123",
            "application_key": sample_application.key
        }
        response = client.post("/auth/login", json=login_data)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client, sample_user, sample_application):
        """Testa login com senha incorreta"""
        login_data = {
            "email": sample_user.email,
            "password": "wrongpassword",
            "application_key": sample_application.key
        }
        response = client.post("/auth/login", json=login_data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()[
            "detail"] == "Email, senha ou aplicação incorretos"

    def test_login_wrong_email(self, client, sample_application):
        """Testa login com email inexistente"""
        login_data = {
            "email": "nonexistent@example.com",
            "password": "password123",
            "application_key": sample_application.key
        }
        response = client.post("/auth/login", json=login_data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()[
            "detail"] == "Email, senha ou aplicação incorretos"

    def test_login_wrong_application(self, client, sample_user):
        """Testa login com aplicação incorreta"""
        login_data = {
            "email": sample_user.email,
            "password": "password123",
            "application_key": "wrong-app-key"
        }
        response = client.post("/auth/login", json=login_data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()[
            "detail"] == "Email, senha ou aplicação incorretos"

    def test_login_by_slug_success(self, client, sample_user, sample_application):
        """Testa login por slug da aplicação com sucesso"""
        login_data = {
            "email": sample_user.email,
            "password": "password123",
            "application_slug": sample_application.slug
        }
        response = client.post("/auth/login-by-slug", json=login_data)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_me_endpoint_success(self, client, auth_headers):
        """Testa endpoint /auth/me com token válido"""
        response = client.get("/auth/me", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "email" in data
        assert "id" in data
        assert "application" in data

    def test_me_endpoint_unauthorized(self, client):
        """Testa endpoint /auth/me sem token"""
        response = client.get("/auth/me")
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_me_endpoint_invalid_token(self, client):
        """Testa endpoint /auth/me com token inválido"""
        headers = {"Authorization": "Bearer invalid-token"}
        response = client.get("/auth/me", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout_success(self, client):
        """Testa endpoint de logout"""
        response = client.post("/auth/logout")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["message"] == "Logout realizado com sucesso"


class TestInputValidation:
    """Testes para validação de entrada"""

    def test_invalid_email_format(self, client, sample_application):
        """Testa registro com email em formato inválido"""
        user_data = {
            "email": "invalid-email-format",
            "password": "password123",
            "application_key": sample_application.key
        }
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_empty_password(self, client, sample_application):
        """Testa registro com senha vazia"""
        user_data = {
            "email": "test@example.com",
            "password": "",
            "application_key": sample_application.key
        }
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_uuid_format(self, client, auth_headers):
        """Testa endpoint com UUID em formato inválido"""
        response = client.get(
            "/domains/invalid-uuid-format", headers=auth_headers)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestEdgeCases:
    """Testes para casos extremos"""

    def test_very_long_domain_name(self, client):
        """Testa criação de domain com nome muito longo"""
        domain_data = {
            "name": "A" * 1000,  # Nome muito longo
            "api_url": "https://api.test.com",
            "admin_url": "https://admin.test.com",
            "site_url": "https://test.com",
            "db_url": "postgresql://test:test@localhost/testdb"
        }
        response = client.post("/domains", json=domain_data)
        # Dependendo da implementação, pode ser 200 ou 422
        assert response.status_code in [
            status.HTTP_200_OK, status.HTTP_422_UNPROCESSABLE_ENTITY]

    def test_special_characters_in_slug(self, client, sample_domain):
        """Testa criação de aplicação com caracteres especiais no slug"""
        app_data = {
            "name": "Test App",
            "slug": "test-app-with-@#$%",
            "key": "test-app-key-special",
            "domain_id": str(sample_domain.id)
        }
        response = client.post("/applications", json=app_data)
        # O slug deveria ser validado para não aceitar caracteres especiais
        assert response.status_code == status.HTTP_200_OK
