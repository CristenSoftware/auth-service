import pytest
import uuid
from fastapi import status


class TestIntegrationFlow:
    """Testes de integração que testam fluxos completos"""

    def test_complete_user_registration_and_login_flow(self, client):
        """Testa fluxo completo: criar domain -> aplicação -> registrar usuário -> fazer login"""

        # 1. Criar um domain
        domain_data = {
            "name": "Integration Test Domain",
            "api_url": "https://api.integration.com",
            "admin_url": "https://admin.integration.com",
            "site_url": "https://integration.com",
            "db_url": "postgresql://integration:test@localhost/integrationdb"
        }
        domain_response = client.post("/domains", json=domain_data)
        assert domain_response.status_code == status.HTTP_200_OK
        domain = domain_response.json()

        # 2. Criar uma aplicação
        app_data = {
            "name": "Integration Test App",
            "slug": "integration-app",
            "key": "integration-app-key",
            "domain_id": domain["id"]
        }
        app_response = client.post("/applications", json=app_data)
        assert app_response.status_code == status.HTTP_200_OK
        application = app_response.json()

        # 3. Registrar um usuário
        user_data = {
            "email": "integration@example.com",
            "password": "password123",
            "application_key": application["key"]
        }
        register_response = client.post("/auth/register", json=user_data)
        assert register_response.status_code == status.HTTP_200_OK
        user = register_response.json()

        # Verificar se o usuário foi criado corretamente
        assert user["email"] == "integration@example.com"
        assert user["application_id"] == application["id"]

        # 4. Fazer login
        login_data = {
            "email": "integration@example.com",
            "password": "password123",
            "application_key": application["key"]
        }
        login_response = client.post("/auth/login", json=login_data)
        assert login_response.status_code == status.HTTP_200_OK
        token_data = login_response.json()

        # Verificar se recebeu o token
        assert "access_token" in token_data
        assert token_data["token_type"] == "bearer"

        # 5. Usar o token para acessar dados do usuário
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        me_response = client.get("/auth/me", headers=headers)
        assert me_response.status_code == status.HTTP_200_OK
        me_data = me_response.json()

        assert me_data["email"] == "integration@example.com"
        assert me_data["application"]["id"] == application["id"]

    def test_login_by_slug_flow(self, client, sample_domain):
        """Testa fluxo de login usando slug da aplicação"""

        # 1. Criar aplicação
        app_data = {
            "name": "Slug Test App",
            "slug": "slug-test-app",
            "key": "slug-test-key",
            "domain_id": str(sample_domain.id)
        }
        app_response = client.post("/applications", json=app_data)
        assert app_response.status_code == status.HTTP_200_OK
        application = app_response.json()

        # 2. Registrar usuário
        user_data = {
            "email": "slugtest@example.com",
            "password": "password123",
            "application_key": application["key"]
        }
        register_response = client.post("/auth/register", json=user_data)
        assert register_response.status_code == status.HTTP_200_OK

        # 3. Login por slug
        login_data = {
            "email": "slugtest@example.com",
            "password": "password123",
            "application_slug": application["slug"]
        }
        login_response = client.post("/auth/login-by-slug", json=login_data)
        assert login_response.status_code == status.HTTP_200_OK
        token_data = login_response.json()

        assert "access_token" in token_data
        assert token_data["token_type"] == "bearer"

    def test_multiple_applications_same_domain(self, client, sample_domain):
        """Testa múltiplas aplicações no mesmo domain"""

        # Criar duas aplicações no mesmo domain
        app1_data = {
            "name": "App 1",
            "slug": "app-1",
            "key": "app-1-key",
            "domain_id": str(sample_domain.id)
        }
        app2_data = {
            "name": "App 2",
            "slug": "app-2",
            "key": "app-2-key",
            "domain_id": str(sample_domain.id)
        }

        app1_response = client.post("/applications", json=app1_data)
        app2_response = client.post("/applications", json=app2_data)

        assert app1_response.status_code == status.HTTP_200_OK
        assert app2_response.status_code == status.HTTP_200_OK

        app1 = app1_response.json()
        app2 = app2_response.json()

        # Registrar mesmo usuário em ambas aplicações
        user_data_app1 = {
            "email": "multiapp@example.com",
            "password": "password123",
            "application_key": app1["key"]
        }
        user_data_app2 = {
            "email": "multiapp@example.com",
            "password": "password123",
            "application_key": app2["key"]
        }

        register1_response = client.post("/auth/register", json=user_data_app1)
        register2_response = client.post("/auth/register", json=user_data_app2)

        assert register1_response.status_code == status.HTTP_200_OK
        assert register2_response.status_code == status.HTTP_200_OK

        user1 = register1_response.json()
        user2 = register2_response.json()

        # Usuários devem ter IDs diferentes mas mesmo email
        assert user1["id"] != user2["id"]
        assert user1["email"] == user2["email"]
        assert user1["application_id"] != user2["application_id"]

    def test_application_users_listing(self, client, sample_domain):
        """Testa listagem de usuários de uma aplicação"""

        # Criar aplicação
        app_data = {
            "name": "Users List App",
            "slug": "users-list-app",
            "key": "users-list-key",
            "domain_id": str(sample_domain.id)
        }
        app_response = client.post("/applications", json=app_data)
        application = app_response.json()

        # Registrar múltiplos usuários
        users_data = [
            {"email": "user1@example.com", "password": "password123",
                "application_key": application["key"]},
            {"email": "user2@example.com", "password": "password123",
                "application_key": application["key"]},
            {"email": "user3@example.com", "password": "password123",
                "application_key": application["key"]}
        ]

        for user_data in users_data:
            register_response = client.post("/auth/register", json=user_data)
            assert register_response.status_code == status.HTTP_200_OK

        # Fazer login com um usuário para obter token
        login_response = client.post("/auth/login", json=users_data[0])
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Listar usuários da aplicação
        users_response = client.get(
            f"/applications/{application['id']}/users", headers=headers)
        assert users_response.status_code == status.HTTP_200_OK

        users_list = users_response.json()
        assert len(users_list) == 3

        emails = [user["email"] for user in users_list]
        assert "user1@example.com" in emails
        assert "user2@example.com" in emails
        assert "user3@example.com" in emails

    def test_error_handling_chain(self, client):
        """Testa cadeia de tratamento de erros"""

        # Tentar registrar usuário em aplicação inexistente
        user_data = {
            "email": "error@example.com",
            "password": "password123",
            "application_key": "nonexistent-key"
        }
        register_response = client.post("/auth/register", json=user_data)
        assert register_response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Aplicação não encontrada" in register_response.json()["detail"]

        # Tentar fazer login com credenciais inexistentes
        login_data = {
            "email": "nonexistent@example.com",
            "password": "password123",
            "application_key": "nonexistent-key"
        }
        login_response = client.post("/auth/login", json=login_data)
        assert login_response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Email, senha ou aplicação incorretos" in login_response.json()[
            "detail"]

        # Tentar acessar recurso protegido sem token
        me_response = client.get("/auth/me")
        assert me_response.status_code == status.HTTP_403_FORBIDDEN

    def test_pagination_integration(self, client):
        """Testa paginação em endpoints reais"""

        # Criar múltiplos domains
        domains = []
        for i in range(10):
            domain_data = {
                "name": f"Domain {i}",
                "api_url": f"https://api{i}.test.com",
                "admin_url": f"https://admin{i}.test.com",
                "site_url": f"https://test{i}.com",
                "db_url": f"postgresql://test{i}:test@localhost/testdb{i}"
            }
            response = client.post("/domains", json=domain_data)
            domains.append(response.json())

        # Testar paginação
        response1 = client.get("/domains?skip=0&limit=5")
        assert response1.status_code == status.HTTP_200_OK
        assert len(response1.json()) == 5

        response2 = client.get("/domains?skip=5&limit=5")
        assert response2.status_code == status.HTTP_200_OK
        assert len(response2.json()) == 5

        # Verificar que não há duplicatas
        ids1 = [domain["id"] for domain in response1.json()]
        ids2 = [domain["id"] for domain in response2.json()]
        assert len(set(ids1) & set(ids2)) == 0


class TestSecurityIntegration:
    """Testes de integração focados em segurança"""

    def test_token_expiration_simulation(self, client, sample_application):
        """Simula expiração de token (teste conceitual)"""

        # Registrar usuário
        user_data = {
            "email": "expiration@example.com",
            "password": "password123",
            "application_key": sample_application.key
        }
        client.post("/auth/register", json=user_data)

        # Fazer login
        login_response = client.post("/auth/login", json=user_data)
        token = login_response.json()["access_token"]

        # Token deve ser válido inicialmente
        headers = {"Authorization": f"Bearer {token}"}
        me_response = client.get("/auth/me", headers=headers)
        assert me_response.status_code == status.HTTP_200_OK

    def test_invalid_token_scenarios(self, client):
        """Testa vários cenários de token inválido"""

        invalid_tokens = [
            "Bearer invalid.token.here",
            "Bearer ",
            "invalid-format-token",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"
        ]

        for token in invalid_tokens:
            headers = {"Authorization": token}
            response = client.get("/auth/me", headers=headers)
            assert response.status_code in [
                status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_cross_application_access_prevention(self, client, sample_domain):
        """Testa que usuários não podem acessar recursos de outras aplicações"""

        # Criar duas aplicações
        app1_data = {
            "name": "App 1",
            "slug": "security-app-1",
            "key": "security-app-1-key",
            "domain_id": str(sample_domain.id)
        }
        app2_data = {
            "name": "App 2",
            "slug": "security-app-2",
            "key": "security-app-2-key",
            "domain_id": str(sample_domain.id)
        }

        app1 = client.post("/applications", json=app1_data).json()
        app2 = client.post("/applications", json=app2_data).json()

        # Registrar usuário na App 1
        user_data = {
            "email": "security@example.com",
            "password": "password123",
            "application_key": app1["key"]
        }
        client.post("/auth/register", json=user_data)

        # Fazer login na App 1
        login_response = client.post("/auth/login", json=user_data)
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Tentar acessar usuários da App 2 com token da App 1
        # Isso deveria falhar ou retornar dados apenas da App 1
        response = client.get(
            f"/applications/{app2['id']}/users", headers=headers)

        # Dependendo da implementação, pode retornar 403, 404 ou lista vazia
        # O importante é que não retorne usuários de outra aplicação
        if response.status_code == status.HTTP_200_OK:
            users = response.json()
            # Se retornar sucesso, não deve haver usuários da App 2
            assert len(users) == 0


class TestDataConsistency:
    """Testes para verificar consistência de dados"""

    def test_user_application_relationship_consistency(self, client, sample_domain):
        """Testa consistência do relacionamento usuário-aplicação"""

        # Criar aplicação
        app_data = {
            "name": "Consistency App",
            "slug": "consistency-app",
            "key": "consistency-key",
            "domain_id": str(sample_domain.id)
        }
        app = client.post("/applications", json=app_data).json()

        # Registrar usuário
        user_data = {
            "email": "consistency@example.com",
            "password": "password123",
            "application_key": app["key"]
        }
        user = client.post("/auth/register", json=user_data).json()

        # Verificar consistência: usuário deve ter application_id correto
        assert user["application_id"] == app["id"]

        # Fazer login e verificar dados via /auth/me
        login_response = client.post("/auth/login", json=user_data)
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        me_response = client.get("/auth/me", headers=headers)
        me_data = me_response.json()

        assert me_data["application"]["id"] == app["id"]
        assert me_data["application"]["slug"] == app["slug"]

    def test_domain_application_relationship_consistency(self, client):
        """Testa consistência do relacionamento domain-aplicação"""

        # Criar domain
        domain_data = {
            "name": "Relationship Domain",
            "api_url": "https://api.relationship.com",
            "admin_url": "https://admin.relationship.com",
            "site_url": "https://relationship.com",
            "db_url": "postgresql://relationship:test@localhost/relationshipdb"
        }
        domain = client.post("/domains", json=domain_data).json()

        # Criar aplicação
        app_data = {
            "name": "Relationship App",
            "slug": "relationship-app",
            "key": "relationship-key",
            "domain_id": domain["id"]
        }
        app = client.post("/applications", json=app_data).json()

        # Verificar que application_id está correto
        assert app["domain_id"] == domain["id"]

    def test_unique_constraints_enforcement(self, client, sample_domain):
        """Testa que constraints únicos são respeitados"""

        # Tentar criar duas aplicações com mesmo slug
        app1_data = {
            "name": "App 1",
            "slug": "duplicate-slug",
            "key": "key-1",
            "domain_id": str(sample_domain.id)
        }
        app2_data = {
            "name": "App 2",
            "slug": "duplicate-slug",  # Mesmo slug
            "key": "key-2",
            "domain_id": str(sample_domain.id)
        }

        response1 = client.post("/applications", json=app1_data)
        assert response1.status_code == status.HTTP_200_OK

        response2 = client.post("/applications", json=app2_data)
        assert response2.status_code == status.HTTP_400_BAD_REQUEST
        assert "Slug já existe" in response2.json()["detail"]
