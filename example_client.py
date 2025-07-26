"""
Exemplos de uso da API Auth Service em Python
Execute: pip install requests
"""

import requests
import json

BASE_URL = "http://localhost:8000"


class AuthServiceClient:
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
        self.token = None

    def register(self, email: str, password: str):
        """Registrar novo usuário"""
        response = requests.post(
            f"{self.base_url}/auth/register",
            json={"email": email, "password": password}
        )
        return response.json()

    def login(self, email: str, password: str):
        """Fazer login e obter token"""
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={"email": email, "password": password}
        )
        data = response.json()
        if response.status_code == 200:
            self.token = data["access_token"]
        return data

    def get_headers(self):
        """Headers com token de autenticação"""
        if not self.token:
            raise ValueError("Token não disponível. Faça login primeiro.")
        return {"Authorization": f"Bearer {self.token}"}

    def get_me(self):
        """Obter informações do usuário atual"""
        response = requests.get(
            f"{self.base_url}/auth/me",
            headers=self.get_headers()
        )
        return response.json()

    def create_domain(self, name: str, api_url: str, admin_url: str, site_url: str, db_url: str):
        """Criar novo domain"""
        response = requests.post(
            f"{self.base_url}/domains",
            headers=self.get_headers(),
            json={
                "name": name,
                "api_url": api_url,
                "admin_url": admin_url,
                "site_url": site_url,
                "db_url": db_url
            }
        )
        return response.json()

    def get_domains(self):
        """Listar domains"""
        response = requests.get(
            f"{self.base_url}/domains",
            headers=self.get_headers()
        )
        return response.json()

    def create_application(self, name: str, slug: str, domain_id: str):
        """Criar nova application"""
        response = requests.post(
            f"{self.base_url}/applications",
            headers=self.get_headers(),
            json={
                "name": name,
                "slug": slug,
                "domain_id": domain_id
            }
        )
        return response.json()

    def get_applications(self):
        """Listar applications"""
        response = requests.get(
            f"{self.base_url}/applications",
            headers=self.get_headers()
        )
        return response.json()

    def get_application_by_slug(self, slug: str):
        """Buscar application por slug"""
        response = requests.get(
            f"{self.base_url}/applications/{slug}",
            headers=self.get_headers()
        )
        return response.json()

    def assign_application_to_user(self, user_id: str, application_id: str):
        """Atribuir aplicação a um usuário"""
        response = requests.post(
            f"{self.base_url}/users/{user_id}/assign-application",
            headers=self.get_headers(),
            json={
                "user_id": user_id,
                "application_id": application_id
            }
        )
        return response.json()

    def remove_application_from_user(self, user_id: str):
        """Remover aplicação de um usuário"""
        response = requests.delete(
            f"{self.base_url}/users/{user_id}/remove-application",
            headers=self.get_headers()
        )
        return response.json()

    def get_user_application(self, user_id: str):
        """Buscar aplicação de um usuário"""
        response = requests.get(
            f"{self.base_url}/users/{user_id}/application",
            headers=self.get_headers()
        )
        return response.json()

    def get_application_users(self, application_id: str):
        """Buscar usuários de uma aplicação"""
        response = requests.get(
            f"{self.base_url}/applications/{application_id}/users",
            headers=self.get_headers()
        )
        return response.json()


def main():
    """Exemplo de uso"""
    client = AuthServiceClient()

    print("=== Testando Auth Service Client ===\n")

    # 1. Registrar usuário
    print("1. Registrando usuário...")
    try:
        user_data = client.register("test@example.com", "password123")
        print(f"Usuário criado: {user_data}")
    except Exception as e:
        print(f"Erro no registro (usuário pode já existir): {e}")

    # 2. Login
    print("\n2. Fazendo login...")
    login_data = client.login("test@example.com", "password123")
    print(f"Login: {login_data}")

    if client.token:
        # 3. Verificar usuário atual
        print("\n3. Verificando usuário atual...")
        me_data = client.get_me()
        print(f"Usuário atual: {me_data}")

        # 4. Criar domain
        print("\n4. Criando domain...")
        domain_data = client.create_domain(
            name="E-commerce System",
            api_url="https://api.ecommerce.com",
            admin_url="https://admin.ecommerce.com",
            site_url="https://ecommerce.com",
            db_url="postgresql://user:pass@localhost/ecommerce_db"
        )
        print(f"Domain criado: {domain_data}")

        domain_id = domain_data.get("id")

        if domain_id:
            # 5. Criar application
            print("\n5. Criando application...")
            app_data = client.create_application(
                name="Loja Virtual",
                slug="loja-virtual",
                domain_id=domain_id
            )
            print(f"Application criada: {app_data}")

        # 6. Listar domains
        print("\n6. Listando domains...")
        domains = client.get_domains()
        print(f"Domains: {domains}")

        # 7. Listar applications
        print("\n7. Listando applications...")
        applications = client.get_applications()
        print(f"Applications: {applications}")

        # 8. Buscar application por slug
        if applications:
            print("\n8. Buscando application por slug...")
            app_by_slug = client.get_application_by_slug("loja-virtual")
            print(f"Application por slug: {app_by_slug}")


if __name__ == "__main__":
    main()
