# Auth Service

Serviço de autenticação construído com FastAPI, SQLAlchemy e PostgreSQL.

## Funcionalidades

- ✅ Registro e autenticação de usuários por aplicação
- ✅ Múltiplos usuários com mesmo email em aplicações diferentes
- ✅ Constraint única: email + application_id
- ✅ JWT tokens com informações da aplicação
- ✅ Login por application_id ou application_slug
- ✅ CRUD para Domains e Applications
- ✅ PostgreSQL como banco de dados
- ✅ Docker e Docker Compose
- ✅ Adminer para administração do banco

## Estrutura do Projeto

```
auth-service/
├── main.py              # Aplicação FastAPI principal
├── models.py            # Modelos SQLAlchemy
├── schemas.py           # Schemas Pydantic
├── crud.py              # Operações CRUD
├── auth.py              # Funções de autenticação
├── database.py          # Configuração do banco
├── requirements.txt     # Dependências Python
├── Dockerfile           # Imagem Docker
├── docker-compose.yml   # Orquestração dos serviços
├── .env                 # Variáveis de ambiente
└── init.sql            # Inicialização do banco
```

## Como executar

### Com Docker Compose (Recomendado)

1. Clone o repositório e navegue até a pasta:
```bash
cd auth-service
```

2. Execute com Docker Compose:
```bash
docker-compose up --build
```

3. A API estará disponível em: `http://localhost:8000`
4. Adminer (admin do banco) em: `http://localhost:8080`

### Manualmente

1. Instale as dependências:
```bash
pip install -r requirements.txt
```

2. Configure as variáveis de ambiente no `.env`

3. Execute a aplicação:
```bash
python main.py
```

## Endpoints da API

### Autenticação

- `POST /auth/register` - Registrar novo usuário (requer application_id)
- `POST /auth/login` - Login por application_id (retorna JWT token)
- `POST /auth/login-by-slug` - Login por application_slug (retorna JWT token)
- `GET /auth/me` - Informações do usuário autenticado
- `POST /auth/logout` - Logout

### Domains

- `POST /domains` - Criar domain
- `GET /domains` - Listar domains
- `GET /domains/{domain_id}` - Buscar domain por ID

### Applications

- `POST /applications` - Criar application
- `GET /applications` - Listar applications
- `GET /applications/{slug}` - Buscar application por slug
- `GET /applications/{application_id}/users` - Listar usuários de uma aplicação

### Utilidade

- `GET /health` - Health check

## Documentação da API

Com a aplicação rodando, acesse:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Exemplos de Uso

### Registrar usuário
```bash
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "application_id": "uuid-da-aplicacao"
  }'
```

### Login por Application ID
```bash
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "application_id": "uuid-da-aplicacao"
  }'
```

### Login por Application Slug (mais user-friendly)
```bash
curl -X POST "http://localhost:8000/auth/login-by-slug" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "application_slug": "academia"
  }'
```

### Criar Domain (requer token)
```bash
curl -X POST "http://localhost:8000/domains" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Academia System",
    "api_url": "https://api.academia.com",
    "admin_url": "https://admin.academia.com",
    "site_url": "https://academia.com",
    "db_url": "postgresql://..."
  }'
```

## Configuração

As principais configurações estão no arquivo `.env`:

- `DATABASE_URL`: URL de conexão com PostgreSQL
- `SECRET_KEY`: Chave secreta para JWT (MUDE EM PRODUÇÃO!)
- `POSTGRES_*`: Configurações do PostgreSQL

## Banco de Dados

O projeto usa PostgreSQL com as seguintes tabelas:

- `users`: Usuários do sistema (constraint única: email + application_id)
- `domains`: Domínios/ambientes
- `applications`: Aplicações vinculadas aos domínios

### Relacionamentos

- Um usuário pertence a uma aplicação (many-to-one)
- Uma aplicação pode ter vários usuários (one-to-many)
- Uma aplicação pertence a um domínio (many-to-one)
- Um domínio pode ter várias aplicações (one-to-many)
- **Importante**: O mesmo email pode existir em aplicações diferentes, mas nunca duplicado na mesma aplicação

## Segurança

- Senhas são hasheadas com bcrypt
- Autenticação via JWT tokens
- Tokens expiram em 30 minutos por padrão
- Validação de dados com Pydantic

## Desenvolvimento

Para desenvolvimento local, você pode:

1. Usar apenas o banco PostgreSQL via Docker:
```bash
docker-compose up db
```

2. Executar a aplicação localmente:
```bash
python main.py
```

## CORS (Cross-Origin Resource Sharing)

A API está configurada com CORS habilitado para permitir requisições de diferentes origens:

- **Desenvolvimento**: Permite todas as origens (`*`) para facilitar o desenvolvimento
- **Produção**: Recomenda-se especificar as origens exatas:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://meusite.com", "https://app.meusite.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
```

## Logs e Monitoramento

- Health check disponível em `/health`
- Logs estruturados via uvicorn
- Adminer para monitoramento do banco
