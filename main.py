from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from database import get_db, engine, Base
from models import User, Domain, Application
from schemas import (
    UserCreate, UserResponse, UserLogin, UserLoginBySlug, UserWithApplication,
    DomainCreate, DomainResponse,
    ApplicationCreate, ApplicationResponse, ApplicationWithUsers,
    Token, UserApplicationAssignment
)
from crud import (
    get_user_by_email_and_application, get_user_by_email_and_application_slug,
    get_user_by_email_and_application_key, authenticate_user_by_key,
    create_user, authenticate_user, authenticate_user_by_slug, get_user_with_application,
    get_domain_by_id, create_domain, get_domains,
    get_application_by_slug, get_application_by_key, create_application, get_applications, get_application_by_id,
    get_users_by_application, get_user_application
)
from auth import create_access_token, verify_token, ACCESS_TOKEN_EXPIRE_MINUTES
from datetime import timedelta
import uuid

# Criar as tabelas
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth Service API",
    description="Serviço de autenticação para aplicações",
    version="1.0.0"
)

security = HTTPBearer()

# Dependency para verificar token


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    email, application_key = verify_token(token)
    if email is None or application_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = get_user_by_email_and_application_key(
        db, email=email, application_key=application_key)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário não encontrado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

# Rotas da API


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "Auth Service is running"}

# Rotas de Autenticação


@app.post("/auth/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    # Primeiro verifica se a aplicação existe
    application = get_application_by_key(db, key=user.application_key)
    if not application:
        raise HTTPException(
            status_code=400, detail="Aplicação não encontrada")

    # Verifica se o usuário já existe nesta aplicação
    db_user = get_user_by_email_and_application_key(
        db, email=user.email, application_key=user.application_key)
    if db_user:
        raise HTTPException(
            status_code=400, detail="Email já registrado nesta aplicação")
    return create_user(db=db, user=user)


@app.post("/auth/login", response_model=Token)
def login(user_credentials: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user_by_key(db, user_credentials.email,
                                    user_credentials.password, user_credentials.application_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email, senha ou aplicação incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "app_key": user_credentials.application_key},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/login-by-slug", response_model=Token)
def login_by_slug(user_credentials: UserLoginBySlug, db: Session = Depends(get_db)):
    user = authenticate_user_by_slug(
        db, user_credentials.email, user_credentials.password, user_credentials.application_slug)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email, senha ou aplicação incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "app_id": str(user.application_id)},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/auth/me", response_model=UserWithApplication)
def read_users_me(current_user: User = Depends(get_current_user)):
    """Retorna informações do usuário atual incluindo sua aplicação"""
    return current_user


@app.post("/auth/logout")
def logout():
    # Em uma implementação real, você poderia invalidar o token aqui
    return {"message": "Logout realizado com sucesso"}

# Rotas de Domains


@app.post("/domains", response_model=DomainResponse)
def create_domain_endpoint(domain: DomainCreate, db: Session = Depends(get_db)):
    return create_domain(db=db, domain=domain)


@app.get("/domains", response_model=list[DomainResponse])
def read_domains(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    domains = get_domains(db, skip=skip, limit=limit)
    return domains


@app.get("/domains/{domain_id}", response_model=DomainResponse)
def read_domain(domain_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_domain = get_domain_by_id(db, domain_id=domain_id)
    if db_domain is None:
        raise HTTPException(status_code=404, detail="Domain não encontrado")
    return db_domain

# Rotas de Applications


@app.post("/applications", response_model=ApplicationResponse)
def create_application_endpoint(application: ApplicationCreate, db: Session = Depends(get_db)):
    # Verificar se o domain existe
    domain = get_domain_by_id(db, application.domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain não encontrado")

    # Verificar se o slug já existe
    existing_app = get_application_by_slug(db, application.slug)
    if existing_app:
        raise HTTPException(status_code=400, detail="Slug já existe")

    return create_application(db=db, application=application)


@app.get("/applications", response_model=list[ApplicationResponse])
def read_applications(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    applications = get_applications(db, skip=skip, limit=limit)
    return applications


@app.get("/applications/{slug}", response_model=ApplicationResponse)
def read_application_by_slug(slug: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_application = get_application_by_slug(db, slug=slug)
    if db_application is None:
        raise HTTPException(
            status_code=404, detail="Application não encontrada")
    return db_application


@app.get("/applications/{application_id}/users", response_model=list[UserResponse])
def get_application_users_endpoint(
    application_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Busca todos os usuários de uma aplicação"""
    users = get_users_by_application(db, application_id)
    return users

# Rota de healthcheck


@app.get("/health")
def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
