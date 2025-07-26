from sqlalchemy.orm import Session
from models import User, Domain, Application
from schemas import UserCreate, DomainCreate, ApplicationCreate
from auth import get_password_hash, verify_password
import uuid

# User CRUD


def get_user_by_email_and_application_key(db: Session, email: str, application_key: str):
    """Buscar usuário por email e key da aplicação"""
    return db.query(User).join(Application).filter(
        User.email == email,
        Application.key == application_key
    ).first()


def get_user_by_email_and_application(db: Session, email: str, application_id: uuid.UUID):
    return db.query(User).filter(User.email == email, User.application_id == application_id).first()


def get_user_by_email_and_application_slug(db: Session, email: str, application_slug: str):
    return db.query(User).join(Application).filter(
        User.email == email,
        Application.slug == application_slug
    ).first()


def get_user_by_email(db: Session, email: str):
    # Esta função agora retorna todos os usuários com esse email (em diferentes apps)
    return db.query(User).filter(User.email == email).all()


def get_user_by_id(db: Session, user_id: uuid.UUID):
    return db.query(User).filter(User.id == user_id).first()


def get_user_with_application(db: Session, user_id: uuid.UUID):
    return db.query(User).filter(User.id == user_id).first()


def create_user(db: Session, user: UserCreate):
    # Buscar aplicação pela key
    application = get_application_by_key(db, user.application_key)
    if not application:
        raise ValueError(
            f"Application with key '{user.application_key}' not found")

    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        senha_hash=hashed_password,
        application_id=application.id
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user_by_key(db: Session, email: str, password: str, application_key: str):
    """Nova função: autenticar usuário por application_key"""
    user = get_user_by_email_and_application_key(db, email, application_key)
    if not user:
        return False
    if not verify_password(password, user.senha_hash):
        return False
    return user


def authenticate_user(db: Session, email: str, password: str, application_id: uuid.UUID):
    user = get_user_by_email_and_application(db, email, application_id)
    if not user:
        return False
    if not verify_password(password, user.senha_hash):
        return False
    return user


def authenticate_user_by_slug(db: Session, email: str, password: str, application_slug: str):
    user = get_user_by_email_and_application_slug(db, email, application_slug)
    if not user:
        return False
    if not verify_password(password, user.senha_hash):
        return False
    return user

# Domain CRUD


def get_domain_by_id(db: Session, domain_id: uuid.UUID):
    return db.query(Domain).filter(Domain.id == domain_id).first()


def create_domain(db: Session, domain: DomainCreate):
    db_domain = Domain(**domain.dict())
    db.add(db_domain)
    db.commit()
    db.refresh(db_domain)
    return db_domain


def get_domains(db: Session, skip: int = 0, limit: int = 100):
    return db.query(Domain).offset(skip).limit(limit).all()

# Application CRUD


def get_application_by_slug(db: Session, slug: str):
    return db.query(Application).filter(Application.slug == slug).first()


def get_application_by_key(db: Session, key: str):
    """Nova função: buscar aplicação pela key"""
    return db.query(Application).filter(Application.key == key).first()


def get_application_by_id(db: Session, application_id: uuid.UUID):
    return db.query(Application).filter(Application.id == application_id).first()


def get_application_with_users(db: Session, application_id: uuid.UUID):
    return db.query(Application).filter(Application.id == application_id).first()


def create_application(db: Session, application: ApplicationCreate):
    # Gerar uma key baseada no slug se não fornecida
    import secrets
    import string

    application_data = application.dict()

    # Se não tem key ou está vazia, gera uma automaticamente baseada no slug
    if not application_data.get('key'):
        # Gera uma key única de 16 caracteres
        key_chars = string.ascii_letters + string.digits
        random_suffix = ''.join(secrets.choice(key_chars) for _ in range(8))
        application_data['key'] = f"{application.slug}-{random_suffix}"

    db_application = Application(**application_data)
    db.add(db_application)
    db.commit()
    db.refresh(db_application)
    return db_application


def get_applications(db: Session, skip: int = 0, limit: int = 100):
    return db.query(Application).offset(skip).limit(limit).all()

# User-Application Assignment CRUD


def assign_user_to_application(db: Session, user_id: uuid.UUID, application_id: uuid.UUID):
    """Atribui uma aplicação a um usuário"""
    user = get_user_by_id(db, user_id)
    application = get_application_by_id(db, application_id)

    if not user or not application:
        return None

    user.application_id = application_id
    db.commit()
    db.refresh(user)
    return user


def remove_user_from_application(db: Session, user_id: uuid.UUID):
    """Remove a aplicação de um usuário"""
    user = get_user_by_id(db, user_id)

    if not user:
        return None

    user.application_id = None
    db.commit()
    db.refresh(user)
    return user


def get_users_by_application(db: Session, application_id: uuid.UUID):
    """Busca todos os usuários de uma aplicação"""
    return db.query(User).filter(User.application_id == application_id).all()


def get_user_application(db: Session, user_id: uuid.UUID):
    """Busca a aplicação de um usuário"""
    user = get_user_by_id(db, user_id)
    return user.application if user else None

# User-Application Association CRUD


def add_user_to_application(db: Session, user_id: uuid.UUID, application_id: uuid.UUID):
    """Adiciona um usuário a uma aplicação"""
    user = get_user_by_id(db, user_id)
    application = get_application_by_id(db, application_id)

    if not user or not application:
        return None

    if application not in user.applications:
        user.applications.append(application)
        db.commit()
        db.refresh(user)

    return user


def remove_user_from_application(db: Session, user_id: uuid.UUID, application_id: uuid.UUID):
    """Remove um usuário de uma aplicação"""
    user = get_user_by_id(db, user_id)
    application = get_application_by_id(db, application_id)

    if not user or not application:
        return None

    if application in user.applications:
        user.applications.remove(application)
        db.commit()
        db.refresh(user)

    return user


def get_user_applications(db: Session, user_id: uuid.UUID):
    """Busca todas as aplicações de um usuário"""
    user = get_user_by_id(db, user_id)
    return user.applications if user else []


def get_application_users(db: Session, application_id: uuid.UUID):
    """Busca todos os usuários de uma aplicação"""
    application = get_application_by_id(db, application_id)
    return application.users if application else []
