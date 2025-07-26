from pydantic import BaseModel, EmailStr
from typing import Optional, ForwardRef
from datetime import datetime
import uuid

# Forward references para resolver dependências circulares
ApplicationResponseRef = ForwardRef('ApplicationResponse')

# User Schemas


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str
    application_key: str  # Mudança: usar key ao invés de ID


class UserResponse(UserBase):
    id: uuid.UUID
    created_at: datetime
    application_id: uuid.UUID  # Agora obrigatório

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    application_key: str  # Mudança: usar key ao invés de ID

# Schema para login por slug da aplicação (mais user-friendly)


class UserLoginBySlug(BaseModel):
    email: EmailStr
    password: str
    application_slug: str

# Domain Schemas


class DomainBase(BaseModel):
    name: str
    api_url: str
    admin_url: str
    site_url: str
    db_url: str


class DomainCreate(DomainBase):
    pass


class DomainResponse(DomainBase):
    id: uuid.UUID

    class Config:
        from_attributes = True

# Application Schemas


class ApplicationBase(BaseModel):
    name: str
    slug: str
    key: Optional[str] = None  # Key opcional para criar aplicação


class ApplicationCreate(ApplicationBase):
    domain_id: uuid.UUID


class ApplicationResponse(ApplicationBase):
    id: uuid.UUID
    domain_id: uuid.UUID
    key: str  # Sempre retorna a key na resposta

    class Config:
        from_attributes = True


class ApplicationWithUsers(ApplicationResponse):
    users: list[UserResponse] = []

# User with Application (definido após ApplicationResponse)


class UserWithApplication(UserResponse):
    application: Optional[ApplicationResponse] = None

# User Application Assignment Schema


class UserApplicationAssignment(BaseModel):
    user_id: uuid.UUID
    application_id: uuid.UUID

# Token Schemas


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
