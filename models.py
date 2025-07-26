from sqlalchemy import Column, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base
import uuid
from datetime import datetime


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4, index=True)
    email = Column(String, nullable=False, index=True)  # Removido unique=True
    senha_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    application_id = Column(UUID(as_uuid=True), ForeignKey(
        "applications.id"), nullable=False)  # Agora obrigatório

    # Relacionamento many-to-one com application
    application = relationship("Application", back_populates="users")

    # Constraint única para email + application_id
    __table_args__ = (
        UniqueConstraint('email', 'application_id',
                         name='_user_email_application_uc'),
    )


class Domain(Base):
    __tablename__ = "domains"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4, index=True)
    name = Column(String, nullable=False)
    api_url = Column(String, nullable=False)
    admin_url = Column(String, nullable=False)
    site_url = Column(String, nullable=False)
    db_url = Column(String, nullable=False)

    # Relacionamento com applications
    applications = relationship("Application", back_populates="domain")


class Application(Base):
    __tablename__ = "applications"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4, index=True)
    name = Column(String, nullable=False)  # Ex: "Sistema de Academia"
    slug = Column(String, unique=True, index=True,
                  nullable=False)  # Ex: "academia"
    key = Column(String, unique=True, index=True,
                 nullable=False)  # Nova key única para autenticação
    domain_id = Column(UUID(as_uuid=True), ForeignKey(
        "domains.id"), nullable=False)

    # Relacionamentos
    domain = relationship("Domain", back_populates="applications")
    users = relationship("User", back_populates="application")
