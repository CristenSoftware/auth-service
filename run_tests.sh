#!/bin/bash

# Script para executar testes do Auth Service

echo "=== Auth Service - Executando Testes Unitários ==="

# Verificar se o ambiente virtual está ativo
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✓ Ambiente virtual ativo: $VIRTUAL_ENV"
else
    echo "⚠ Ativando ambiente virtual..."
    source .venv/bin/activate
fi

# Executar diferentes tipos de teste
echo ""
echo "=== 1. Testes de Health Check ==="
python -m pytest tests/test_domains_applications.py::TestHealthCheck -v

echo ""
echo "=== 2. Testes de Autenticação ==="
python -m pytest tests/test_auth.py -v

echo ""
echo "=== 3. Testes de CRUD ==="
python -m pytest tests/test_crud.py -v

echo ""
echo "=== 4. Testes de Schemas ==="
python -m pytest tests/test_schemas.py -v

echo ""
echo "=== 5. Testes de Endpoints (API) ==="
python -m pytest tests/test_domains_applications.py -v

echo ""
echo "=== 6. Testes de Integração ==="
python -m pytest tests/test_integration.py -v

echo ""
echo "=== 7. Todos os Testes ==="
python -m pytest tests/ -v --tb=short

echo ""
echo "=== 8. Relatório de Cobertura ==="
python -m pytest tests/ --cov=. --cov-report=html --cov-report=term

echo ""
echo "=== Testes Concluídos ==="
