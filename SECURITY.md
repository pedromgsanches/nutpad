# Melhorias de Segurança Implementadas

Este documento descreve as melhorias de segurança aplicadas à aplicação NutPad.

## 1. Proteção CSRF (Cross-Site Request Forgery)

- **Flask-WTF** implementado para proteção CSRF
- Tokens CSRF adicionados a todos os formulários (estáticos e dinâmicos)
- Função JavaScript `addCSRFToken()` para formulários criados dinamicamente

## 2. Headers de Segurança HTTP

Headers adicionados via `@app.after_request`:
- `X-Frame-Options: DENY` - Previne clickjacking
- `X-Content-Type-Options: nosniff` - Previne MIME type sniffing
- `X-XSS-Protection: 1; mode=block` - Proteção XSS (legado)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy` - Política de segurança de conteúdo

## 3. Validação e Sanitização de Inputs

Módulo `security.py` criado com:
- Validação de username (caracteres permitidos, comprimento)
- Validação de senha (comprimento mínimo, complexidade)
- Validação de títulos e conteúdo (comprimento máximo)
- Sanitização de inputs (remoção de caracteres de controle)
- Validação de prioridades e IDs de usuário

## 4. Rate Limiting

- **Flask-Limiter** implementado
- Limite de 5 tentativas de login por minuto
- Limite global: 200 requisições por dia, 50 por hora

## 5. Verificação de Usuário Ativo

- Verificação de `is_active` no login
- Usuários inativos não podem fazer login
- Mensagem de erro apropriada para usuários desativados

## 6. Segurança de Senhas

- Validação de complexidade (maiúsculas, minúsculas, números)
- Comprimento mínimo de 8 caracteres
- Comprimento máximo de 128 caracteres
- Hash seguro usando Werkzeug (PBKDF2)

## 7. SECRET_KEY Segura

- Geração automática de chave aleatória se não definida (apenas desenvolvimento)
- **IMPORTANTE**: Em produção, definir `SECRET_KEY` como variável de ambiente
- Erro se `SECRET_KEY` não estiver definida em produção

## 8. Autorização e Controle de Acesso

- Verificação de propriedade de recursos (notas/todos pertencem ao usuário)
- Validação de IDs antes de operações
- Prevenção de auto-exclusão/desativação de administradores
- Verificação de role para ações administrativas

## 9. Proteção contra SQL Injection

- Uso de prepared statements (parâmetros `?`) em todas as queries
- Nunca concatenar strings diretamente em queries SQL

## 10. Sanitização de HTML

- Módulo `bleach` para sanitização de HTML
- Tags e atributos permitidos definidos
- Escape de caracteres especiais

## Configuração de Produção

### Variáveis de Ambiente Necessárias

```bash
# Gerar uma chave secreta segura
python -c "import secrets; print(secrets.token_hex(32))"

# Definir no ambiente
export SECRET_KEY="sua-chave-secreta-aqui"
export FLASK_ENV="production"
```

### Dependências Adicionadas

- `Flask-WTF==1.0.1` - Proteção CSRF
- `WTForms==3.0.1` - Formulários seguros
- `Flask-Limiter==2.1.0` - Rate limiting
- `bleach==6.0.0` - Sanitização HTML

## Recomendações Adicionais

1. **HTTPS**: Sempre usar HTTPS em produção
2. **Backup**: Implementar backups regulares do banco de dados
3. **Logging**: Adicionar logging de eventos de segurança
4. **Monitoramento**: Monitorar tentativas de login falhadas
5. **Atualizações**: Manter dependências atualizadas

## Notas Importantes

- A senha padrão do admin (`admin`) deve ser alterada imediatamente após a primeira instalação
- Em produção, nunca usar a chave de desenvolvimento
- Revisar e ajustar os limites de rate limiting conforme necessário
- Testar todas as funcionalidades após implementação

