"""
Módulo de segurança com funções de validação e sanitização
"""
import re
import bleach
from html import escape

# Configuração de sanitização HTML
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
                'ul', 'ol', 'li', 'a', 'code', 'pre', 'blockquote', 'hr']
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'code': ['class'],
    'pre': ['class']
}

# Limites de validação
MAX_TITLE_LENGTH = 200
MAX_CONTENT_LENGTH = 10000
MAX_USERNAME_LENGTH = 50
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

def validate_username(username):
    """
    Valida o nome de usuário
    Retorna: (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    
    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username must be at most {MAX_USERNAME_LENGTH} characters"
    
    # Apenas letras, números, underscore e hífen
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscore and hyphen"
    
    return True, None

def validate_password(password, is_new=True):
    """
    Valida a senha
    Retorna: (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must be at most {MAX_PASSWORD_LENGTH} characters"
    
    if is_new:
        # Verificar complexidade para novas senhas
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one number"
    
    return True, None

def validate_title(title):
    """
    Valida o título de uma nota ou todo
    Retorna: (is_valid, error_message)
    """
    if not title:
        return False, "Title is required"
    
    if len(title) > MAX_TITLE_LENGTH:
        return False, f"Title must be at most {MAX_TITLE_LENGTH} characters"
    
    # Remover espaços em branco no início e fim
    title = title.strip()
    if not title:
        return False, "Title cannot be empty"
    
    return True, None

def validate_content(content):
    """
    Valida o conteúdo de uma nota
    Retorna: (is_valid, error_message)
    """
    if content is None:
        content = ""
    
    if len(content) > MAX_CONTENT_LENGTH:
        return False, f"Content must be at most {MAX_CONTENT_LENGTH} characters"
    
    return True, None

def sanitize_html(content):
    """
    Sanitiza HTML removendo tags e atributos perigosos
    """
    if not content:
        return ""
    
    # Primeiro, escapar HTML básico
    content = escape(content)
    
    # Permitir apenas tags seguras (para markdown renderizado)
    # Nota: Para markdown, normalmente não precisamos sanitizar tanto,
    # mas vamos fazer uma limpeza básica
    return bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True
    )

def sanitize_input(text, max_length=None):
    """
    Sanitiza input de texto removendo caracteres perigosos
    """
    if not text:
        return ""
    
    # Remover caracteres de controle
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    
    # Limitar comprimento
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    return text.strip()

def validate_priority(priority):
    """
    Valida a prioridade de um todo
    """
    try:
        priority = int(priority)
        if priority < 0 or priority > 2:
            return False, "Priority must be between 0 and 2"
        return True, None
    except (ValueError, TypeError):
        return False, "Priority must be a number"

def validate_user_id(user_id):
    """
    Valida se o user_id é válido e numérico
    """
    try:
        user_id = int(user_id)
        if user_id <= 0:
            return False, "Invalid user ID"
        return True, None
    except (ValueError, TypeError):
        return False, "User ID must be a number"

