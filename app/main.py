from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import re
import markdown
from app.database import init_db, get_db
from app.auth import User
from app.security import (
    validate_username, validate_password, validate_title, validate_content,
    sanitize_input, sanitize_html, validate_priority, validate_user_id
)
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timedelta
import secrets

app = Flask(__name__)

# Configuração de segurança
# SECRET_KEY deve ser definida como variável de ambiente em produção
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    # Gerar uma chave aleatória se não estiver definida (apenas para desenvolvimento)
    secret_key = secrets.token_hex(32)
    if os.environ.get('FLASK_ENV') == 'production':
        raise ValueError("SECRET_KEY environment variable must be set in production!")

app.secret_key = secret_key
app.permanent_session_lifetime = timedelta(days=7)  # Sessão dura 7 dias

# Configurar CSRF Protection
csrf = CSRFProtect(app)

# Configurar Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'  # Proteção adicional para a sessão

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Initialize database
with app.app_context():
    init_db()

@app.before_request
def make_session_permanent():
    session.permanent = True  # Torna a sessão permanente

@app.after_request
def set_security_headers(response: Response) -> Response:
    """
    Adiciona headers de segurança HTTP
    """
    # Prevenir clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevenir MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS Protection (legado, mas ainda útil)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Content Security Policy básico
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('notes'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limiting para login
def login():
    if current_user.is_authenticated:
        return redirect(url_for('notes'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validação básica
        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')
        
        # Sanitizar username
        username = sanitize_input(username, max_length=50)
        
        # Autenticar usuário
        user = User.authenticate(username, password)
        if user:
            # Verificar se o usuário está ativo
            if not user.is_active:
                flash('Account is disabled. Please contact an administrator.')
                return render_template('login.html')
            
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('notes'))
        else:
            # Não revelar se o usuário existe ou não (timing attack protection)
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/notes')
@login_required
def notes():
    search_query = request.args.get('search', '')
    
    # Sanitizar query de busca
    if search_query:
        search_query = sanitize_input(search_query, max_length=100)
    
    conn = get_db()
    if search_query:
        cursor = conn.execute('''
            SELECT id, title, content 
            FROM notes 
            WHERE user_id = ? 
            AND (title LIKE ? OR content LIKE ?)
            ORDER BY id DESC
        ''', (current_user.id, f'%{search_query}%', f'%{search_query}%'))
    else:
        cursor = conn.execute('''
            SELECT id, title, content 
            FROM notes 
            WHERE user_id = ? 
            ORDER BY id DESC
        ''', (current_user.id,))
    
    notes = cursor.fetchall()
    conn.close()
    
    return render_template('notes.html', notes=notes, search_query=search_query)

@app.route('/notes/<int:id>')
@login_required
def get_note(id):
    # Validar ID
    is_valid, error = validate_user_id(id)
    if not is_valid:
        return {'error': 'Invalid note ID'}, 400
    
    conn = get_db()
    note = conn.execute('''
        SELECT id, title, content 
        FROM notes 
        WHERE id = ? AND user_id = ?
    ''', (id, current_user.id)).fetchone()
    conn.close()
    
    if note is None:
        return {'error': 'Note not found'}, 404
        
    return {
        'id': note[0],
        'title': note[1],
        'content': note[2].replace('\n', '\r\n')  # Converte para o formato do navegador
    }

@app.route('/notes/new', methods=['POST'])
@login_required
def new_note():
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').replace('\r\n', '\n')
    
    # Validação
    is_valid, error = validate_title(title)
    if not is_valid:
        flash(error)
        return redirect(url_for('notes'))
    
    is_valid, error = validate_content(content)
    if not is_valid:
        flash(error)
        return redirect(url_for('notes'))
    
    # Sanitizar inputs
    title = sanitize_input(title, max_length=200)
    content = sanitize_input(content, max_length=10000)
    
    conn = get_db()
    conn.execute('''
        INSERT INTO notes (title, content, user_id)
        VALUES (?, ?, ?)
    ''', (title, content, current_user.id))
    conn.commit()
    conn.close()
    
    flash('Note created successfully')
    return redirect(url_for('notes'))

@app.route('/notes/<int:id>/update', methods=['POST'])
@login_required
def update_note(id):
    # Validar ID
    is_valid, error = validate_user_id(id)
    if not is_valid:
        flash('Invalid note ID')
        return redirect(url_for('notes'))
    
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').replace('\r\n', '\n')
    
    # Validação
    is_valid, error = validate_title(title)
    if not is_valid:
        flash(error)
        return redirect(url_for('notes'))
    
    is_valid, error = validate_content(content)
    if not is_valid:
        flash(error)
        return redirect(url_for('notes'))
    
    # Sanitizar inputs
    title = sanitize_input(title, max_length=200)
    content = sanitize_input(content, max_length=10000)
    
    conn = get_db()
    # Verificar se a nota pertence ao usuário
    note = conn.execute('''
        SELECT id FROM notes WHERE id = ? AND user_id = ?
    ''', (id, current_user.id)).fetchone()
    
    if not note:
        flash('Note not found')
        conn.close()
        return redirect(url_for('notes'))
    
    conn.execute('''
        UPDATE notes 
        SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
    ''', (title, content, id, current_user.id))
    conn.commit()
    conn.close()
    
    flash('Note updated successfully')
    return redirect(url_for('notes'))

@app.route('/notes/<int:id>/delete', methods=['POST'])
@login_required
def delete_note(id):
    # Validar ID
    is_valid, error = validate_user_id(id)
    if not is_valid:
        flash('Invalid note ID')
        return redirect(url_for('notes'))
    
    conn = get_db()
    # Verificar se a nota pertence ao usuário antes de deletar
    note = conn.execute('''
        SELECT id FROM notes WHERE id = ? AND user_id = ?
    ''', (id, current_user.id)).fetchone()
    
    if not note:
        flash('Note not found')
        conn.close()
        return redirect(url_for('notes'))
    
    conn.execute('DELETE FROM notes WHERE id = ? AND user_id = ?', (id, current_user.id))
    conn.commit()
    conn.close()
    
    flash('Note deleted successfully')
    return redirect(url_for('notes'))

# Todo Routes
@app.route('/todos')
@login_required
def todos():
    search_query = request.args.get('search', '')
    
    # Sanitizar query de busca
    if search_query:
        search_query = sanitize_input(search_query, max_length=100)
    
    db = get_db()
    cursor = db.cursor()
    
    if search_query:
        cursor.execute('''
            SELECT id, title, completed, priority, due_date FROM todos 
            WHERE user_id = ? AND title LIKE ?
        ''', (current_user.id, f'%{search_query}%'))
    else:
        cursor.execute('''
            SELECT id, title, completed, priority, due_date FROM todos 
            WHERE user_id = ? 
            ORDER BY completed, priority DESC, due_date
        ''', (current_user.id,))
    
    todos = cursor.fetchall()
    return render_template('todo.html', todos=todos, search_query=search_query)

@app.route('/todos/new', methods=['POST'])
@login_required
def new_todo():
    title = request.form.get('title', '').strip()
    priority = request.form.get('priority', 0)
    due_date = request.form.get('due_date', '')
    completed = request.form.get('completed', 0)
    
    # Validação
    is_valid, error = validate_title(title)
    if not is_valid:
        flash(error)
        return redirect(url_for('todos'))
    
    is_valid, error = validate_priority(priority)
    if not is_valid:
        flash(error)
        return redirect(url_for('todos'))
    
    # Sanitizar
    title = sanitize_input(title, max_length=200)
    
    # Validar completed (deve ser 0 ou 1)
    try:
        completed = int(completed)
        if completed not in [0, 1]:
            completed = 0
    except (ValueError, TypeError):
        completed = 0
    
    # Validar due_date (formato YYYY-MM-DD)
    if due_date:
        due_date = sanitize_input(due_date, max_length=10)
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', due_date):
            due_date = None
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO todos (user_id, title, priority, due_date, completed) 
        VALUES (?, ?, ?, ?, ?)
    ''', (current_user.id, title, priority, due_date if due_date else None, completed))
    db.commit()
    
    flash('Todo created successfully')
    return redirect(url_for('todos'))

@app.route('/todos/<int:todo_id>', methods=['GET'])
@login_required
def get_todo(todo_id):
    # Validar ID
    is_valid, error = validate_user_id(todo_id)
    if not is_valid:
        return {'error': 'Invalid todo ID'}, 400
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT id, title, priority, due_date, completed 
        FROM todos 
        WHERE id = ? AND user_id = ?
    ''', (todo_id, current_user.id))
    todo = cursor.fetchone()
    
    if todo:
        return {
            'id': todo[0],
            'title': todo[1],
            'priority': todo[2],
            'due_date': todo[3],
            'completed': todo[4]
        }
    return {'error': 'Not found'}, 404

@app.route('/todos/<int:todo_id>/update', methods=['POST'])
@login_required
def update_todo(todo_id):
    # Validar ID
    is_valid, error = validate_user_id(todo_id)
    if not is_valid:
        flash('Invalid todo ID')
        return redirect(url_for('todos'))
    
    title = request.form.get('title', '').strip()
    priority = request.form.get('priority', 0)
    due_date = request.form.get('due_date', '')
    completed = request.form.get('completed', 0)
    
    # Validação
    is_valid, error = validate_title(title)
    if not is_valid:
        flash(error)
        return redirect(url_for('todos'))
    
    is_valid, error = validate_priority(priority)
    if not is_valid:
        flash(error)
        return redirect(url_for('todos'))
    
    # Sanitizar
    title = sanitize_input(title, max_length=200)
    
    # Validar completed
    try:
        completed = int(completed)
        if completed not in [0, 1]:
            completed = 0
    except (ValueError, TypeError):
        completed = 0
    
    # Validar due_date
    if due_date:
        due_date = sanitize_input(due_date, max_length=10)
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', due_date):
            due_date = None
    
    db = get_db()
    cursor = db.cursor()
    
    # Verificar se o todo pertence ao usuário
    todo = cursor.execute('''
        SELECT id FROM todos WHERE id = ? AND user_id = ?
    ''', (todo_id, current_user.id)).fetchone()
    
    if not todo:
        flash('Todo not found')
        db.close()
        return redirect(url_for('todos'))
    
    cursor.execute('''
        UPDATE todos 
        SET title = ?, priority = ?, due_date = ?, completed = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
    ''', (title, priority, due_date if due_date else None, completed, todo_id, current_user.id))
    db.commit()
    db.close()
    
    flash('Todo updated successfully')
    return redirect(url_for('todos'))

@app.route('/todos/<int:todo_id>/delete', methods=['POST'])
@login_required
def delete_todo(todo_id):
    # Validar ID
    is_valid, error = validate_user_id(todo_id)
    if not is_valid:
        flash('Invalid todo ID')
        return redirect(url_for('todos'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Verificar se o todo pertence ao usuário
    todo = cursor.execute('''
        SELECT id FROM todos WHERE id = ? AND user_id = ?
    ''', (todo_id, current_user.id)).fetchone()
    
    if not todo:
        flash('Todo not found')
        db.close()
        return redirect(url_for('todos'))
    
    cursor.execute('DELETE FROM todos WHERE id = ? AND user_id = ?', (todo_id, current_user.id))
    db.commit()
    db.close()
    
    flash('Todo deleted successfully')
    return redirect(url_for('todos'))

@app.route('/todos/<int:todo_id>/toggle_completed', methods=['POST'])
@login_required
def toggle_todo_completed(todo_id):
    # Validar ID
    is_valid, error = validate_user_id(todo_id)
    if not is_valid:
        flash('Invalid todo ID')
        return redirect(url_for('todos'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Verificar se o todo pertence ao usuário
    todo = cursor.execute('''
        SELECT id FROM todos WHERE id = ? AND user_id = ?
    ''', (todo_id, current_user.id)).fetchone()
    
    if not todo:
        flash('Todo not found')
        db.close()
        return redirect(url_for('todos'))
    
    cursor.execute('UPDATE todos SET completed = NOT completed, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
                  (todo_id, current_user.id))
    db.commit()
    db.close()
    
    return redirect(url_for('todos'))

@app.route('/help')
@login_required
def help():
    return render_template('help.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        
        # Validação de senha
        is_valid, error = validate_password(new_password, is_new=True)
        if not is_valid:
            flash(error)
        elif User.change_password(current_user.id, current_password, new_password):
            flash('Password changed successfully')
        else:
            flash('Current password is incorrect')
    
    # Se for admin, buscar lista de usuários
    users = None
    if current_user.role == 'admin':
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, username, role, is_active FROM users WHERE username != ?', (current_user.username,))
        users = cursor.fetchall()
        db.close()
    
    return render_template('settings.html', users=users)

@app.route('/about')
def about():
    return render_template('about.html')

def is_admin():
    return current_user.is_authenticated and current_user.role == 'admin'

@app.route('/users/new', methods=['POST'])
@login_required
def new_user():
    if not is_admin():
        flash('Access denied')
        return redirect(url_for('notes'))
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')
    
    # Validação
    is_valid, error = validate_username(username)
    if not is_valid:
        flash(error)
        return redirect(url_for('settings'))
    
    is_valid, error = validate_password(password, is_new=True)
    if not is_valid:
        flash(error)
        return redirect(url_for('settings'))
    
    # Validar role
    if role not in ['user', 'admin']:
        flash('Invalid role')
        return redirect(url_for('settings'))
    
    # Sanitizar username
    username = sanitize_input(username, max_length=50)
    
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                      (username, User.hash_password(password), role))
        db.commit()
        flash('User created successfully')
    except sqlite3.IntegrityError:
        flash('Username already exists')
    except Exception as e:
        flash('Error creating user')
    finally:
        db.close()
    
    return redirect(url_for('settings'))

@app.route('/users/<int:user_id>/toggle_active', methods=['POST'])
@login_required
def toggle_user_active(user_id):
    if not is_admin():
        flash('Access denied')
        return redirect(url_for('notes'))
    
    # Validar ID
    is_valid, error = validate_user_id(user_id)
    if not is_valid:
        flash('Invalid user ID')
        return redirect(url_for('settings'))
    
    # Não permitir desativar a si mesmo
    if user_id == current_user.id:
        flash('Cannot deactivate your own account')
        return redirect(url_for('settings'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Verificar se o usuário existe
    user = cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found')
        db.close()
        return redirect(url_for('settings'))
    
    cursor.execute('UPDATE users SET is_active = NOT is_active WHERE id = ? AND username != ?',
                  (user_id, current_user.username))
    db.commit()
    db.close()
    
    flash('User status updated successfully')
    return redirect(url_for('settings'))

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not is_admin():
        flash('Access denied')
        return redirect(url_for('notes'))
    
    # Validar ID
    is_valid, error = validate_user_id(user_id)
    if not is_valid:
        flash('Invalid user ID')
        return redirect(url_for('settings'))
    
    # Não permitir deletar a si mesmo
    if user_id == current_user.id:
        flash('Cannot delete your own account')
        return redirect(url_for('settings'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Verificar se o usuário existe
    user = cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found')
        db.close()
        return redirect(url_for('settings'))
    
    cursor.execute('DELETE FROM users WHERE id = ? AND username != ?', (user_id, current_user.username))
    db.commit()
    db.close()
    
    flash('User deleted successfully')
    return redirect(url_for('settings'))

@app.route('/users/<int:user_id>/change_password', methods=['POST'])
@login_required
def change_user_password(user_id):
    if not is_admin():
        flash('Access denied')
        return redirect(url_for('notes'))
    
    # Validar ID
    is_valid, error = validate_user_id(user_id)
    if not is_valid:
        flash('Invalid user ID')
        return redirect(url_for('settings'))
    
    new_password = request.form.get('new_password', '')
    
    # Validação de senha
    is_valid, error = validate_password(new_password, is_new=True)
    if not is_valid:
        flash(error)
        return redirect(url_for('settings'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Verificar se o usuário existe
    user = cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found')
        db.close()
        return redirect(url_for('settings'))
    
    cursor.execute('UPDATE users SET password = ? WHERE id = ? AND username != ?',
                  (User.hash_password(new_password), user_id, current_user.username))
    db.commit()
    db.close()
    
    flash('Password changed successfully')
    return redirect(url_for('settings'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)