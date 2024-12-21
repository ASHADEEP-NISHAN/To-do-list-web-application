from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    priority = db.Column(db.String(50), nullable=True)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Routes
@app.route('/')
def merged():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)
    tasks = Task.query.filter_by(user_id=user_id).all()
    return render_template('index.html', tasks=tasks, current_user=user)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if User.query.filter_by(username=username).first():
            return "<script>alert('Username already exists.'); window.history.back();</script>"

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('merged'))
        return "<script>alert('Invalid credentials.'); window.history.back();</script>"

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/add', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task_name = request.form.get('task_name')
    due_date = request.form.get('due_date')
    category = request.form.get('category')
    priority = request.form.get('priority')

    if due_date:
        due_date = datetime.strptime(due_date, '%Y-%m-%d').date()
        if due_date < datetime.now().date():
            return "<script>alert('Due date cannot be in the past.'); window.history.back();</script>"

    new_task = Task(
        name=task_name,
        due_date=due_date,
        category=category,
        priority=priority,
        user_id=session['user_id']
    )
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('merged'))

@app.route('/toggle/<int:task_id>', methods=['POST'])
def toggle_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task = Task.query.get_or_404(task_id)
    if task.user_id != session['user_id']:
        return "<script>alert('Unauthorized action.'); window.history.back();</script>"

    task.completed = not task.completed
    db.session.commit()
    return redirect(url_for('merged'))

@app.route('/delete/<int:task_id>', methods=['GET'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task = Task.query.get_or_404(task_id)
    if task.user_id != session['user_id']:
        return "<script>alert('Unauthorized action.'); window.history.back();</script>"

    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('merged'))


@app.route('/sort/<string:sort_by>')
def sort_tasks(sort_by):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)
    if sort_by == 'due_date':
        tasks = Task.query.filter_by(user_id=user_id).order_by(Task.due_date.asc()).all()
    elif sort_by == 'priority':
        priority_map = {'High': 1, 'Medium': 2, 'Low': 3}
        tasks = sorted(Task.query.filter_by(user_id=user_id).all(), key=lambda x: priority_map[x.priority])
    elif sort_by == 'category':
        tasks = Task.query.filter_by(user_id=user_id).order_by(Task.category.asc()).all()
    else:
        tasks = Task.query.filter_by(user_id=user_id).all()

    return render_template('index.html', tasks=tasks, current_user=user)


@app.route('/search', methods=['GET'])
def search_tasks():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = request.args.get('query', '').strip().lower()
    if not query:
        return redirect(url_for('merged'))

    user_id = session['user_id']
    current_user = User.query.get(user_id)
    filtered_tasks = Task.query.filter(
        Task.user_id == user_id,
        (db.func.lower(Task.name).contains(query) | db.func.lower(Task.category).contains(query))
    ).all()
    return render_template('index.html', tasks=filtered_tasks, current_user=current_user)




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
