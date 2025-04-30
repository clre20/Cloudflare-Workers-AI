# Cloudflare-Workers-AI

專案結構 (示例)

├── app.py

├── config.py

├── models.py

├── scheduler.py

├── monitors.py

├── requirements.txt

└── templates/

├── base.html

├── login.html

├── monitors.html

├── monitor_form.html

└── chart.html

---

### config.py
```python
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///monitor.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # APScheduler
    SCHEDULER_API_ENABLED = True
    JOBS_DB_URL = SQLALCHEMY_DATABASE_URI

```

---
models.py
```python
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Monitor(db.Model):
    __tablename__ = 'monitors'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(10), nullable=False)
    target = db.Column(db.String(200), nullable=False)
    port = db.Column(db.Integer)
    keyword = db.Column(db.String(200))
    frequency = db.Column(db.Integer, nullable=False)
    last_status = db.Column(db.Boolean, default=True)
    enabled = db.Column(db.Boolean, default=True)
    user = db.relationship('User', backref='monitors')

class MonitorResult(db.Model):
    __tablename__ = 'monitor_results'
    id = db.Column(db.Integer, primary_key=True)
    monitor_id = db.Column(db.Integer, db.ForeignKey('monitors.id'))
    timestamp = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    response_time = db.Column(db.Float)
    details = db.Column(db.Text)
    monitor = db.relationship('Monitor', backref='results')

```
---

monitors.py (檢查函式)
```python
import socket, subprocess, time
import requests
from icmplib import ping
from datetime import datetime
from models import db, Monitor, MonitorResult
from notifications import notify_all


def check_ping(monitor: Monitor):
    result = ping(monitor.target, count=1, timeout=2)
    status = 'up' if result.is_alive else 'down'
    return status, result.avg_rtt


def check_http(monitor: Monitor):
    start = time.time()
    try:
        resp = requests.get(monitor.target, timeout=5)
        elapsed = (time.time() - start) * 1000
        if resp.status_code == 200 and (not monitor.keyword or monitor.keyword in resp.text):
            return 'up', elapsed
        else:
            return 'down', elapsed
    except Exception as e:
        return 'down', None


def check_dns(monitor: Monitor):
    try:
        ip = socket.gethostbyname(monitor.target)
        return 'up', None
    except Exception:
        return 'down', None


def check_tcp(monitor: Monitor):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        res = sock.connect_ex((monitor.target, monitor.port))
        status = 'up' if res == 0 else 'down'
    finally:
        sock.close()
    return status, None


def run_monitor(monitor_id):
    monitor = Monitor.query.get(monitor_id)
    if not monitor or not monitor.enabled:
        return
    checks = {'ping': check_ping, 'http': check_http, 'dns': check_dns, 'tcp': check_tcp}
    func = checks.get(monitor.type)
    status, rtime = func(monitor)
    now = datetime.utcnow()
    # 儲存結果
    result = MonitorResult(monitor_id=monitor.id, timestamp=now,
                           status=status, response_time=rtime)
    db.session.add(result)
    # 首次異常通知
    if status == 'down' and monitor.last_status:
        notify_all(monitor, result)
    monitor.last_status = (status == 'up')
    db.session.commit()

```
---

scheduler.py
```python
from apscheduler.schedulers.background import BackgroundScheduler
from flask import current_app
from models import Monitor, db
from monitors import run_monitor

scheduler = BackgroundScheduler()


def init_scheduler(app):
    scheduler.configure(jobstores={'default':
                                   {'type': 'sqlalchemy', 'url': app.config['SQLALCHEMY_DATABASE_URI']}})
    scheduler.start()
    # 載入所有啟用任務
    with app.app_context():
        for m in Monitor.query.filter_by(enabled=True).all():
            scheduler.add_job(func=run_monitor,
                              trigger='interval', seconds=m.frequency,
                              args=[m.id], id=str(m.id))

```
---

notifications.py
```python
import smtplib
import requests
from email.mime.text import MIMEText
from config import Config

SMTP_SERVER = 'smtp.example.com'
SMTP_PORT = 587
SMTP_USER = 'your-email@example.com'
SMTP_PASS = 'password'
DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/...'  

def notify_all(monitor, result):
    subject = f"[Alert] {monitor.name} is down"
    body = f"Time: {result.timestamp}\nTarget: {monitor.target}\nType: {monitor.type}\n"
    send_email(monitor.user.email, subject, body)
    send_discord(subject + '\n' + body)


def send_email(to_addr, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = to_addr

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SMTP_USER, SMTP_PASS)
    server.sendmail(SMTP_USER, [to_addr], msg.as_string())
    server.quit()


def send_discord(content):
    data = {"content": content}
    requests.post(DISCORD_WEBHOOK_URL, json=data)
```

---

app.py
```python
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from config import Config
from models import db, User, Monitor, MonitorResult
from scheduler import init_scheduler, scheduler
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)

# LoginManager 設定
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 初始化排程
with app.app_context():
    init_scheduler(app)

# 路由: 登入 / 登出
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            login_user(user)
            return redirect(url_for('monitors'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 路由: 監控列表
@app.route('/')
@login_required
def monitors():
    items = Monitor.query.filter_by(user_id=current_user.id).all()
    return render_template('monitors.html', monitors=items)

# 新增 / 編輯
@app.route('/monitor/<int:id>', methods=['GET', 'POST'])
@app.route('/monitor/new', methods=['GET', 'POST'])
def monitor_form(id=None):
    monitor = Monitor.query.get(id) if id else None
    if request.method == 'POST':
        data = request.form
        if monitor:
            # 更新
            monitor.name = data['name']
            monitor.type = data['type']
            monitor.target = data['target']
            monitor.port = data.get('port')
            monitor.keyword = data.get('keyword')
            monitor.frequency = int(data['frequency'])
        else:
            # 新增
            monitor = Monitor(user_id=current_user.id,
                              name=data['name'], type=data['type'],
                              target=data['target'], port=data.get('port'),
                              keyword=data.get('keyword'),
                              frequency=int(data['frequency']), enabled=True)
            db.session.add(monitor)
            db.session.flush()  # 取得 ID
            scheduler.add_job(run_monitor, 'interval', seconds=monitor.frequency, args=[monitor.id], id=str(monitor.id))
        db.session.commit()
        return redirect(url_for('monitors'))
    return render_template('monitor_form.html', monitor=monitor)

# 刪除
@app.route('/monitor/delete/<int:id>', methods=['POST'])
@login_required
def monitor_delete(id):
    monitor = Monitor.query.get_or_404(id)
    scheduler.remove_job(str(monitor.id))
    db.session.delete(monitor)
    db.session.commit()
    return redirect(url_for('monitors'))

# 圖表
@app.route('/monitor/chart/<int:id>')
@login_required
def monitor_chart(id):
    monitor = Monitor.query.get_or_404(id)
    results = MonitorResult.query.filter_by(monitor_id=id).order_by(MonitorResult.timestamp.asc()).all()
    times = [r.timestamp.strftime('%Y-%m-%d %H:%M:%S') for r in results]
    statuses = [1 if r.status=='up' else 0 for r in results]
    return render_template('chart.html', monitor=monitor, labels=times, data=statuses)

if __name__ == '__main__':
    app.run(debug=True)
```

---

templates/base.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{% block title %}監控系統{% endblock %}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="{{ url_for('monitors') }}">監控系統</a>
  {% if current_user.is_authenticated %}
    <a class="nav-link" href="{{ url_for('logout') }}">登出</a>
  {% endif %}
</nav>
<div class="container mt-4">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      {% for msg in messages %}<div class="alert alert-warning">{{ msg }}</div>{% endfor %}
    {% endif %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>
</body>
</html>


---

templates/login.html

{% extends 'base.html' %}
{% block content %}
<h2>登入</h2>
<form method="post">
  <div class="form-group">
    <label>帳號</label>
    <input class="form-control" name="username" required>
  </div>
  <div class="form-group">
    <label>密碼</label>
    <input type="password" class="form-control" name="password" required>
  </div>
  <button class="btn btn-primary">登入</button>
</form>
{% endblock %}

```
---

templates/monitors.html
```html
{% extends 'base.html' %}
{% block content %}
<h2>監控列表</h2>
<a class="btn btn-success mb-2" href="{{ url_for('monitor_form') }}">新增監控</a>
<table class="table table-striped">
  <thead><tr><th>名稱</th><th>類型</th><th>目標</th><th>頻率(s)</th><th>狀態</th><th>操作</th></tr></thead>
  <tbody>
    {% for m in monitors %}
    <tr>
      <td>{{ m.name }}</td>
      <td>{{ m.type }}</td>
      <td>{{ m.target }}{% if m.port %}:{{ m.port }}{% endif %}</td>
      <td>{{ m.frequency }}</td>
      <td>{{ 'Up' if m.last_status else 'Down' }}</td>
      <td>
        <a class="btn btn-sm btn-primary" href="{{ url_for('monitor_form', id=m.id) }}">編輯</a>
        <form style="display:inline;" method="post" action="{{ url_for('monitor_delete', id=m.id) }}">
          <button class="btn btn-sm btn-danger">刪除</button>
        </form>
        <a class="btn btn-sm btn-info" href="{{ url_for('monitor_chart', id=m.id) }}">圖表</a>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}

```
---

templates/monitor_form.html
```html
{% extends 'base.html' %}
{% block content %}
<h2>{{ '編輯' if monitor else '新增' }} 監控</h2>
<form method="post">
  <div class="form-group">
    <label>名稱</label>
    <input class="form-control" name="name" value="{{ monitor.name if monitor }}" required>
  </div>
  <div class="form-group">
    <label>類型</label>
    <select class="form-control" name="type">
      <option value="ping" {% if monitor and monitor.type=='ping' %}selected{% endif %}>Ping</option>
      <option value="http" {% if monitor and monitor.type=='http' %}selected{% endif %}>HTTP</option>
      <option value="dns" {% if monitor and monitor.type=='dns' %}selected{% endif %}>DNS</option>
      <option value="tcp" {% if monitor and monitor.type=='tcp' %}selected{% endif %}>TCP</option>
    </select>
  </div>
  <div class="form-group">
    <label>目標 (URL / IP / Domain)</label>
    <input class="form-control" name="target" value="{{ monitor.target if monitor }}" required>
  </div>
  <div class="form-group">
    <label>Port (TCP only)</label>
    <input class="form-control" name="port" value="{{ monitor.port if monitor }}">
  </div>
  <div class="form-group">
    <label>關鍵字 (HTTP only)</label>
    <input class="form-control" name="keyword" value="{{ monitor.keyword if monitor }}">
  </div>
  <div class="form-group">
    <label>頻率 (秒, 最少 20)</label>
    <input type="number" class="form-control" name="frequency" min="20" value="{{ monitor.frequency if monitor else 60 }}" required>
  </div>
  <button class="btn btn-primary">送出</button>
</form>
{% endblock %}
```

---

templates/chart.html
```html
{% extends 'base.html' %}
{% block content %}
<h2>{{ monitor.name }} - 歷史狀態</h2>
<canvas id="statusChart"></canvas>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
  const ctx = document.getElementById('statusChart').getContext('2d');
  const labels = {{ labels|tojson }};
  const data = {{ data|tojson }};
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'Up/Down',
        data: data,
        fill: false,
        borderWidth: 1
      }]
    },
    options: {
      scales: { y: { ticks: { stepSize: 1 } } }
    }
  });
</script>
{% endblock %}
```

---

requirements.txt
```txt
Flask
Flask-Login
Flask-Migrate
Flask-SQLAlchemy
APScheduler
requests
icmplib

```