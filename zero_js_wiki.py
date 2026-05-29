#!/usr/bin/env python3
# Zero-JS Wiki v0.11 (Flask + SQLite) — secure, minimal, no business JavaScript
#
# Run:
#    Windows PowerShell: $env:SECRET_KEY="your-key"; python zero_js_wiki.py
#    Linux/macOS:        export SECRET_KEY="your-key"; python zero_js_wiki.py
#SPDX-License-Identifier: CC0-1.0
#SPDX-FileCopyrightText: 2026 Feynman_Wong


import os
import glob
import re
import sys
import time
import html as html_mod
import sqlite3
import base64   
import random
import io                                    # 在内存中操作图片
import secrets
import urllib.parse
import threading
from datetime import datetime, timezone, timedelta
from PIL import Image, ImageDraw, ImageFilter  # 验证码

try:
    from flask import (
        Flask, request, redirect, url_for, session,
        render_template_string, g, flash, abort, make_response,
    )
    from werkzeug.security import generate_password_hash, check_password_hash
    import mistune
except ImportError:
    print(" Missing dependencies. Install with: pip install flask mistune pillow")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Config — environment variables
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    print(" SECRET_KEY environment variable must be set.")
    sys.exit(1)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",  #SAMESITE="Lax"也是可以的，主要考虑减少潜在的跨站请求携带 Cookie 的风险
    # Uncomment if HTTPS:
    # SESSION_COOKIE_SECURE=True,  #HTTP模式下不能设置 Secure cookie，否则 Cookie 不会被发送
)

DATABASE = os.environ.get("WIKI_DB", "wiki.db")

# 用环境变量控制是否允许公开注册
ALLOW_REGISTRATION = os.environ.get("ALLOW_REGISTRATION", "false").lower() == "true"

# 避免数据库空白的瞬间抢注管理员，故生成一个随机 key 并打印到终端
SETUP_KEY = os.environ.get("SETUP_KEY")
if SETUP_KEY is None:
    SETUP_KEY = secrets.token_hex(16)
    print(f"SETUP_KEY not set. Using temporary key: {SETUP_KEY}")

# ---------------------------------------------------------------------------
# Config — tunable constants
# ---------------------------------------------------------------------------

#登录连续失败锁定
LOCKOUT_THRESHOLD = 3            # 登录连续失败锁定触发次数
LOCKOUT_DURATION = 1             # 登录连续失败锁定分钟数
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# 全局速率限制阈值（基于 SQLite 实现）
GLOBAL_LOGIN_MAX = 100           # 每分钟允许的最大登录/注册 POST 请求
GLOBAL_LOGIN_WINDOW = 60         # 窗口秒数

# 会话
SESSION_IDLE_TIMEOUT = 7200      # 空闲超时秒数（120分钟）

# 内容限制
MAX_CONTENT_SIZE = 200 * 1024    # 页面内容最大字节数（200 KB）

# 验证码
CAPTCHA_EXPIRE_SECONDS = 120     # 验证码过期秒数
CAPTCHA_ONE_TIME_EXPIRE = 120    # 一次性令牌过期秒数
CAPTCHA_RATE_WINDOW = 60         # 验证码频率窗口秒数（per session）
CAPTCHA_RATE_MAX = 10            # 每分钟每 session 最大验证码生成次数
GLOBAL_CAPTCHA_MAX = 1000         # 每分钟全局最大验证码生成次数（极端滥用时的熔断机制）
GLOBAL_CAPTCHA_WINDOW = 60       # 全局窗口秒数
CAPTCHA_IMG_SIZE = (150, 150)    # 验证码图片尺寸
CAPTCHA_CATEGORY_NAMES = {'A': '车', 'B': '狗', 'C': '猫'}  # 分类显示名

# 外部链接令牌
REDIRECT_TOKEN_EXPIRE = 120      # 过期秒数

# 历史记录
HISTORY_MAX = 100                # 每页最大历史记录数

# 审计日志
LOG_PAGE_SIZE = 200              # 每页日志条数

def _check_and_record_rate(table_name, max_allowed, window_sec):
    # 事务性速率检查+记录。超限返回 True，否则记录并返回 False。
    db = get_db()
    now = time.time()
    cutoff = now - window_sec
    db.execute("BEGIN IMMEDIATE")
    db.execute(f"DELETE FROM {table_name} WHERE timestamp < ?", (cutoff,))
    count = db.execute(
        f"SELECT COUNT(*) FROM {table_name} WHERE timestamp >= ?", (cutoff,)
    ).fetchone()[0]
    if count >= max_allowed:
        db.execute("ROLLBACK")
        return True
    db.execute(f"INSERT INTO {table_name} (timestamp) VALUES (?)", (now,))
    db.execute("COMMIT")
    return False

# ---- public wrappers ----

def check_global_login_rate():
    # 登录速率检查+记录。返回 True 表示超限。
    return _check_and_record_rate("login_rate", GLOBAL_LOGIN_MAX, GLOBAL_LOGIN_WINDOW)

def check_global_register_rate():
    # 注册速率检查+记录。返回 True 表示超限。
    return _check_and_record_rate("register_rate", GLOBAL_LOGIN_MAX, GLOBAL_LOGIN_WINDOW)

def check_global_captcha_rate():
    # 全局验证码生成速率检查+记录。返回 True 表示超限（防 DoS）。
    return _check_and_record_rate("captcha_rate", GLOBAL_CAPTCHA_MAX, GLOBAL_CAPTCHA_WINDOW)

# =========================================================================
# HTML escape helper
# =========================================================================
def escape_html(text):
    return html_mod.escape(str(text), quote=True)

def is_safe_redirect(target):
    # 只允许以 / 开头的相对路径，拒绝 // 或外部 URL
    return target.startswith('/') and not target.startswith('//')

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, check_same_thread=False, timeout=10)
        # 设置超时并允许跨线程使用（同一线程内 g.db 可复用，避免并发锁问题）
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode=WAL")   # 启用 WAL 模式，提升读写并发；多 worker 部署时需注意只有一个进程写入，否则可能损坏数据
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()
        
def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'reader',
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                session_token TEXT
            );
            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT UNIQUE NOT NULL,
                content_md TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS page_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_id INTEGER REFERENCES pages(id) ON DELETE CASCADE,
                content_md TEXT NOT NULL,
                edited_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                edited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS login_rate (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_login_rate_timestamp ON login_rate(timestamp);
            CREATE TABLE IF NOT EXISTS register_rate (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_register_rate_timestamp ON register_rate(timestamp);
            CREATE TABLE IF NOT EXISTS captcha_rate (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_captcha_rate_timestamp ON captcha_rate(timestamp);
               CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                detail TEXT
            );
        """)
        db.commit()         
    print(" Database initialized.")

# captcha_初始化图片文件夹
def init_captcha_folders():
    # 确保 captcha_images/A, B, C 目录存在
    base = "captcha_images"
    for cat in ['A', 'B', 'C']:
        path = os.path.join(base, cat)
        os.makedirs(path, exist_ok=True)
    print("Image captcha folders ready. Place your own images in captcha_images/A, B, C.")

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
SLUG_RE = re.compile(r"[a-zA-Z0-9_\-]+")

def validate_slug(slug):
    # 标准化并验证 slug。返回 (normalized_slug, is_valid)。
    if slug.lower() == "home":
        return "home", True
    if SLUG_RE.fullmatch(slug):
        return slug, True
    return slug, False

def db_has_users():
    return get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0

def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute(
        "SELECT id, username, role, password_hash, session_token FROM users WHERE id = ?", (uid,)
    ).fetchone()

def require_login(role=None):
    if "user_id" not in session:
        if not db_has_users():
            return redirect(url_for("setup"))
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    user = get_current_user()
    if not user:
        session.clear()
        flash("Account no longer exists.", "error")
        return redirect(url_for("login"))
    if role and user["role"] != role:
        abort(403)
    return None

def check_write_permission():
    check = require_login()
    if check:
        return check
    if get_current_user()["role"] not in ("admin", "writer"):
        abort(403)
    return None

# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

# 添加安全 HTTP 头
@app.after_request
def add_security_headers(response):
    response.headers['Referrer-Policy'] = 'no-referrer'         # 不泄露 Referer
    response.headers['X-Content-Type-Options'] = 'nosniff'      # 防止 MIME 类型嗅探
    response.headers['X-Frame-Options'] = 'DENY'                # 禁止页面被嵌入 iframe
    # 内容安全策略：减少注入面，明确禁止脚本执行_可运行hash.py以确认style-src、script-src是否正确
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; "  #默认拒绝所有资源
        "connect-src 'self'; "  #允许向本站发起网络请求-预留扩展性，目前不使用
        "img-src 'self' data: http: https:; "  #暂定，允许外部图片
        "media-src 'self' data:; "  #兼容性
        "style-src 'sha256-YP3ofrOZapiLEdike0PDe0XLhNAYmpJLtlEmdtg4aCE='; "  #禁止非指定的内联样式（通过hash判断）
        "script-src 'sha256-+kINJrk1I+GPzMwE7dq7z+zST3o2ihrHTzCFIX+3il8='; "  #禁止非指定的脚本（通过hash判断）
        "script-src-elem 'sha256-+kINJrk1I+GPzMwE7dq7z+zST3o2ihrHTzCFIX+3il8='; "  #兼容性；禁止非指定的脚本（通过hash判断）
        "base-uri 'self'; "  #限制 <base> 标签只能指向本站，防止攻击者用 <base> 劫持页面内链接
        "form-action 'self'; "  #只允许表单提交到本站，防止攻击者把你的表单提交到外部恶意网址
        "frame-ancestors 'none'; "  #禁止页面被嵌入 <iframe>，防止点击劫持
    )
    return response

@app.route('/favicon.ico')
def favicon():
    # 魔法图片：返回一个 1x1 透明 PNG，以后再改
    pixel = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==')
    return make_response(pixel, 200, {'Content-Type': 'image/png'})


@app.before_request
def csrf_protect():
    # 会话空闲超时：120分钟无活动则踢出
    if "user_id" in session:
        now = time.time()
        last = session.get('_last_activity', now)
        if now - last > SESSION_IDLE_TIMEOUT:
            session.clear()
            flash("Session expired due to inactivity.", "warning")
            return redirect(url_for("login"))
        session['_last_activity'] = now
    #  CSRF 与 session_token 校验
    if request.method == "POST":
        if request.path == "/setup" and not db_has_users():
            return
        token = session.get("_csrf_token")
        if not token or token != request.form.get("_csrf_token", ""):
            abort(403)

    # 会话固定防护：检查已登录用户的 session_token 是否与数据库匹配
    user_id = session.get("user_id")
    if user_id:
        db = get_db()
        user = db.execute("SELECT session_token FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["session_token"] != session.get("session_token"):
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = os.urandom(32).hex()
    return session["_csrf_token"]

app.jinja_env.globals["csrf_token"] = generate_csrf_token

# =========================================================================
# 保护外部链接
# =========================================================================

# 临时存储外部链接令牌（用于隐藏真实URL）
_redirect_tokens = {}
_token_lock = threading.Lock()
_MAX_REDIRECT_TOKENS = 5000  # 防止内存耗尽

def store_redirect_token(original_url):
    # 生成一个随机令牌并存储原始URL，返回令牌
    token = secrets.token_urlsafe(16)
    with _token_lock:
        # 清理过期令牌
        now = time.time()
        expired = [t for t, data in _redirect_tokens.items() if now - data["timestamp"] > REDIRECT_TOKEN_EXPIRE]
        for t in expired:
            del _redirect_tokens[t]
        # 容量保护：超过上限时拒绝新令牌
        if len(_redirect_tokens) >= _MAX_REDIRECT_TOKENS:
            return None
        _redirect_tokens[token] = {"url": original_url, "timestamp": now}
    return token

def consume_redirect_token(token):
    # 取出并删除令牌对应的URL（一次性消费）
    with _token_lock:
        data = _redirect_tokens.pop(token, None)
    if data and time.time() - data["timestamp"] <= REDIRECT_TOKEN_EXPIRE:
        return data["url"]
    return None

def is_valid_token(token):
    # 检查令牌是否存在且未过期（不删除）
    with _token_lock:
        data = _redirect_tokens.get(token)
        if data and time.time() - data["timestamp"] <= REDIRECT_TOKEN_EXPIRE:
            return True
    return False

# ---------------------------------------------------------------------------
# Honeypot&Captcha_check&log_action
# ---------------------------------------------------------------------------

def honeypot_check():
    if request.form.get("email_confirm", "").strip():
        log_action("bot_detected", detail=f"path={request.path}")
        abort(400)

#审计日志
def log_action(action, user_id=None, username=None, detail=""):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (user_id, username, action, detail) VALUES (?, ?, ?, ?)",
        (user_id, username, action, detail)
    )
    db.commit()

#Captcha check：返回某类别下所有图片的绝对路径列表
_image_list_cache = {}       # {cat: (timestamp, [paths])}
_IMAGE_CACHE_TTL = 1000        # 刷新一次目录扫描的间隔时间（s）

def get_images_in_category(cat):
    # 返回某类别下的图片绝对路径列表（带缓存）
    now = time.time()
    cached = _image_list_cache.get(cat)
    if cached and now - cached[0] < _IMAGE_CACHE_TTL:
        return cached[1]
    cat_dir = os.path.join("captcha_images", cat)
    exts = ['*.png', '*.jpg', '*.jpeg']
    files = []
    for ext in exts:
        files.extend(glob.glob(os.path.join(cat_dir, ext)))
    _image_list_cache[cat] = (now, files)
    return files

#生成九宫格图片列表及验证答案，返回 (selected_items, target_cat, answer_tokens) 或 (None, None, None) 如果某类别为空
def generate_image_captcha():
    categories = ['A', 'B', 'C']
    target_cat = random.choice(categories)
    
    # 获取每个类别的图片列表
    cat_images = {}
    for cat in categories:
        images = get_images_in_category(cat)
        if not images:
            return None, None, None   # 缺少图片，无法生成
        cat_images[cat] = images
    
    # 分配每类抽取数量：共9张，每类至少1张
    total = 9
    min_per_cat = 1
    remaining = total - min_per_cat * 3
    counts = {cat: min_per_cat for cat in categories}
    for _ in range(remaining):
        cat = random.choice(categories)
        counts[cat] += 1
    
    selected_items = []      # 每个元素: {'token': token, 'category': cat, 'path': path}
    token_to_path = {}       # 用于存储映射，后续图片路由使用
    
    for cat in categories:
        num = counts[cat]
        imgs = cat_images[cat]
        # 如果图片数量不足，允许重复（随机抽取可重复）
        if len(imgs) < num:
            samples = random.choices(imgs, k=num)
        else:
            samples = random.sample(imgs, num)
        for img_path in samples:
            token = secrets.token_urlsafe(12)   # 生成随机 token
            token_to_path[token] = (cat, img_path)
            selected_items.append({
                'token': token,
                'category': cat,
                'path': img_path
            })
    random.shuffle(selected_items)
    
    # 答案：目标类别下所有图片的 token
    answer_tokens = [item['token'] for item in selected_items if item['category'] == target_cat]
    
    # 存入 session
    session['img_captcha_mapping'] = token_to_path
    session['img_captcha_answer'] = answer_tokens
    session['img_captcha_target'] = target_cat
    # 可选：设置验证码生成时间，用于过期控制（10分钟）
    session['img_captcha_expire'] = time.time() + CAPTCHA_EXPIRE_SECONDS
    
    return selected_items, target_cat, answer_tokens


def check_captcha_rate_limit():
    # 检查验证码生成频率。返回 (allowed: bool, error_msg: str)
    now = time.time()
    last_gen = session.get('img_captcha_last_gen', 0)
    gen_count = session.get('img_captcha_gen_count', 0)
    if now - last_gen > CAPTCHA_RATE_WINDOW:
        session['img_captcha_gen_count'] = 1
        session['img_captcha_last_gen'] = now
        return True, ""
    if gen_count >= CAPTCHA_RATE_MAX:
        return False, "Too many captcha requests. Please wait a minute."
    session['img_captcha_gen_count'] = gen_count + 1
    return True, ""


def build_captcha_grid_html(selected_items, target_cat, next_url):
    # 构建验证码九宫格 HTML 片段（可嵌入任意页面）
    # 防御：拒绝非相对路径的 next_url，防止开放重定向
    if not is_safe_redirect(next_url):
        next_url = "/"
    csrf_token = generate_csrf_token()
    category_name = CAPTCHA_CATEGORY_NAMES
    target_display = category_name.get(target_cat, target_cat)
    safe_next = escape_html(next_url)

    html = f'''<h2>图片分类验证</h2>
<p>请<strong>点击图片</strong>选择所有属于 <strong>{target_display}</strong> 类别的图片。</p>
<form method="post" action="/image_captcha">
<input type="hidden" name="_csrf_token" value="{csrf_token}">
<input type="hidden" name="next" value="{safe_next}">
<div class="captcha-grid">
'''
    for item in selected_items:
        img_url = url_for('captcha_img', token=item['token'], _external=True)
        html += f'''
<div class="captcha-cell">
    <label class="captcha-label">
        <input type="checkbox" name="selected_tokens" value="{item['token']}" class="captcha-checkbox">
        <img src="{img_url}" class="captcha-img">
        <span class="checkmark">✓</span>
    </label>
</div>'''
    html += '''
</div>
<input type="submit" value="提交验证" class="captcha-submit">
</form>'''
    return html


@app.route("/captcha_img/<token>")
def captcha_img(token):
    # 返回经过随机混淆的图片。每次请求均重新生成随机变换，防止攻击者建立 token→图片 的稳定映射。
    # 要求图片已用 preprocess_images.py 预处理为 150×150 PNG，否则运行时性能会下降。
    mapping = session.get('img_captcha_mapping')
    if not mapping or token not in mapping:
        abort(404)
    cat, img_path = mapping[token]
    if not os.path.exists(img_path):
        abort(404)

    try:
        img = Image.open(img_path).convert('RGB')
    except Exception:
        abort(404)

    # 注：图片应已用 preprocess_images.py 预处理为 150×150 PNG，此处不再做初始缩放

    # 1. 随机旋转 (-180..180 度)
    angle = random.uniform(-180, 180)
    img = img.rotate(angle, expand=False, fillcolor=(255, 255, 255))  # expand=False 保持尺寸

    # 2. 随机缩放 (0.9~1.1) 并裁切/填充回目标尺寸
    scale = random.uniform(0.9, 1.1)
    new_w = int(img.width * scale)
    new_h = int(img.height * scale)
    img = img.resize((new_w, new_h), Image.Resampling.LANCZOS)
    if new_w > CAPTCHA_IMG_SIZE[0] or new_h > CAPTCHA_IMG_SIZE[1]:
        # 裁切
        left = (new_w - CAPTCHA_IMG_SIZE[0]) // 2
        top = (new_h - CAPTCHA_IMG_SIZE[1]) // 2
        img = img.crop((left, top, left + CAPTCHA_IMG_SIZE[0], top + CAPTCHA_IMG_SIZE[1]))
    else:
        # 填充白色
        new_img = Image.new('RGB', CAPTCHA_IMG_SIZE, (255, 255, 255))
        paste_x = (CAPTCHA_IMG_SIZE[0] - new_w) // 2
        paste_y = (CAPTCHA_IMG_SIZE[1] - new_h) // 2
        new_img.paste(img, (paste_x, paste_y))
        img = new_img

    # 3. 轻微高斯模糊
    blur_radius = random.uniform(0, 0.8)
    if blur_radius > 0:
        img = img.filter(ImageFilter.GaussianBlur(radius=blur_radius))

    draw = ImageDraw.Draw(img)
    width, height = img.size

    # 4. 随机噪点
    for _ in range(200):
        x = random.randint(0, width - 1)
        y = random.randint(0, height - 1)
        draw.point((x, y), fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))

    # 5. 随机几何图形干扰（圆形、方形、三角形）
    num_shapes = random.randint(3, 8)
    for _ in range(num_shapes):
        shape_type = random.choice(['circle', 'square', 'triangle'])
        # 随机位置
        x = random.randint(0, width)
        y = random.randint(0, height)
        size = random.randint(10, 40)
        color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))  # 随机颜色；PIL 不支持 alpha
        outline_width = random.randint(1, 2)
        if shape_type == 'circle':
            draw.ellipse((x - size // 2, y - size // 2, x + size // 2, y + size // 2), outline=color, width=outline_width)
        elif shape_type == 'square':
            draw.rectangle((x - size // 2, y - size // 2, x + size // 2, y + size // 2), outline=color, width=outline_width)
        else:  # triangle
            h = size * (3 ** 0.5) / 2  # 三角形高度
            points = [
                (x, y - h / 2),
                (x + size / 2, y + h / 2),
                (x - size / 2, y + h / 2)
            ]
            draw.polygon(points, outline=color, width=outline_width)

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    response = make_response(buf.getvalue())
    response.headers['Content-Type'] = 'image/png'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response


@app.route("/image_captcha", methods=["GET", "POST"])
def image_captcha():
    if request.method == "GET":
        # 全局速率限制（防 DoS）
        if check_global_captcha_rate():
            flash("Too many captcha requests. Please wait a moment.", "error")
            return redirect(url_for("index"))
        # 每 session 频率限制
        allowed, err_msg = check_captcha_rate_limit()
        if not allowed:
            flash(err_msg, "error")
            return redirect(url_for("index"))

        result = generate_image_captcha()
        if result[0] is None:
            flash("图片验证码未就绪：请确保 captcha_images/A, B, C 文件夹内都有图片。", "error")
            return redirect(url_for("index"))
        selected_items, target_cat, _ = result

        # 独立页面模式（protected_link 跳转过来的）
        next_url = request.args.get("next", "")
        captcha_grid = build_captcha_grid_html(selected_items, target_cat, next_url)
        content = captcha_grid + '<p><a href="/">返回首页</a></p>'
        return render_template_string(BASE, title="图片验证", content=content)
    
    # POST 处理
    if request.method == "POST":
        honeypot_check()
        # CSRF 已由全局 before_request 自动校验，这里无需重复
        selected = request.form.getlist("selected_tokens")
        next_url = request.form.get("next", "")  # 保存来源页面，失败/过期时原路带回
        expected = session.get('img_captcha_answer')
        if expected is None:
            flash("验证码数据已失效，请重新验证。", "error")
            # 清除可能残留的 session 数据
            session.pop('img_captcha_mapping', None)
            session.pop('img_captcha_answer', None)
            session.pop('img_captcha_target', None)
            session.pop('img_captcha_expire', None)
            return redirect(url_for("image_captcha", next=next_url))
        # 检查验证码是否过期
        expire = session.get('img_captcha_expire', 0)
        if time.time() > expire:
            flash("验证码已过期，请重新验证。", "error")
            # 清除 session 数据
            session.pop('img_captcha_mapping', None)
            session.pop('img_captcha_answer', None)
            session.pop('img_captcha_target', None)
            session.pop('img_captcha_expire', None)
            return redirect(url_for("image_captcha", next=next_url))
        
        if set(selected) == set(expected):
            flash("验证通过！", "success")
            # 清除验证数据
            session.pop('img_captcha_mapping', None)
            session.pop('img_captcha_answer', None)
            session.pop('img_captcha_target', None)
            session.pop('img_captcha_expire', None)
            # 纯 session 方案：验证通过后设置 session 标志，有效期 120 秒，限定目标路径
            # 重定向到原来请求的页面（无需 URL 令牌）
            next_url = request.form.get("next") or url_for("index")
            # 防止开放重定向：只允许相对路径
            if not is_safe_redirect(next_url):
                next_url = url_for("index")
            session['img_captcha_verified'] = True
            session['img_captcha_verified_expire'] = time.time() + CAPTCHA_ONE_TIME_EXPIRE
            session['img_captcha_verified_for'] = next_url
            return redirect(next_url)
        else:
            flash("验证失败，请重试。", "error")
            # 清除旧的 session 数据，强制重新生成
            session.pop('img_captcha_mapping', None)
            session.pop('img_captcha_answer', None)
            session.pop('img_captcha_target', None)
            session.pop('img_captcha_expire', None)
            return redirect(url_for("image_captcha", next=next_url))


def generate_session_token():
    return secrets.token_hex(32)  #生成64字符会话令牌

def validate_captcha_token():
    # GET 阶段：检查 session 中是否存在有效的验证标志（不消费）。
    # 验证标志限定路径——为 /login 验证的不应用于 /register 或 /protected_link。
    if not session.get('img_captcha_verified'):
        return False
    expire = session.get('img_captcha_verified_expire', 0)
    if time.time() > expire:
        return False
    verified_for = session.get('img_captcha_verified_for', '')
    if verified_for:
        # 只比较路径（去掉查询参数），因为 request.path 不含 ?token=xxx
        verified_path = urllib.parse.urlparse(verified_for).path
        if verified_path != request.path:
            return False
    return True

def has_valid_captcha():
    # POST 阶段：检查 session 中是否存在有效的验证标志（不消费）。
    if not session.get('img_captcha_verified'):
        return False
    expire = session.get('img_captcha_verified_expire', 0)
    return time.time() < expire

def consume_captcha_token():
    # 销毁 session 中的验证标志（登录/注册/外链操作成功后调用）。
    session.pop('img_captcha_verified', None)
    session.pop('img_captcha_verified_expire', None)
    session.pop('img_captcha_verified_for', None)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
class WikiRenderer(mistune.HTMLRenderer):
    def heading(self, text, level):
        #为标题生成 id，例如 '## My Section' -> <h2 id="my-section">My Section</h2>
        # 生成 id：小写，去掉首尾空格，替换空格为连字符，仅保留字母数字和连字符
        slug_id = re.sub(r'[^\w\s-]', '', text.lower()).strip().replace(' ', '-')
        return f'<h{level} id="{slug_id}">{text}</h{level}>'

    def link(self, text, url, title=None):
        if url.startswith("##"):
         # 页内锚点：例如 [go](##section) → <a href="#section">go</a>
            anchor = url[2:]
            # 去掉一个 #，保留剩余部分作为锚点；仅允许合法字符，防止不规范输入
            if not re.fullmatch(r"[a-zA-Z0-9_\-\.]+", anchor):
                anchor = ''
            # 不合法则忽略，生成 # 链接（回到顶部）
            url = f'#{anchor}'
        # 处理内部 Wiki 链接 [page](#slug) → /slug
        elif url.startswith("#") and not url.startswith("#!"):
            slug = url[1:]
            if re.fullmatch(r"[a-zA-Z0-9_\-]+", slug):
                url = f"/{slug}"
            else:
                url = "#"

        # 相对路径或锚点，直接保留
        if url.startswith(('/', '#')):
            return super().link(text, url, title)

        # 所有外部 http/https 链接：生成令牌，跳转到受保护路由
        if url.startswith(('http://', 'https://')):
            token = store_redirect_token(url)          # 生成令牌，隐藏真实URL
            if token is None:
                # 令牌池满，不暴露裸链接——否则攻击者可故意填满令牌池来绕过保护
                return f'<span class="unsafe-image">[Link temporarily unavailable: {escape_html(text)}]</span>'
            protected_url = url_for('protected_link', token=token, _external=False)
            return super().link(text, protected_url, title)

        # 其他协议（mailto: 等）原样保留
        return super().link(text, url, title)
    
    def image(self, text, url, title=None):
        allowed = ('.png', '.jpg', '.jpeg', '.gif')
        if urllib.parse.urlparse(url).path.lower().endswith(allowed):
            return super().image(text, url, title)
        else:
            # 可选：返回一个带样式的提示
            return f'<span class="unsafe-image">[Blocked unsafe image: {escape_html(text)}]</span>'


_md_renderer = None

def md2html(md_text: str) -> str:
    # Render Markdown to HTML using a cached renderer instance.
    global _md_renderer
    if _md_renderer is None:
        _md_renderer = mistune.create_markdown(renderer=WikiRenderer(escape=True))
    return _md_renderer(md_text)

# ---------------------------------------------------------------------------
# History helpers
# ---------------------------------------------------------------------------

def add_history(page_id, content_md, user_id, timestamp):
    # Insert a history record and trim excess entries.
    # Caller is expected to handle the outer transaction and commit.
    db = get_db()
    db.execute(
        "INSERT INTO page_history (page_id, content_md, edited_by, edited_at) VALUES (?,?,?,?)",
        (page_id, content_md, user_id, timestamp),
    )
    db.execute(
        "DELETE FROM page_history WHERE page_id = ? AND id IN ("
        "  SELECT id FROM page_history WHERE page_id = ?"
        "  ORDER BY edited_at DESC LIMIT -1 OFFSET ?"
        ")",
        (page_id, page_id, HISTORY_MAX),
    )

# ---------------------------------------------------------------------------
# Template (base HTML)
# ---------------------------------------------------------------------------
BASE = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} — Wiki</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;padding:0;color:#1d1d1d;background:#fefefe;font-family:sans-serif}
  nav{display:flex;flex-wrap:wrap;align-items:baseline;gap:0.8em;padding:0.3em 1em;background:#f0f0f0;font-size:1em;line-height:1.3}
  nav a,nav span{white-space:nowrap;color:inherit;text-decoration:none}
  nav form{display:inline;margin:0}
  nav form input[type="hidden"]{display:none !important}
  nav form button{background:none;border:none;padding:0;margin:0;font:inherit;color:inherit;text-decoration:underline;cursor:pointer;line-height:inherit;vertical-align:baseline}
  #search-form{display:inline-flex;align-items:center;gap:0.3em;margin:0}
  #search-form input[type="text"]{width:auto !important;display:inline-block !important;margin:0 !important;height:2em;box-sizing:border-box;padding:0 6px;border:1px solid #aaa;font:inherit;line-height:1}
  #search-form input[type="submit"]{height:2em;box-sizing:border-box;padding:0 10px;border:1px solid #aaa;background:#eaeaea;cursor:pointer;font:inherit;line-height:1;margin:0}
  .flash{padding:.5em 1em}
  .flash.success{background:#d4edda}
  .flash.warning{background:#fff3cd}
  .flash.error{background:#f8d7da}
  article{padding:1em;margin:auto;max-width:100ch;font-size:1.25em;line-height:1.75}
  article img{max-width:100%;height:auto}
  textarea{width:100%;min-height:20em;font:inherit}
  form label,form input:not([type=submit]):not(#search-form input),form textarea,form select{display:block;margin:.5em 0;width:100%}
  form input[type=submit],form button{margin-top:1em}
  .js-status{margin:0;padding:1em 1.5em;font-weight:bold;border-bottom:2px solid #aaa}
  .js-on{background:#fff3cd;color:#856404}
  .js-off{background:#d4edda;color:#155724}
  .notice{background:#f0f0f0;padding:1em;border-left:4px solid #bbb;margin:1em 0}
  .error-box{background:#f8d7da;border:2px solid #a94442;padding:1.5em;margin:1em 0;text-align:center}
  .error-box h1{color:#a94442;margin-top:0}
  .form-row{display:none !important}
  .history-preview{white-space:pre-wrap;background:#f9f9f9;padding:.5em}
  .admin-table{width:100%;border-collapse:collapse;margin-bottom:1em}
  .admin-table th,.admin-table td{padding:0.5em 0.75em;text-align:left;border-bottom:1px solid #ddd;vertical-align:middle}
  .admin-table th{background:#f4f4f4;font-weight:bold}
  .admin-table td:first-child,.admin-table th:first-child{width:30%}
  .admin-table td:last-child,.admin-table th:last-child{width:15%}
  .inline-form{display:inline}
  .inline-form select,.inline-form button{vertical-align:middle}
  .danger-link{color:red}
  .danger-btn{color:red;background:none;border:1px solid red}
  .audit-table{width:100%;border-collapse:collapse;font-size:0.9em}
  .captcha-grid{display:grid;grid-template-columns:repeat(3,150px);gap:8px;justify-content:center}
  .captcha-cell{text-align:center;position:relative}
  .captcha-label{display:inline-block;cursor:pointer;position:relative}
  .captcha-checkbox{position:absolute;opacity:0;width:0;height:0;pointer-events:none}
  .captcha-img{width:150px;height:150px;object-fit:contain;border:2px solid #ccc;transition:all 0.1s;vertical-align:bottom}
  .captcha-checkbox:checked+.captcha-img{border-color:#4caf50;box-shadow:0 0 0 2px #4caf50}
  .captcha-checkbox:checked+.captcha-img+.checkmark{display:flex}
  .checkmark{display:none;position:absolute;bottom:5px;right:5px;background:#4caf50;color:#fff;font-size:20px;font-weight:bold;width:28px;height:28px;border-radius:50%;align-items:center;justify-content:center;pointer-events:none}
  .captcha-submit{display:block;margin:16px auto}
</style>
</head>
<body>
<noscript><div class="js-status js-off"> Strange, it seems the browser's JS is only half disabled? Don't worry, this Wiki works perfectly without JS.</div></noscript>
<script>document.write('<div class="js-status js-on">Warning: JS is enabled. It is recommended to disable JS for the safest experience.</div>');</script>

<nav>
  <a href="/">Home</a>
  <a href="/pages">All Pages</a>
  {% if session.user_id %}
    <span>{{ session.username }} ({{ session.role }})</span>
    {% if session.role in ('admin','writer') %}<a href="/new">New</a>{% endif %}
    {% if session.role == 'admin' %}<a href="/admin">Manage Users</a>{% endif %}
    <a href="/change_password">Change Password</a>
    <form method="post" action="/logout">
      <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
      <button type="submit">Logout</button>
    </form>
  {% else %}
    <a href="/login">Login</a>{% if allow_registration %} <a href="/register">Register</a>{% endif %}
  {% endif %}
  <form id="search-form" method="get" action="/search">
    <input type="text" name="q" placeholder="Search...">
    <input type="submit" value="Go">
  </form>
</nav>

{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    {% for cat, msg in messages %}<div class="flash {{ cat }}">{{ msg }}</div>{% endfor %}
  {% endif %}
{% endwith %}

<article>{{ content|safe }}</article>
</body>
</html>"""

@app.context_processor
def inject_allow_registration():
    return dict(allow_registration=ALLOW_REGISTRATION or not db_has_users())

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    page = db.execute("SELECT * FROM pages WHERE slug = 'home'").fetchone()
    user = get_current_user()
    can_edit = user and user["role"] in ("admin", "writer")

    if page:
        rendered = md2html(page["content_md"])
        actions = []
        if can_edit:
            actions.append('<a href="/edit/home">Edit</a>')
        if user:
            actions.append('<a href="/history/home">History</a>')
            if user["role"] == "admin":
                actions.append('<a href="/delete/home">Delete</a>')
        actions_html = ("<p>" + " | ".join(actions) + "</p>") if actions else ""
        note = ""
        if user and not can_edit:
            note = '<div class="notice"> You are logged in as reader. Ask an admin to become writer.</div>'
        return render_template_string(BASE, title="Home", content=actions_html + note + rendered)

    # No home page yet
    query = request.args.get("q", "").strip()
    safe_query = escape_html(query) if query else ""
    if query:
        # 转义 LIKE 通配符 % 和 _
        escaped_query = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        pages = db.execute(
            "SELECT slug, updated_at FROM pages WHERE slug LIKE ? ESCAPE '\\' ORDER BY updated_at DESC",
            (f"%{escaped_query}%",)
        ).fetchall()
    else:
        pages = db.execute("SELECT slug, updated_at FROM pages ORDER BY updated_at DESC").fetchall()

    list_html = ""
    if pages:
        items = "".join(
            f'<li><a href="/{escape_html(p["slug"])}">{escape_html(p["slug"])}</a> <small>(updated {p["updated_at"]})</small></li>'
            for p in pages
        )
        list_html = f"<h2>All Pages</h2><ul>{items}</ul>"
    else:
        list_html = "<p>No pages yet.</p>"

    search_html = f"""
    <form method="get" action="/">
      <label>Search: <input type="text" name="q" value="{safe_query}"></label>
      <input type="submit" value="Search">
    </form>
    """
    c = f"<h1>Welcome to the Wiki</h1>{search_html}{list_html}"
    if can_edit:
        c += '<p><a href="/new">Create a new page</a></p>'
    else:
        if not db_has_users():
            c += '<p><a href="/setup">Set up admin account</a> to start editing.</p>'
        else:
            c += '<p><a href="/login">Log in</a> to contribute.</p>'
    return render_template_string(BASE, title="Home", content=c)

@app.route("/<slug>")
def view_page(slug):
    slug, valid = validate_slug(slug)
    if not valid:
        abort(404)
    if slug == "home":
        return redirect(url_for("index"))

    db = get_db()
    page = db.execute("SELECT * FROM pages WHERE slug = ?", (slug,)).fetchone()
    if page is None:
        user = get_current_user()
        can_create = user and user["role"] in ("admin", "writer")
        safe_slug = escape_html(slug)
        c = f'<div class="error-box"><h1>404 – Page “{safe_slug}” not found</h1>'
        if can_create:
            c += f'<p><a href="/edit/{safe_slug}">Create this page</a></p>'
        elif user:
            c += '<p>Your account (reader) cannot create pages.</p>'
        else:
            c += '<p><a href="/login">Log in</a> to create this page.</p>'
        c += '</div>'
        return render_template_string(BASE, title="Not Found", content=c), 404

    user = get_current_user()
    can_edit = user and user["role"] in ("admin", "writer")
    rendered = md2html(page["content_md"])

    parts = []
    if can_edit:
        parts.append(f'<a href="/edit/{escape_html(slug)}">Edit</a>')
    if user:
        parts.append(f'<a href="/history/{escape_html(slug)}">History</a>')
    if user and user["role"] == "admin":
        parts.append(f'<a href="/delete/{escape_html(slug)}">Delete</a>')
    actions = ("<p>" + " | ".join(parts) + "</p>") if parts else ""

    note = ""
    if user and not can_edit:
        note = '<div class="notice"> You are logged in as reader. Ask an admin to become writer.</div>'

    return render_template_string(BASE, title=slug, content=actions + note + rendered)

@app.route("/new", methods=["GET", "POST"])
def new_page():
    check = check_write_permission()
    if check:
        return check

    if request.method == "POST":
        honeypot_check()
        slug = request.form.get("slug", "").strip()
        content_md = request.form.get("content", "")

        # 限制长度，解决潜在ReDoS风险
        if len(content_md) > MAX_CONTENT_SIZE:
            flash(f"Content is too large. Maximum allowed size is {MAX_CONTENT_SIZE // 1024} KB.", "error")
            token = generate_csrf_token()
            safe_slug = escape_html(slug)
            safe_content = escape_html(content_md)
            c = f"""<h1>New Page</h1>
<form method="post">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <label>Slug (URL name): <input type="text" name="slug" required pattern="[a-zA-Z0-9_\\-]+" placeholder="e.g. my-page" value="{safe_slug}"></label>
  <label>Content (Markdown):</label>
  <textarea name="content" placeholder="Write here...">{safe_content}</textarea>
  <input type="submit" value="Create">
</form>"""
            return render_template_string(BASE, title="New Page", content=c)

        if slug.lower() == "home":
            flash("Please edit the homepage directly.", "warning")
            return redirect(url_for("edit_page", slug="home"))
        if not SLUG_RE.fullmatch(slug):
            flash("Slug may only contain letters, numbers, hyphens, underscores.", "error")
        else:
            db = get_db()
            if db.execute("SELECT id FROM pages WHERE slug = ?", (slug,)).fetchone():
                flash(f"Page “{escape_html(slug)}” already exists.", "error")
            else:
                now = datetime.now(timezone.utc).strftime(TIME_FORMAT)
                uid = session["user_id"]
                db.execute("BEGIN IMMEDIATE")
                try:
                    cursor = db.execute(
                        "INSERT INTO pages (slug, content_md, created_at, updated_at, created_by, updated_by) VALUES (?,?,?,?,?,?)",
                        (slug, content_md, now, now, uid, uid),
                    )
                    page_id = cursor.lastrowid
                    add_history(page_id, content_md, uid, now)
                    db.execute("COMMIT")
                except Exception:
                    db.execute("ROLLBACK")
                    flash("Failed to create page due to server error.", "error")
                    return redirect(url_for("new_page"))
                flash("Page created.", "success")
                return redirect(url_for("view_page", slug=slug))

    token = generate_csrf_token()
    c = f"""<h1>New Page</h1>
<form method="post">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <label>Slug (URL name): <input type="text" name="slug" required pattern="[a-zA-Z0-9_\\-]+" placeholder="e.g. my-page"></label>
  <label>Content (Markdown):</label>
  <textarea name="content" placeholder="Write here..."></textarea>
  <input type="submit" value="Create">
</form>"""
    return render_template_string(BASE, title="New Page", content=c)

@app.route("/edit/<slug>", methods=["GET", "POST"])
def edit_page(slug):
    slug, valid = validate_slug(slug)
    if not valid:
        abort(404)
    check = check_write_permission()
    if check:
        return check

    db = get_db()
    page = db.execute("SELECT * FROM pages WHERE slug = ?", (slug,)).fetchone()
    user = get_current_user()

    if request.method == "POST":
        honeypot_check()
        content_md = request.form.get("content", "")

        # 限制长度，解决潜在ReDoS风险
        if len(content_md) > MAX_CONTENT_SIZE:
            flash(f"Content is too large. Maximum allowed size is {MAX_CONTENT_SIZE // 1024} KB.", "error")
            existing = page["content_md"] if page else ""
            token = generate_csrf_token()
            safe_slug = escape_html(slug)
            c = f"""<h1>{'Edit' if page else 'Create'} “{safe_slug}”</h1>
<form method="post">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <textarea name="content" placeholder="Markdown content...">{escape_html(existing)}</textarea>
  <input type="submit" value="Save">
</form>"""
            return render_template_string(BASE, title=f"Edit {slug}", content=c)

        now = datetime.now(timezone.utc).strftime(TIME_FORMAT)
        db.execute("BEGIN IMMEDIATE")
        try:
            if page:
                old = page["content_md"]
                db.execute("UPDATE pages SET content_md=?, updated_at=?, updated_by=? WHERE id=?",
                           (content_md, now, user["id"], page["id"]))
                add_history(page["id"], old, user["id"], now)
                flash("Page updated.", "success")
            else:
                cursor = db.execute(
                    "INSERT INTO pages (slug, content_md, created_at, updated_at, created_by, updated_by) VALUES (?,?,?,?,?,?)",
                    (slug, content_md, now, now, user["id"], user["id"]),
                )
                page_id = cursor.lastrowid
                add_history(page_id, content_md, user["id"], now)
                flash("Page created.", "success")
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            flash("Failed to save page due to server error.", "error")
            return redirect(url_for("edit_page", slug=slug))
        return redirect(url_for("view_page", slug=slug) if slug != "home" else url_for("index"))

    existing = escape_html(page["content_md"]) if page else ""
    token = generate_csrf_token()
    safe_slug = escape_html(slug)
    c = f"""<h1>{'Edit' if page else 'Create'} “{safe_slug}”</h1>
<form method="post">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <textarea name="content" placeholder="Markdown content...">{existing}</textarea>
  <input type="submit" value="Save">
</form>"""
    return render_template_string(BASE, title=f"Edit {slug}", content=c)

@app.route("/delete/<slug>", methods=["GET", "POST"])
def delete_page(slug):
    slug, valid = validate_slug(slug)
    if not valid:
        abort(404)
    check = require_login(role="admin")
    if check:
        return check

    db = get_db()
    page = db.execute("SELECT * FROM pages WHERE slug = ?", (slug,)).fetchone()
    if not page:
        flash("Page not found.", "error")
        return redirect(url_for("index"))
    if request.method == "POST":
        honeypot_check()
        db.execute("DELETE FROM pages WHERE id = ?", (page["id"],))
        db.commit()
        flash(f"Page “{escape_html(slug)}” deleted.", "success")
        return redirect(url_for("index"))

    token = generate_csrf_token()
    safe_slug = escape_html(slug)
    c = f"""<h1>Delete “{safe_slug}”?</h1>
<p>Are you sure?</p>
<form method="post">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <input type="submit" value="Yes, delete">
  <a href="/{safe_slug}">Cancel</a>
</form>"""
    return render_template_string(BASE, title=f"Delete {slug}", content=c)

@app.route("/history/<slug>")
def page_history(slug):
    slug, valid = validate_slug(slug)
    if not valid:
        abort(404)
    db = get_db()
    page = db.execute("SELECT id FROM pages WHERE slug = ?", (slug,)).fetchone()
    if not page:
        flash("Page not found.", "error")
        return redirect(url_for("index"))

    logs = db.execute("""
        SELECT h.id, h.content_md, h.edited_at, u.username
        FROM page_history h LEFT JOIN users u ON h.edited_by = u.id
        WHERE h.page_id = ? ORDER BY h.edited_at DESC
    """, (page["id"],)).fetchall()

    if not logs:
        c = "<p>No history yet.</p>"
    else:
        items = ""
        for e in logs:
            preview = escape_html(e["content_md"][:150])
            user_name = escape_html(e["username"] or "unknown")
            # 添加查看完整版本的链接
            view_link = f' <a href="/history/{escape_html(slug)}/{e["id"]}">(old version content)</a>'
            items += f"""<li><strong>{escape_html(e['edited_at'])}</strong> by {user_name}{view_link}<br>
<pre class="history-preview">{preview}…</pre></li>"""
        c = f"<h1>History for “{escape_html(slug)}”</h1><ul>{items}</ul>"
    return render_template_string(BASE, title=f"History: {slug}", content=c)

@app.route("/history/<slug>/<int:history_id>")
def view_history_version(slug, history_id):
    slug, valid = validate_slug(slug)
    if not valid:
        abort(404)
    db = get_db()
    page = db.execute("SELECT id FROM pages WHERE slug = ?", (slug,)).fetchone()
    if not page:
        flash("Page not found.", "error")
        return redirect(url_for("index"))

    entry = db.execute(
        "SELECT content_md, edited_at, edited_by FROM page_history WHERE id = ? AND page_id = ?",
        (history_id, page["id"])
    ).fetchone()
    if not entry:
        abort(404)

    editor = "unknown"
    if entry["edited_by"]:
        user = db.execute("SELECT username FROM users WHERE id = ?", (entry["edited_by"],)).fetchone()
        if user:
            editor = user["username"]

    rendered = md2html(entry["content_md"])
    safe_editor = escape_html(editor)
    safe_ts = escape_html(entry["edited_at"])
    content = f"""<h1>Historical Version of “{escape_html(slug)}”</h1>
<p>Edited by {safe_editor} at {safe_ts}</p>
<hr>
{rendered}
<hr>
<p><a href="/history/{escape_html(slug)}">← Back to history</a></p>"""
    return render_template_string(BASE, title=f"History: {slug}", content=content)

# =========================================================================
# 带验证码的登录路由
# =========================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if not db_has_users():
        flash("No admin account exists. Please set up first.", "warning")
        return redirect(url_for("setup"))

    # GET 请求时验证一次性图片验证令牌（不消费）
    if request.method == "GET":
        if not validate_captcha_token():
            # 嵌入模式：在同一页面展示验证码，而非跳转到独立页面
            allowed, err_msg = check_captcha_rate_limit()
            if not allowed:
                flash(err_msg, "error")
                return redirect(url_for("index"))
            result = generate_image_captcha()
            if result[0] is None:
                flash("图片验证码未就绪：请确保 captcha_images/A, B, C 文件夹内都有图片。", "error")
                return redirect(url_for("index"))
            selected_items, target_cat, _ = result
            captcha_grid = build_captcha_grid_html(selected_items, target_cat, "/login")
            content = f'''<h1>Login</h1>
<div class="notice">请先完成下方图片验证，验证通过后将显示登录表单。</div>
{captcha_grid}
<p><a href="/">返回首页</a></p>'''
            return render_template_string(BASE, title="Login", content=content)
        # 令牌有效，显示登录表单
        return render_template_string(BASE, title="Login", content=login_form())

    if request.method == "POST":
        # 检查是否有有效的图片验证令牌（防止直接 POST 绕过验证码）
        if not has_valid_captcha():
            next_url = request.full_path
            return redirect(url_for('image_captcha', next=next_url))
        # 立即消费令牌——无论后续登录结果如何，单次验证仅限单次 POST 尝试
        consume_captcha_token()

        honeypot_check()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user:
            # 检查锁定（使用 datetime 对象比较）
            locked = False
            if user["locked_until"]:
                try:
                    locked_time = datetime.strptime(user["locked_until"], TIME_FORMAT).replace(tzinfo=timezone.utc)
                    if locked_time > datetime.now(timezone.utc):
                        locked = True
                except ValueError:
                    pass
            if locked:
                # 登录失败（账户已锁定）
                log_action("login_failed", user_id=user["id"], username=user["username"], detail="account locked")  #审计日志
                flash("Invalid username or password.", "error")
                return redirect(url_for("login"))

            if check_password_hash(user["password_hash"], password):
                # 登录成功 —— 先检查速率（含原子性记录）
                if check_global_login_rate():
                    flash("Too many login attempts. Please wait a moment.", "error")
                    return redirect(url_for('image_captcha', next=request.full_path))

                # 事务性更新：重置失败计数 + 写入新会话令牌
                new_token = generate_session_token()
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                        "UPDATE users SET failed_attempts=0, locked_until=NULL, session_token=? WHERE id=?",
                        (new_token, user["id"]),
                    )
                    db.execute("COMMIT")
                except Exception:
                    db.execute("ROLLBACK")
                    flash("Login failed due to server error.", "error")
                    return redirect(url_for("login"))

                session.clear()
                session["session_token"] = new_token
                session["_csrf_token"] = os.urandom(32).hex()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                log_action("login_success", user_id=user["id"], username=user["username"])  #审计日志
                flash("Logged in.", "success")
                next_url = request.args.get("next")
                if next_url and is_safe_redirect(next_url):
                    return redirect(next_url)
                return redirect(url_for("index"))
            else:
                # 密码错误 —— 先检查速率（含原子性记录）
                if check_global_login_rate():
                    flash("Too many login attempts. Please wait a moment.", "error")
                    return redirect(url_for('image_captcha', next=request.full_path))

                # 登录失败：递增计数器并可能锁定
                log_action("login_failed", user_id=user["id"], username=user["username"], detail="wrong password")  #审计日志
                attempts = (user["failed_attempts"] or 0) + 1
                locked_until = None
                if attempts >= LOCKOUT_THRESHOLD:
                    locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION)).strftime(TIME_FORMAT)
                db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                           (attempts, locked_until, user["id"]))
                db.commit()
                flash("Invalid username or password.", "error")
                return redirect(url_for("login"))
        else:
            # 用户不存在 —— 先检查速率（含原子性记录）
            if check_global_login_rate():
                flash("Too many login attempts. Please wait a moment.", "error")
                return redirect(url_for('image_captcha', next=request.full_path))

            log_action("login_failed", username=username, detail="nonexistent user")  #审计日志
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))
    #处理非预期的 GET/POST 之外的请求方法
    return redirect(url_for("login"))


def login_form():
    token = generate_csrf_token()
    show_register = ALLOW_REGISTRATION or not db_has_users()
    register_html = '<p><a href="/register">Don\'t have an account? Register here.</a></p>' if show_register else ''
    return f"""<h1>Login</h1>
<form method="post">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <label>Username: <input type="text" name="username" required autocomplete="username"></label>
  <label>Password: <input type="password" name="password" required autocomplete="current-password"></label>
  <input type="submit" value="Login">
</form>
{register_html}"""

def register_form():
    token = generate_csrf_token()
    return f"""<h1>Register</h1>
<form method="post">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <label>Username: <input type="text" name="username" required autocomplete="username"></label>
  <label>Password: <input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
  <input type="submit" value="Register">
</form>
<p><a href="/login">Already have an account? Login</a></p>"""

# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if not db_has_users():
        flash("Please set up admin first.", "warning")
        return redirect(url_for("setup"))
    if not ALLOW_REGISTRATION:
        abort(403)

    # GET 请求时验证一次性图片验证令牌（不消费）
    if request.method == "GET":
        if not validate_captcha_token():
            # 嵌入模式：在同一页面展示验证码
            allowed, err_msg = check_captcha_rate_limit()
            if not allowed:
                flash(err_msg, "error")
                return redirect(url_for("index"))
            result = generate_image_captcha()
            if result[0] is None:
                flash("图片验证码未就绪：请确保 captcha_images/A, B, C 文件夹内都有图片。", "error")
                return redirect(url_for("index"))
            selected_items, target_cat, _ = result
            captcha_grid = build_captcha_grid_html(selected_items, target_cat, "/register")
            content = f'''<h1>Register</h1>
<div class="notice">请先完成下方图片验证，验证通过后将显示注册表单。</div>
{captcha_grid}
<p><a href="/">返回首页</a></p>'''
            return render_template_string(BASE, title="Register", content=content)
        return render_template_string(BASE, title="Register", content=register_form())

    if request.method == "POST":
        # 检查是否有有效的图片验证令牌（防止直接 POST 绕过验证码）
        if not has_valid_captcha():
            next_url = request.full_path
            return redirect(url_for('image_captcha', next=next_url))
        # 立即消费令牌——无论后续注册结果如何
        consume_captcha_token()

        honeypot_check()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password required.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            db = get_db()
            if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
                flash("Username already taken.", "error")
            else:
                # 先检查速率（含原子性记录），通过后再创建用户
                if check_global_register_rate():
                    flash("Too many registration attempts. Please wait a moment.", "error")
                    return render_template_string(BASE, title="Register", content=register_form()), 429

                # 事务性：创建用户 + 写入会话令牌
                new_token = generate_session_token()
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                        "INSERT INTO users (username, password_hash, role, session_token) VALUES (?, ?, ?, ?)",
                        (username, generate_password_hash(password), "reader", new_token),
                    )
                    db.execute("COMMIT")
                except Exception:
                    db.execute("ROLLBACK")
                    flash("Registration failed due to server error.", "error")
                    return redirect(url_for("register"))

                user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                session.clear()
                session["session_token"] = new_token
                session["_csrf_token"] = os.urandom(32).hex()
                session["user_id"] = user["id"]
                session["username"] = username
                session["role"] = "reader"
                log_action("register", user_id=user["id"], username=username, detail="reader created")  #审计日志
                flash("Registered as reader. Ask an admin to become writer.", "success")
                return redirect(url_for("index"))

    # 验证失败 → 重定向到 /register，需重新通过图片验证
    return redirect(url_for("register"))

@app.route("/logout", methods=["POST"])
def logout():
    if "user_id" in session:
        db = get_db()
        db.execute("UPDATE users SET session_token = NULL WHERE id = ?", (session["user_id"],))
        db.commit()
    # 先保存 flash 消息，再清空 session
    msg = "Logged out."
    session.clear()
    flash(msg, "success")  # flash 会写入新会话，但只含 _flashes，这是安全的
    return redirect(url_for("index"))

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if db_has_users():
        flash("Setup already completed.", "warning")
        return redirect(url_for("index"))
    if request.method == "POST":
        honeypot_check()
        #setup key 验证
        if request.form.get("setup_key", "") != SETUP_KEY:
            flash("Invalid setup key.", "error")
            return redirect(url_for("setup"))   # 重新显示表单
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password required.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            db = get_db()
            # 事务性：创建用户 + 写入会话令牌
            new_token = generate_session_token()
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, role, session_token) VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), "admin", new_token),
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                flash("Setup failed due to server error.", "error")
                return redirect(url_for("setup"))
            user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            session.clear()
            session["session_token"] = new_token
            session["_csrf_token"] = os.urandom(32).hex()
            session["user_id"] = user["id"]
            session["username"] = username
            session["role"] = "admin"
            flash("Welcome! You are now the admin.", "success")
            return redirect(url_for("index"))
    #GET 部分增加 setup key 字段
    token = generate_csrf_token()
    c = f"""<div class="notice"><strong>First time setup – create the admin account.</strong></div>
<h1>Setup</h1>
<form method="post">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <label>Username: <input type="text" name="username" required></label>
  <label>Password: <input type="password" name="password" required minlength="8"></label>
  <label>Setup Key: <input type="password" name="setup_key" required></label>
  <input type="submit" value="Create Admin">
</form>"""
    return render_template_string(BASE, title="Setup", content=c)

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    check = require_login()
    if check:
        return check

    user = get_current_user()
    if not user or user["session_token"] != session.get("session_token"):
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        old_pw = request.form.get("old_password", "")
        new_pw = request.form.get("new_password", "")
        if not old_pw or not new_pw:
            flash("Both fields are required.", "error")
        elif len(new_pw) < 8:
            flash("New password must be at least 8 characters.", "error")
        elif not check_password_hash(user["password_hash"], old_pw):
            flash("Old password is incorrect.", "error")
        else:
            try:
                db = get_db()
                # 事务性：密码哈希 + 新会话令牌 一起提交
                new_token = generate_session_token()
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE users SET password_hash = ?, session_token = ? WHERE id = ?",
                           (generate_password_hash(new_pw), new_token, user["id"]))
                db.execute("COMMIT")
                # 更新当前会话的令牌，这样当前用户不会被踢出
                session["session_token"] = new_token
                log_action("password_changed", user_id=user["id"], username=user["username"])  #审计日志
                flash("Password changed. All other sessions have been invalidated.", "success")
                return redirect(url_for("index"))
            except Exception as e:
                # 打印错误到终端，便于调试
                print(f"Change password error: {e}", file=sys.stderr)
                flash("An error occurred while updating the password. Please try again.", "error")

    token = generate_csrf_token()
    c = f"""<h1>Change Password</h1>
<form method="post">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <label>Old password: <input type="password" name="old_password" required autocomplete="current-password"></label>
  <label>New password: <input type="password" name="new_password" required minlength="8" autocomplete="new-password"></label>
  <input type="submit" value="Change">
</form>"""
    return render_template_string(BASE, title="Change Password", content=c)

# ---------- Admin ----------
@app.route("/admin")
def admin_panel():
    check = require_login(role="admin")
    if check:
        return check
    db = get_db()
    users = db.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    rows = ""
    token = generate_csrf_token()
    for u in users:
        opts = "".join(
            f'<option value="{r}" {"selected" if u["role"]==r else ""}>{r}</option>'
            for r in ["admin", "writer", "reader"]
        )
        safe_name = escape_html(u['username'])
        rows += f"""<tr>
          <td>{safe_name}</td>
          <td><form method="post" action="/admin/change_role" class="inline-form">
            <input type="hidden" name="_csrf_token" value="{token}">
            <input type="hidden" name="user_id" value="{u['id']}">
            <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
            <select name="new_role">{opts}</select>
            <button type="submit">Change</button></form>
          </td>
          <td><a href="/admin/delete_user?user_id={u['id']}" class="danger-link">Delete</a></td></tr>"""
    c = f"""<h1>User Management</h1>
<p><a href="/admin/logs">View Audit Logs</a></p>
<table class="admin-table"><tr><th>Username</th><th>Role</th><th>Action</th></tr>{rows}</table>
<hr><h2>Add User</h2>
<form method="post" action="/admin/add_user">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <label>Username: <input type="text" name="username" required autocomplete="username"></label>
  <label>Password: <input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
  <label>Role: <select name="role"><option value="reader">reader</option><option value="writer">writer</option><option value="admin">admin</option></select></label>
  <input type="submit" value="Create User">
</form>"""
    return render_template_string(BASE, title="Admin", content=c)

# =========================================================================
# Separate confirmation page for delete (GET)
# =========================================================================
@app.route("/admin/logs")
def admin_logs():
    check = require_login(role="admin")
    if check:
        return check
    db = get_db()

    total = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    total_pages = max(1, (total + LOG_PAGE_SIZE - 1) // LOG_PAGE_SIZE)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * LOG_PAGE_SIZE

    logs = db.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
        (LOG_PAGE_SIZE, offset)
    ).fetchall()

    rows = ""
    for l in logs:
        ts = escape_html(l["timestamp"]) if l["timestamp"] else ""
        uid = escape_html(str(l["user_id"])) if l["user_id"] else ""
        uname = escape_html(l["username"]) if l["username"] else ""
        action = escape_html(l["action"])
        detail = escape_html(l["detail"]) if l["detail"] else ""
        rows += f"""<tr>
          <td>{ts}</td>
          <td>{uid}</td>
          <td>{uname}</td>
          <td>{action}</td>
          <td>{detail}</td>
        </tr>"""

    # 分页导航
    pager = ""
    if total_pages > 1:
        prev_link = f'<a href="/admin/logs?page={page-1}">← Prev</a>' if page > 1 else '← Prev'
        next_link = f'<a href="/admin/logs?page={page+1}">Next →</a>' if page < total_pages else 'Next →'
        pager = f'<p>{prev_link} | Page {page}/{total_pages} | {next_link}</p>'

    token = generate_csrf_token()
    content = f"""<h1>Audit Logs ({total} total)</h1>
{pager}
<table class="audit-table">
  <tr><th>Timestamp</th><th>User ID</th><th>Username</th><th>Action</th><th>Detail</th></tr>
  {rows}
</table>
{pager}
<p><a href="/admin/clear_logs" class="danger-link">Clear All Logs</a></p>
<p><a href="/admin">← Back to Admin</a></p>"""
    return render_template_string(BASE, title="Audit Logs", content=content)

@app.route("/admin/clear_logs", methods=["GET", "POST"])
def clear_logs():
    check = require_login(role="admin")
    if check:
        return check
    if request.method == "GET":
        token = generate_csrf_token()
        content = f"""<h1>Clear All Audit Logs?</h1>
<p>Are you sure? This cannot be undone.</p>
<form method="post" action="/admin/clear_logs">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input class="form-row" type="text" name="email_confirm" autocomplete="off" tabindex="-1">
  <input type="submit" value="Yes, clear all logs" class="danger-btn">
  <a href="/admin/logs">Cancel</a>
</form>"""
        return render_template_string(BASE, title="Clear Logs", content=content)
    # POST
    honeypot_check()
    db = get_db()
    db.execute("DELETE FROM audit_log")
    db.commit()
    log_action("admin_clear_logs", user_id=session["user_id"], username=session["username"], detail="all logs cleared")
    flash("All audit logs cleared.", "success")
    return redirect(url_for("admin_logs"))

@app.route("/admin/delete_user", methods=["GET"])
def delete_user_confirm():
    check = require_login(role="admin")
    if check:
        return check
    uid = request.args.get("user_id", "")
    if not uid.isdigit():
        abort(404)
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_panel"))
    token = generate_csrf_token()
    content = f"""<h1>Delete User?</h1>
<p>Are you sure you want to delete user <strong>{escape_html(user['username'])}</strong>?</p>
<form method="post" action="/admin/delete_user">
  <input type="hidden" name="_csrf_token" value="{token}">
  <input type="hidden" name="user_id" value="{uid}">
  <input type="submit" value="Yes, delete" class="danger-btn">
  <a href="/admin">Cancel</a>
</form>"""
    return render_template_string(BASE, title="Delete User", content=content)

@app.route("/admin/add_user", methods=["POST"])
def add_user():
    check = require_login(role="admin")
    if check:
        return check
    honeypot_check()
    db = get_db()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "reader")
    if role not in ("admin", "writer", "reader"):
        role = "reader"
    if not username or not password:
        flash("Username and password required.", "error")
    elif len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
    else:
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )
            db.commit()
            log_action("admin_add_user", user_id=session["user_id"], username=session["username"], detail=f"added {username} as {role}")  #审计日志
            flash(f"User “{escape_html(username)}” created.", "success")
        except sqlite3.IntegrityError:
            flash("Username already exists.", "error")
    return redirect(url_for("admin_panel"))

@app.route("/admin/change_role", methods=["POST"])
def change_role():
    check = require_login(role="admin")
    if check:
        return check
    honeypot_check()
    uid_str = request.form.get("user_id", "")
    if not uid_str.isdigit():
        flash("Invalid user ID.", "error")
        return redirect(url_for("admin_panel"))
    uid = int(uid_str)
    new_role = request.form.get("new_role", "reader")
    if new_role not in ("admin", "writer", "reader"):
        new_role = "reader"
    db = get_db()
    if uid == session["user_id"] and new_role != "admin":
        flash("You cannot downgrade your own admin role.", "error")
    else:
        db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, uid))
        db.commit()
        log_action("admin_change_role", user_id=session["user_id"], username=session["username"], detail=f"user_id {uid} role -> {new_role}")  #审计日志
        flash("Role updated.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete_user", methods=["POST"])
def delete_user():
    check = require_login(role="admin")
    if check:
        return check
    honeypot_check()
    uid_str = request.form.get("user_id", "")
    if not uid_str.isdigit():
        flash("Invalid user ID.", "error")
        return redirect(url_for("admin_panel"))
    uid = int(uid_str)
    db = get_db()
    if uid == session["user_id"]:
        flash("You cannot delete yourself.", "error")
    else:
        db.execute("DELETE FROM users WHERE id = ?", (uid,))
        db.commit()
        log_action("admin_delete_user", user_id=session["user_id"], username=session["username"], detail=f"deleted user_id {uid}")  #审计日志
        flash("User deleted.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/pages")
def list_all_pages():
    #展示所有页面列表（按更新时间倒序）
    db = get_db()
    pages = db.execute(
        "SELECT slug, updated_at FROM pages ORDER BY updated_at DESC"
    ).fetchall()
    if pages:
        items = "".join(
            f'<li><a href="/{escape_html(p["slug"])}">{escape_html(p["slug"])}</a> <small>(updated {p["updated_at"]})</small></li>'
            for p in pages
        )
        results = f"<ul>{items}</ul>"
    else:
        results = "<p>No pages yet.</p>"
    content = f"<h1>All Pages</h1>{results}"
    return render_template_string(BASE, title="All Pages", content=content)

@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    if not query:
        return redirect(url_for("index"))
    safe_query = escape_html(query)

    # 转义 LIKE 通配符
    escaped_query = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

    db = get_db()
    pages = db.execute(
        "SELECT slug, updated_at FROM pages WHERE slug LIKE ? ESCAPE '\\' ORDER BY updated_at DESC",
        (f"%{escaped_query}%",)
    ).fetchall()

    if pages:
        items = "".join(
            f'<li><a href="/{escape_html(p["slug"])}">{escape_html(p["slug"])}</a> <small>(updated {p["updated_at"]})</small></li>'
            for p in pages
        )
        results = f"<ul>{items}</ul>"
    else:
        results = "<p>No pages found.</p>"
    c = f"<h1>Search: “{safe_query}”</h1>{results}"
    return render_template_string(BASE, title=f"Search: {safe_query}", content=c)

# =========================================================================
# 受保护链接路由
# =========================================================================
@app.route("/protected_link", methods=["GET"])
def protected_link():
    token = request.args.get("token", "")
    if not token or not is_valid_token(token):
        flash("Invalid or expired link.", "error")
        return redirect(url_for("index"))

    # 验证一次性图片验证令牌
    if not validate_captcha_token():
        next_url = request.full_path
        return redirect(url_for('image_captcha', next=next_url))

    # 验证通过，立即消费令牌（外链跳转是一次性操作）
    consume_captcha_token()

    # 取出目标 URL
    original_url = consume_redirect_token(token)

    if not original_url:
        flash("Link expired or invalid.", "error")
        return redirect(url_for("index"))
    return render_link_confirmation(original_url)



def render_link_confirmation(original_url):
    # 显示验证通过后的确认页面，包含可点击的外部链接
    safe_url = escape_html(original_url)
    # 注意：href 中直接使用原始 URL，但需要确保协议安全（只允许 http/https）
    content = f"""<h1>External Link Verification Passed</h1>
<p>The link you requested has been verified. You can now access it by clicking the button below.</p>
<p><strong>URL:</strong> <a href="{safe_url}" rel="noreferrer noopener" target="_blank">{safe_url}</a></p>
<p>Or <a href="/">return to home page</a>.</p>
"""
    return render_template_string(BASE, title="External Link", content=content)

# =========================================================================
# Error handlers
# =========================================================================
@app.errorhandler(404)
def not_found(e):
    c = '<div class="error-box"><h1>404 – Page Not Found</h1><p><a href="/">← Back to home</a></p></div>'
    return render_template_string(BASE, title="Not Found", content=c), 404

@app.errorhandler(403)
def forbidden(e):
    c = '<div class="error-box"><h1>403 – Forbidden</h1><p>You do not have permission.</p></div>'
    return render_template_string(BASE, title="Forbidden", content=c), 403

# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_captcha_folders()
    print("="*60)
    print(" Zero-JS Wiki ")
    print("WARNING: This application is designed for single-worker deployment only.")
    print("  http://127.0.0.1:4000")
    print("="*60)
    init_db()
    app.run(host="127.0.0.1", port=4000, debug=False)
