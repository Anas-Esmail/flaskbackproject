from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import hashlib  # Added missing import
from werkzeug.utils import secure_filename


# ===== إعداد الفلاسك =====
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///thebest.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# إعداد مجلد التحميلات
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp4'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# إنشاء مجلد التحميلات إذا لم يكن موجودًا
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db = SQLAlchemy(app)

# ===== النماذج =====
class University(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    whatsapp_group = db.Column(db.String(200))  # رابط واتساب
    subjects = db.relationship('Subject', backref='university', lazy=True)
    users = db.relationship('User', backref='university', lazy=True)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    university_id = db.Column(db.Integer, db.ForeignKey('university.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    discussion_group = db.Column(db.String(200))  # رابط واتساب للمناقشة
    lessons = db.relationship('Lesson', backref='subject', lazy=True)

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    video_path = db.Column(db.String(200))  # رابط الفيديو أو اسم الملف

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    whatsapp_number = db.Column(db.String(20))
    university_id = db.Column(db.Integer, db.ForeignKey('university.id'))
    device_id = db.Column(db.String(200))  # معرف الجهاز
    permissions = db.relationship('Permission', backref='user', lazy=True)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)

# ===== إنشاء قاعدة البيانات والجداول =====
with app.app_context():
    db.create_all()

    # إنشاء مسؤول افتراضي
    if not User.query.filter_by(email='admin@thebest.edu').first():
        admin = User(
            name='Admin',
            email='admin@thebest.edu',
            password=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

# ===== ديكورات للمساعدة =====
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            flash("هذه الصفحة للمسؤول فقط")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ===== دالة Device ID (يمكن تعديلها حسب متطلباتك) =====
def get_device_id():
    # مثال: يمكنك استخدام IP + User-Agent لتوليد معرف مؤقت
    user_agent = request.headers.get('User-Agent', '')
    ip = request.remote_addr
    return hashlib.md5(f"{ip}-{user_agent}".encode()).hexdigest()

# ===== المسارات =====
from datetime import datetime

@app.context_processor
def utility_processor():
    return {'now': datetime.now}

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    universities = University.query.all()
    uni_stats = []
    for uni in universities:
        subjects_count = Subject.query.filter_by(university_id=uni.id).count()
        students_count = User.query.filter_by(university_id=uni.id).count()
        uni_stats.append({
            'id': uni.id,
            'name': uni.name,
            'whatsapp_link': uni.whatsapp_group,
            'subjects_count': subjects_count,
            'students_count': students_count,
            'subjects': Subject.query.filter_by(university_id=uni.id).all()
        })
    return render_template('index.html', uni_stats=uni_stats)

# ===== تسجيل الدخول =====
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            current_device = get_device_id()
            if not user.device_id:
                user.device_id = current_device
                db.session.commit()
            if user.device_id != current_device:
                flash("❌ لا يمكنك تسجيل الدخول من هذا الجهاز. استخدم الجهاز المسجل فقط.")
                return redirect(url_for('login'))
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('dashboard'))
        flash("البريد أو كلمة المرور غير صحيحة")
    return render_template('login.html')

# ===== تسجيل الخروج =====
@app.route('/logout')
def logout():
    session.clear()
    flash('تم تسجيل الخروج')
    return redirect(url_for('login'))

# ===== إنشاء حساب جديد =====
@app.route('/register', methods=['GET', 'POST'])
def register():
    universities = University.query.all()
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        whatsapp_number = request.form['whatsapp_number']
        university_id = request.form['university_id']
        if User.query.filter_by(email=email).first():
            flash('البريد الإلكتروني مسجل مسبقاً')
            return redirect(url_for('register'))
        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            is_admin=False,
            whatsapp_number=whatsapp_number,
            university_id=university_id
        )
        db.session.add(new_user)
        db.session.commit()
        flash('تم إنشاء الحساب بنجاح، يمكنك تسجيل الدخول الآن')
        return redirect(url_for('login'))
    return render_template('register.html', universities=universities)

# ===== لوحة الطالب =====
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    subject_ids = [p.subject_id for p in Permission.query.filter_by(user_id=user.id).all()]
    subjects = Subject.query.filter(Subject.id.in_(subject_ids)).all()
    return render_template('dashboard.html', user=user, subjects=subjects)

@app.route('/lessons/<int:subject_id>')
@login_required
def lessons(subject_id):
    user_id = session['user_id']
    if not Permission.query.filter_by(user_id=user_id, subject_id=subject_id).first():
        flash("ليس لديك صلاحية مشاهدة هذه المادة")
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    subject = Subject.query.get_or_404(subject_id)
    lessons = Lesson.query.filter_by(subject_id=subject_id).all()

    return render_template('lessons.html', user=user, subject=subject, lessons=lessons)

# ===== لوحة المسؤول =====
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    universities = University.query.all()
    subjects = Subject.query.all()
    lessons = Lesson.query.all()
    users = User.query.filter_by(is_admin=False).all()
    return render_template('admin_dashboard.html', universities=universities,
                           subjects=subjects, lessons=lessons, users=users)

# ===== إدارة الجامعات =====
@app.route('/admin/university', methods=['GET','POST'])
@app.route('/admin/university/<int:university_id>', methods=['GET','POST'])
@admin_required
def manage_university(university_id=None):
    if university_id:
        uni = University.query.get_or_404(university_id)
    else:
        uni = None
    if request.method == 'POST':
        name = request.form['name']
        whatsapp_group = request.form.get('whatsapp_group')
        if uni:
            uni.name = name
            uni.whatsapp_group = whatsapp_group
            flash('تم تعديل الجامعة')
        else:
            db.session.add(University(name=name, whatsapp_group=whatsapp_group))
            flash('تمت إضافة الجامعة')
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('university_form.html', university=uni)

@app.route('/admin/delete_university/<int:university_id>')
@admin_required
def delete_university(university_id):
    uni = University.query.get_or_404(university_id)
    db.session.delete(uni)
    db.session.commit()
    flash('تم حذف الجامعة')
    return redirect(url_for('admin_dashboard'))

# ===== إدارة المواد =====
@app.route('/admin/subject', methods=['GET','POST'])
@app.route('/admin/subject/<int:subject_id>', methods=['GET','POST'])
@admin_required
def manage_subject(subject_id=None):
    universities = University.query.all()
    if subject_id:
        subject = Subject.query.get_or_404(subject_id)
    else:
        subject = None
    if request.method == 'POST':
        name = request.form['name']
        university_id = request.form['university_id']
        discussion_group = request.form.get('discussion_group')
        if subject:
            subject.name = name
            subject.university_id = university_id
            subject.discussion_group = discussion_group
            flash('تم تعديل المادة')
        else:
            db.session.add(Subject(name=name, university_id=university_id, discussion_group=discussion_group))
            flash('تمت إضافة المادة')
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('subject_form.html', subject=subject, universities=universities)

@app.route('/admin/delete_subject/<int:subject_id>')
@admin_required
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    db.session.delete(subject)
    db.session.commit()
    flash('تم حذف المادة')
    return redirect(url_for('admin_dashboard'))

# ===== إدارة الدروس =====
# تعديل دالة manage_lesson
@app.route('/admin/lesson', methods=['GET','POST'])
@app.route('/admin/lesson/<int:lesson_id>', methods=['GET','POST'])
@admin_required
def manage_lesson(lesson_id=None):
    subjects = Subject.query.all()
    if lesson_id:
        lesson = Lesson.query.get_or_404(lesson_id)
    else:
        lesson = None

    if request.method == 'POST':
        title = request.form['title']
        subject_id = request.form['subject_id']

        # التعامل مع رفع الملف
        if 'video_file' in request.files:
            file = request.files['video_file']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # إضافة طابع زمني لضمان عدم تكرار الأسماء
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{timestamp}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                video_path = filename
            else:
                if not lesson:  # إذا كان درس جديد ولم يتم رفع ملف
                    flash('يجب رفع ملف فيديو بصيغة MP4')
                    return render_template('lesson_form.html', lesson=lesson, subjects=subjects)
                else:  # إذا كان تعديل ولم يتم رفع ملف جديد، نستخدم المسار القديم
                    video_path = lesson.video_path
        else:
            if not lesson:  # إذا كان درس جديد ولم يتم رفع ملف
                flash('يجب رفع ملف فيديو')
                return render_template('lesson_form.html', lesson=lesson, subjects=subjects)
            else:  # إذا كان تعديل ولم يتم رفع ملف جديد، نستخدم المسار القديم
                video_path = lesson.video_path

        if lesson:
            lesson.title = title
            lesson.subject_id = subject_id
            if 'video_file' in request.files and file and file.filename != '' and allowed_file(file.filename):
                # حذف الملف القديم إذا تم رفع ملف جديد
                if lesson.video_path and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], lesson.video_path)):
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], lesson.video_path))
                lesson.video_path = video_path
            flash('تم تعديل الدرس')
        else:
            db.session.add(Lesson(title=title, subject_id=subject_id, video_path=video_path))
            flash('تمت إضافة الدرس')
        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    return render_template('lesson_form.html', lesson=lesson, subjects=subjects)

@app.route('/admin/delete_lesson/<int:lesson_id>')
@admin_required
def delete_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    # حذف الملف المرفوع إذا كان موجودًا
    if lesson.video_path and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], lesson.video_path)):
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], lesson.video_path))
    db.session.delete(lesson)
    db.session.commit()
    flash('تم حذف الدرس')
    return redirect(url_for('admin_dashboard'))

# ===== إدارة الصلاحيات =====
# ... (الكود الحالي)

@app.route('/admin/permission', methods=['GET','POST'], endpoint="manage_permission")
@admin_required
def permission():
    students = User.query.filter_by(is_admin=False).all()
    subjects = Subject.query.all()

    if request.method == 'POST':
        user_id = request.form['user_id']
        subject_ids = request.form.getlist('subject_ids')  # الحصول على قائمة بالمواد المختارة

        # حذف جميع الصلاحيات الحالية للمستخدم
        Permission.query.filter_by(user_id=user_id).delete()

        # إضافة الصلاحيات الجديدة للمواد المختارة
        for subject_id in subject_ids:
            permission = Permission(user_id=user_id, subject_id=subject_id)
            db.session.add(permission)

        db.session.commit()
        flash('تم تحديث صلاحيات المستخدم بنجاح')
        return redirect(url_for('admin_dashboard'))

    return render_template('permission_form.html', students=students, subjects=subjects)


@app.route('/admin/delete_permission/<int:permission_id>')
@admin_required
def delete_permission(permission_id):
    permission = Permission.query.get_or_404(permission_id)
    db.session.delete(permission)
    db.session.commit()
    flash('تم حذف الصلاحية')
    return redirect(url_for('admin_dashboard'))

@app.route('/prices')
def prices():
    return render_template('prices.html')

# ===== إدارة المستخدمين =====
@app.route('/admin/user', methods=['GET','POST'])
@app.route('/admin/user/<int:user_id>', methods=['GET','POST'])
@admin_required
def manage_user(user_id=None):
    universities = University.query.all()
    if user_id:
        user = User.query.get_or_404(user_id)
    else:
        user = None

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        whatsapp_number = request.form['whatsapp_number']
        university_id = request.form['university_id']
        password = request.form.get('password')

        if user:
            user.name = name
            user.email = email
            user.whatsapp_number = whatsapp_number
            user.university_id = university_id
            if password:
                user.password = generate_password_hash(password)
            flash('تم تعديل المستخدم')
        else:
            if User.query.filter_by(email=email).first():
                flash('البريد الإلكتروني مسجل مسبقاً')
                return redirect(url_for('manage_user'))
            new_user = User(
                name=name,
                email=email,
                password=generate_password_hash(password),
                whatsapp_number=whatsapp_number,
                university_id=university_id
            )
            db.session.add(new_user)
            flash('تمت إضافة المستخدم')
        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    return render_template('user_form.html', user=user, universities=universities)

@app.route('/admin/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('لا يمكن حذف حساب مسؤول')
        return redirect(url_for('admin_dashboard'))

    # حذف الصلاحيات المرتبطة بالمستخدم
    Permission.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('تم حذف المستخدم')
    return redirect(url_for('admin_dashboard'))

@app.route('/settings')
@login_required
def settings():
    user = User.query.get(session['user_id'])
    # جلب المواد المصرح بها
    subject_ids = [p.subject_id for p in Permission.query.filter_by(user_id=user.id).all()]
    subjects = Subject.query.filter(Subject.id.in_(subject_ids)).all()
    return render_template('settings.html', user=user, subjects=subjects)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user = User.query.get(session['user_id'])
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if not check_password_hash(user.password, current_password):
        flash("❌ كلمة المرور الحالية غير صحيحة")
        return redirect(url_for('settings'))

    if new_password != confirm_password:
        flash("❌ كلمة المرور الجديدة لا تطابق التأكيد")
        return redirect(url_for('settings'))

    user.password = generate_password_hash(new_password)
    db.session.commit()
    flash("✅ تم تغيير كلمة المرور بنجاح")
    return redirect(url_for('settings'))

# ===== تشغيل الفلاسك =====
if __name__ == '__main__':
    app.run(debug=True, port=5022)

