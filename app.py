
# Full working app.py with unified login (local + Microsoft Entra ID), upload support, and dashboard
import os
import uuid
from io import BytesIO
from functools import wraps
from flask import Flask, redirect, url_for, session, request, render_template, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from azure.storage.blob import BlobServiceClient
import msal

app = Flask(__name__)
app.secret_key = 'Xavor123'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://adminx:Xavor%40123456@onedrivex101.mysql.database.azure.com/onedb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

AZURE_CONNECTION_STRING = 'BlobEndpoint=https://xnas.blob.core.windows.net/;SharedAccessSignature=sv=2024-11-04&ss=b&srt=sco&sp=rwdlaciytfx&se=2025-09-05T14:02:40Z&st=2025-05-20T06:02:40Z&spr=https,http&sig=0zmdGsn59M2LDVQ8MG7WwMXq/Q0/JjMaRNFQLtz80iY='
CONTAINER_NAME = 'gaming-files'
blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)

CLIENT_ID = '068db2f1-f67e-4e87-802d-846f63ba0528'
CLIENT_SECRET = 'PQC8Q~UUBgl8foX845p3SeT22Z.quXfM00wRxbGt'
AUTHORITY = 'https://login.microsoftonline.com/55ebfaff-4038-47d6-bda3-21d69a1f66b2'
REDIRECT_PATH = '/callback'
SCOPE = ['User.Read']

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(20), nullable=False)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return self.password_hash and check_password_hash(self.password_hash, password)
    @property
    def is_authenticated(self): return True
    @property
    def is_active(self): return True
    @property
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    folder_path = db.Column(db.String(1024), nullable=False)
    shared_by = db.Column(db.String(255), nullable=False)
    shared_with_user = db.Column(db.String(255))
    shared_with_project = db.Column(db.String(255))
    shared_with_everyone = db.Column(db.Boolean, default=False)
    access_level = db.Column(db.Enum('read', 'write'), default='read')

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)

class ProjectMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    username = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(min_role):
    roles = {'Reader': 1, 'Member': 2, 'Owner': 3}
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if roles.get(current_user.role, 0) < roles.get(min_role, 0):
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return wrapper

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))
@app.route('/admin')
@login_required
@role_required('Owner')
def admin():
    users = User.query.all()
    projects = Project.query.all()
    project_members = ProjectMember.query.all()
    return render_template('admin.html', users=users, projects=projects, members=project_members)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Local login logic
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/sso-login')
def sso_login():
    msal_app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET
    )
    auth_url = msal_app.get_authorization_request_url(
        scopes=SCOPE,
        redirect_uri=url_for('callback', _external=True)
    )
    return redirect(auth_url)

@app.route(REDIRECT_PATH)
def callback():
    msal_app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET
    )
    code = request.args.get('code')
    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=SCOPE,
        redirect_uri=url_for('callback', _external=True)
    )
    if "access_token" in result:
        email = result.get("id_token_claims", {}).get("preferred_username")
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, role='Reader')
            db.session.add(user)
            db.session.commit()
        login_user(user)
        return redirect(url_for('dashboard'))
    return "Microsoft SSO login failed", 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    prefix = request.args.get('folder', f'root/{current_user.email}/')
    user_email = current_user.email

    # User's project names
    project_ids = [pm.project_id for pm in ProjectMember.query.filter_by(username=user_email)]
    project_names = [p.name for p in Project.query.filter(Project.id.in_(project_ids)).all()]

    # All shares the user qualifies for
    shares = Share.query.filter(
        (Share.shared_with_user == user_email) |
        (Share.shared_with_project.in_(project_names)) |
        (Share.shared_with_everyone == True)
    ).all()
    allowed_prefixes = {s.folder_path for s in shares}
    owns_folder = prefix.startswith(f'root/{user_email}/')
    has_access = any(prefix.startswith(shared_path) for shared_path in allowed_prefixes)

    if not owns_folder and not has_access:
        abort(403)

    # Prepare blob listing
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    blobs = container_client.list_blobs(name_starts_with=prefix)
    folders, files = set(), []
    prefix_len = len(prefix)
    for blob in blobs:
        remainder = blob.name[prefix_len:]
        if not remainder:
            continue
        parts = remainder.split('/')
        if len(parts) == 1:
            files.append({'name': parts[0], 'full_path': blob.name})
        else:
            folders.add(parts[0])

    # Identify top-level shared roots (excluding owned ones)
    shared_roots = set()
    for share in shares:
        root_parts = share.folder_path.split('/')
        if len(root_parts) >= 3:
            shared_root = '/'.join(root_parts[:3]) + '/'
            if not shared_root.startswith(f'root/{user_email}/'):
                shared_roots.add(shared_root)

    return render_template('dashboard.html',
                           folders=sorted(folders),
                           files=sorted(files, key=lambda x: x['name']),
                           prefix=prefix,
                           user=current_user,
                           shared_roots=sorted(shared_roots))




@app.route('/edit_project_members/<int:project_id>', methods=['GET', 'POST'])
@login_required
@role_required('Owner')
def edit_project_members(project_id):
    project = Project.query.get_or_404(project_id)
    users = User.query.all()

    if request.method == 'POST':
        selected = request.form.getlist('users')

        # Remove existing members
        ProjectMember.query.filter_by(project_id=project_id).delete()

        # Add selected members
        for email in selected:
            db.session.add(ProjectMember(project_id=project_id, username=email))

        db.session.commit()
        flash("Project members updated", "success")
        return redirect(url_for('admin'))

    current_members = {m.username for m in ProjectMember.query.filter_by(project_id=project_id)}
    return render_template('edit_project_members.html', project=project, users=users, current_members=current_members)




@app.route('/share_folder', methods=['GET', 'POST'])
@login_required
@role_required('Owner')
def share_folder():
    folder = request.args.get('folder') or request.form.get('folder')

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        project_id = request.form.get('shared_with_project')
        project = Project.query.get(project_id)
        shared_with_project = project.name if project else None
        shared_with_everyone = request.form.get('shared_with_everyone') == '1'
        access_level = request.form.get('access_level', 'read')

        new_share = Share(
            folder_path=folder,
            shared_by=current_user.email,
            shared_with_user=user_id if user_id else None,
            shared_with_project=shared_with_project,
            shared_with_everyone=shared_with_everyone,
            access_level=access_level
        )
        db.session.add(new_share)
        db.session.commit()
        flash("Folder shared successfully!", "success")
        return redirect(url_for('dashboard', folder=folder))

    users = User.query.filter(User.email != current_user.email).all()
    projects = Project.query.all()
    return render_template('share_folder.html', users=users, projects=projects, folder=folder)






@app.route('/download')
@login_required
def download():
    file = request.args.get('file')
    if not file:
        abort(400, "File parameter is required.")
    blob = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=file)
    data = blob.download_blob().readall()
    return send_file(BytesIO(data), as_attachment=True, download_name=os.path.basename(file))
@app.route('/create_user', methods=['GET', 'POST'])
@login_required
@role_required('Owner')
def create_user():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        if User.query.filter_by(email=email).first():
            flash('User already exists', 'danger')
        else:
            user = User(email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('User created successfully', 'success')

        return redirect(url_for('admin'))

    return render_template('create_user.html')
@app.route('/create_project', methods=['GET', 'POST'])
@login_required
@role_required('Owner')
def create_project():
    if request.method == 'POST':
        name = request.form['name']
        user_emails = request.form['users'].split(',')

        # Check for duplicates
        if Project.query.filter_by(name=name).first():
            flash('Project already exists', 'danger')
            return redirect(url_for('create_project'))

        # Create the project
        project = Project(name=name, created_by=current_user.email)
        db.session.add(project)
        db.session.commit()

        # Add members to the project
        for email in [e.strip() for e in user_emails if e.strip()]:
            user = User.query.filter_by(email=email).first()
            if user:
                member = ProjectMember(project_id=project.id, username=email)
                db.session.add(member)
        db.session.commit()

        flash('Project created and users assigned successfully', 'success')
        return redirect(url_for('admin'))

    return render_template('create_project.html')
@app.route('/admin/assign_permission', methods=['POST'])
@login_required
@role_required('Owner')
def assign_permission():
    user = User.query.get(request.form['user_id'])
    new_role = request.form['role']

    if user:
        user.role = new_role
        db.session.commit()
        flash(f"Role updated to {new_role} for {user.email}", "success")
    else:
        flash("User not found", "danger")

    return redirect(url_for('admin'))
@app.route('/admin/reset_password', methods=['POST'])
@login_required
@role_required('Owner')
def reset_password():
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')

    user = User.query.get(user_id)
    if user:
        user.set_password(new_password)
        db.session.commit()
        flash(f"Password reset for {user.email}", "success")
    else:
        flash("User not found", "danger")

    return redirect(url_for('admin'))

@app.route('/preview')
@login_required
def preview():
    file = request.args.get('file')
    if not file:
        abort(400, "File parameter is required.")
    blob = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=file)
    stream = blob.download_blob()
    props = blob.get_blob_properties()
    return send_file(BytesIO(stream.readall()), mimetype=props.content_settings.content_type)

@app.route('/upload_files', methods=['POST'])
@login_required
@role_required('Member')
def upload_files():
    folder = request.form.get('folder', f'root/{current_user.email}/')
    files = request.files.getlist('files')
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    for file in files:
        blob_path = folder + file.filename.replace("\\", "/")
        container_client.upload_blob(name=blob_path, data=file, overwrite=True)
    return '', 204

@app.route('/upload_folder', methods=['POST'])
@login_required
@role_required('Member')
def upload_folder():
    folder = request.form.get('folder', f'root/{current_user.email}/')
    files = request.files.getlist('folder_files')
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    for file in files:
        blob_path = folder + file.filename.replace("\\", "/")
        container_client.upload_blob(name=blob_path, data=file, overwrite=True)
    return '', 204
# === Run App ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
