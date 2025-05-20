from flask import Flask, redirect, url_for, session, request, render_template, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import msal
from functools import wraps
import os
from io import BytesIO
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)
app.secret_key = 'Xavor123'

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://adminx:Xavor@123456@onedrivex101.mysql.database.azure.com/onedb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Azure Blob Storage config (replace with your actual credentials)
AZURE_CONNECTION_STRING = 'BlobEndpoint=https://xnas.blob.core.windows.net/;QueueEndpoint=https://xnas.queue.core.windows.net/;FileEndpoint=https://xnas.file.core.windows.net/;TableEndpoint=https://xnas.table.core.windows.net/;SharedAccessSignature=sv=2024-11-04&ss=b&srt=sco&sp=rwdlaciytfx&se=2025-09-05T14:02:40Z&st=2025-05-20T06:02:40Z&spr=https,http&sig=0zmdGsn59M2LDVQ8MG7WwMXq%2FQ0%2FJjMaRNFQLtz80iY%3D'
blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
CONTAINER_NAME = 'userfiles'

# MSAL config (Azure Active Directory)
CLIENT_ID = '068db2f1-f67e-4e87-802d-846f63ba0528'
CLIENT_SECRET = 'PQC8Q~UUBgl8foX845p3SeT22Z.quXfM00wRxbGt'
AUTHORITY = 'https://login.microsoftonline.com/55ebfaff-4038-47d6-bda3-21d69a1f66b2'
REDIRECT_URI = 'https://onedrivex101.azurewebsites.net/callback'

SCOPE = ['User.Read']
SESSION_TYPE = 'filesystem'

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    role = db.Column(db.String(20))  # Owner, Member, Reader

    def is_authenticated(self):
        return True
    def is_active(self):
        return True
    def is_anonymous(self):
        return False
    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role required decorator
def role_required(min_role):
    roles = {'Reader': 1, 'Member': 2, 'Owner': 3}
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if roles.get(current_user.role, 0) < roles.get(min_role, 0):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/login')
def login():
    msal_app = msal.ConfidentialClientApplication(
        CLIENT_ID, authority=AUTHORITY,
        client_credential=CLIENT_SECRET)
    auth_url = msal_app.get_authorization_request_url(
        scopes=SCOPE,
        redirect_uri=url_for('callback', _external=True))
    return redirect(auth_url)

@app.route(REDIRECT_PATH)
def callback():
    msal_app = msal.ConfidentialClientApplication(
        CLIENT_ID, authority=AUTHORITY,
        client_credential=CLIENT_SECRET)
    code = request.args.get('code')
    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=SCOPE,
        redirect_uri=url_for('callback', _external=True))
    if "access_token" in result:
        user_email = result.get("id_token_claims", {}).get("preferred_username")
        user = User.query.filter_by(email=user_email).first()
        if not user:
            user = User(email=user_email, role='Reader')
            db.session.add(user)
            db.session.commit()
        login_user(user)
        return redirect(url_for('dashboard'))
    else:
        return "Login failure", 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    prefix = request.args.get('folder', 'root/')
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    blobs = container_client.list_blobs(name_starts_with=prefix)
    files = [blob.name for blob in blobs]
    return render_template('dashboard.html', files=files, prefix=prefix, user=current_user)

@app.route('/upload', methods=['POST'])
@login_required
@role_required('Member')
def upload():
    folder = request.form.get('folder', 'root/')
    uploaded_files = request.files.getlist("files")
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    for f in uploaded_files:
        blob_name = folder + f.filename
        container_client.upload_blob(name=blob_name, data=f, overwrite=True)
    flash("Upload successful!")
    return redirect(url_for('dashboard', folder=folder))

@app.route('/download')
@login_required
def download():
    file_name = request.args.get('file')
    if not file_name:
        abort(404)
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    try:
        stream = container_client.download_blob(file_name)
        file_data = stream.readall()
        return send_file(BytesIO(file_data), download_name=file_name.split('/')[-1], as_attachment=True)
    except Exception:
        abort(404)

@app.route('/preview')
@login_required
def preview():
    file_name = request.args.get('file')
    if not file_name:
        abort(404)
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    try:
        blob_client = container_client.get_blob_client(file_name)
        properties = blob_client.get_blob_properties()
        content_type = properties.content_settings.content_type
        stream = blob_client.download_blob()
        file_data = stream.readall()
        if 'image' in content_type or 'pdf' in content_type or 'text' in content_type:
            return send_file(BytesIO(file_data), mimetype=content_type)
        else:
            return "Preview not supported"
    except Exception:
        abort(404)

# Admin panel and folder sharing would follow similarly...

if __name__ == '__main__':
    app.run(debug=True)
