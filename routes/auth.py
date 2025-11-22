import random
import string
from flask import Blueprint, request, redirect, url_for, render_template, make_response, session, current_app
import requests
from flask_login import login_user, logout_user, login_required, current_user
from __init__ import db, bcrypt, login_manager, oauth
from models.user import User, Group
from utils.logger import log

auth_bp = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(user_id)

@auth_bp.route('/')
def index():
	if current_user.is_authenticated:
		return redirect(url_for('auth.dashboard'))
	return render_template('login.html', error=session.pop('error', None))

@auth_bp.route('/dashboard')
@login_required
def dashboard():
	return render_template('dashboard.html')

@auth_bp.route('/login', methods=['POST'])
def login():
	username = request.form['username']
	password = request.form['password']
	remember = request.form.get('remember', False)
	user = User.query.filter_by(username=username).first()
	
	if user and bcrypt.check_password_hash(user.password, password):
		login_user(user, remember=remember)

		response = make_response(redirect(url_for('auth.dashboard')))
  
		cookie_age = 60 * 60 * 24 * 365 if remember else None
		response.set_cookie('userid', user.id, max_age=cookie_age)
		response.set_cookie('username', user.username, max_age=cookie_age)
		response.set_cookie('token', user.auth_token, max_age=cookie_age)
		return response
	else:
		session['error'] = "Invalid username or password."
		return redirect(url_for('auth.index'))


@auth_bp.route('/oidc/login')
def oidc_login():
	"""Start OIDC flow with authentik."""
	# If a redirect URI is configured explicitly, use it; otherwise build one.
	redirect_uri = current_app.config.get('AUTHENTIK_REDIRECT_URI') or url_for('auth.oidc_callback', _external=True)
	# Make sure the client was registered at app startup
	if not hasattr(oauth, 'authentik'):
		log('OIDC login attempted but oauth.client "authentik" is not registered')
		session['error'] = 'OIDC client not configured. Check AUTHENTIK_ISSUER/CLIENT_ID/CLIENT_SECRET.'
		return redirect(url_for('auth.index'))

	try:
		return oauth.authentik.authorize_redirect(redirect_uri)
	except Exception as e:
		# Log the exception for debugging and give a helpful message to the UI
		log(f'Failed to start OIDC authorization redirect: {e}')
		session['error'] = 'Unable to start OIDC login. Check server configuration and that the issuer URL exposes /.well-known/openid-configuration.'
		return redirect(url_for('auth.index'))


@auth_bp.route('/oidc/callback')
def oidc_callback():
	"""Handle callback from authentik and map (or create) a local user."""
	try:
		token = oauth.authentik.authorize_access_token()
	except Exception as e:
		log(f'OIDC authorize_access_token error: {e}')
		session['error'] = 'OIDC authorization failed. See server logs for details.'
		return redirect(url_for('auth.index'))

	# Try to fetch userinfo
	# Try to fetch userinfo. Prefer an explicit configured URL if present.
	userinfo = None
	userinfo_url = current_app.config.get('AUTHENTIK_USERINFO_URL')
	try:
		if userinfo_url:
			resp = oauth.authentik.get(userinfo_url)
		else:
			# This may raise a requests.exceptions.MissingSchema if the client
			# wasn't configured with a metadata userinfo endpoint, so handle that.
			resp = oauth.authentik.get('userinfo')
		userinfo = resp.json()
	except requests.exceptions.MissingSchema as e:
		log(f'Userinfo request failed due to missing schema (probably no userinfo endpoint configured): {e}')
	except Exception as e:
		log(f'Failed to fetch userinfo: {e}')

	if not userinfo:
		# Fallback: try parsing id token
		try:
			userinfo = oauth.authentik.parse_id_token(token)
		except Exception as e2:
			log(f'Failed to parse id_token as fallback: {e2}')
			session['error'] = 'Failed to get user information from OIDC provider.'
			return redirect(url_for('auth.index'))

	username = userinfo.get('preferred_username') or userinfo.get('email') or userinfo.get('sub')
	if not username:
		session['error'] = 'OIDC provider did not return a usable username.'
		return redirect(url_for('auth.index'))

	# Extract groups from SSO and map them to local Group records (create Group if missing)
	def _extract_sso_groups(info):
		"""Return a list of group tokens (strings) from userinfo or id_token.
		Handles several common shapes: list of strings, comma-separated string,
		list of dicts with 'displayName'/'name'."""
		groups_val = None
		for key in ('groups', 'member_of', 'memberOf', 'memberof'):
			if key in info:
				groups_val = info.get(key)
				break
		if not groups_val:
			return []
		# If it's a string, maybe CSV
		if isinstance(groups_val, str):
			return [g.strip() for g in groups_val.split(',') if g.strip()]
		# If it's a list
		if isinstance(groups_val, list):
			out = []
			for item in groups_val:
				if isinstance(item, str):
					out.append(item)
				elif isinstance(item, dict):
					# common fields
					if 'displayName' in item:
						out.append(item.get('displayName'))
					elif 'name' in item:
						out.append(item.get('name'))
					elif 'display_name' in item:
						out.append(item.get('display_name'))
			return [g for g in out if g]
		# Unknown format
		return []

	# Map SSO groups to existing local Group IDs only (do NOT auto-create groups)
	sso_group_tokens = _extract_sso_groups(userinfo)
	mapped_group_ids = []
	for token in sso_group_tokens:
		if not token:
			continue
		# Try to find group by id first
		group = Group.query.filter_by(id=token).first()
		if not group:
			# Try display_name
			group = Group.query.filter_by(display_name=token).first()
		if group:
			mapped_group_ids.append(group.id)

	# If no mapped groups found, default to the local "User" group (if it exists)
	if not mapped_group_ids:
		default_group = Group.query.filter_by(display_name='User').first() or Group.query.filter_by(display_name='user').first()
		if default_group:
			mapped_group_ids = [default_group.id]

	# Normalize to comma-separated string for storage
	groups_csv = ','.join(mapped_group_ids) if mapped_group_ids else ''

	user = User.query.filter_by(username=username).first()
	if not user:
		# create a local user with a random password and groups from SSO
		random_pw = generate_auth_token()[:12]
		user = create_user(username, random_pw, groups=groups_csv)
	else:
		# Update user's groups on each login to reflect SSO
		user.groups = groups_csv
		db.session.commit()

	login_user(user)
	response = make_response(redirect(url_for('auth.dashboard')))
	# preserve same cookie semantics as password login
	response.set_cookie('userid', user.id)
	response.set_cookie('username', user.username)
	response.set_cookie('token', user.auth_token)
	return response

@auth_bp.route('/logout')
@login_required
def logout():
	logout_user()
 
	# Delete cookies
	response = make_response(redirect(url_for('auth.index')))
	response.set_cookie('userid', '', expires=0)
	response.set_cookie('username', '', expires=0)
	response.set_cookie('token', '', expires=0)
	return response

@auth_bp.route('/droplet_connect', methods=['GET'])
def droplet_connect():
	userid = request.cookies.get("userid")
	token = request.cookies.get("token")
 
	if not userid or not token:
		return make_response("", 401)

	user = User.query.filter_by(id=userid).first()
	if not user:
		return make_response("", 401)

	if user.auth_token != token:
		return make_response("", 401)
	
	return make_response("", 200)

def generate_auth_token() -> str:
	return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(80))

def create_user(username, password, groups):
	# Accept groups as list or comma-separated string
	if isinstance(groups, list):
		groups_val = ','.join(groups)
	else:
		groups_val = groups or ''

	user = User(username=username, password=bcrypt.generate_password_hash(password).decode('utf-8'), 
				groups=groups_val, auth_token=generate_auth_token())
	db.session.add(user)
	db.session.commit()
	return user 