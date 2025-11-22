import os
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from authlib.integrations.flask_client import OAuth

__version__ = "develop"

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()
oauth = OAuth()
login_manager.login_view = '/'

def create_app(config=None):
	app = Flask(__name__)
	
	from config.config import configure_app
	configure_app(app, config)

	# Initialize OAuth
	oauth.init_app(app)

	# Register authentik OIDC client if configured
	issuer = app.config.get('AUTHENTIK_ISSUER')
	client_id = app.config.get('AUTHENTIK_CLIENT_ID')
	client_secret = app.config.get('AUTHENTIK_CLIENT_SECRET')
	if issuer and client_id and client_secret:
			# Prefer an explicitly configured metadata URL (helpful for providers like authentik
			# that expose discovery at a non-root path such as /application/o/<app>/.well-known/...)
			metadata_url = app.config.get('AUTHENTIK_METADATA_URL')
			if not metadata_url:
				# fallback to issuer-based discovery
				metadata_url = issuer.rstrip('/') + '/.well-known/openid-configuration'
			# Allow explicit endpoints to be provided as fallbacks (in case discovery is unavailable)
			authorize_url = app.config.get('AUTHENTIK_AUTHORIZATION_URL')
			token_url = app.config.get('AUTHENTIK_TOKEN_URL')
			userinfo_url = app.config.get('AUTHENTIK_USERINFO_URL')

			register_kwargs = dict(
				client_id=client_id,
				client_secret=client_secret,
				client_kwargs={
					'scope': 'openid email profile'
				}
			)

			# Use server_metadata_url when available
			register_kwargs['server_metadata_url'] = metadata_url

			# If explicit endpoints are provided, add them to the registration (these will be used if discovery isn't desirable)
			if authorize_url:
				register_kwargs['authorize_url'] = authorize_url
			if token_url:
				register_kwargs['access_token_url'] = token_url
			if userinfo_url:
				register_kwargs['userinfo_endpoint'] = userinfo_url

			oauth.register('authentik', **register_kwargs)
	
	app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
	db.init_app(app)
	migrate.init_app(app, db)
	bcrypt.init_app(app)
	login_manager.init_app(app)
	
	# Register blueprints
	from routes.auth import auth_bp
	from routes.admin import admin_bp
	from routes.droplet import droplet_bp
	
	app.register_blueprint(auth_bp)
	app.register_blueprint(admin_bp, url_prefix='/api/admin')
	app.register_blueprint(droplet_bp)
	
	@app.errorhandler(404)
	def page_not_found(e):
		from flask import render_template
		return render_template('404.html'), 404
	
	return app

def initialize_database_and_setup():
	db.create_all()
	from utils.setup import initialize_app
	from flask import current_app
	initialize_app(current_app) 