import platform
import sys
import os
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy.sql import func
from __init__ import db, bcrypt, __version__
from models.user import User, Group
from models.droplet import Droplet, DropletInstance
from models.registry import Registry
from models.network import DockerNetwork
from models.log import Log
from utils.permissions import Permissions
from utils.logger import log
import utils.docker

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/system_info', methods=['GET'])
@login_required
def api_admin_system():
	if not Permissions.check_permission(current_user.id, Permissions.ADMIN_PANEL):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	#Get Nginx version
	nginx_version = None
	try:
		#get docker container
		nginx_container = utils.docker.docker_client.containers.get("flowcase-nginx")
		result = nginx_container.exec_run("nginx -v")
		nginx_version = result.output.decode('utf-8').split("\n")[0].replace("nginx version: nginx/", "")
	except:
		nginx_version = "Unable to get version"

	response = {
		"success": True,
		"system": {
			"hostname": os.popen("hostname").read().strip(),
			"os": f"{platform.system()} {platform.release()}"
		},
		"version": {
			"flowcase": __version__,
			"python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
			"docker": utils.docker.get_docker_version(),
			"nginx": nginx_version,
		},
	}
 
	return jsonify(response)

@admin_bp.route('/users', methods=['GET'])
@login_required
def api_admin_users():
	if not Permissions.check_permission(current_user.id, Permissions.VIEW_USERS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403
	
	users = User.query.all()
 
	response = {
		"success": True,
		"users": []
	}
 
	for user in users:
		response["users"].append({
			"id": user.id,
			"username": user.username,
			"created_at": user.created_at,
			"groups": []
		})
		
		user_groups = user.groups.split(",")
		groups = Group.query.all()
		for group in groups:
			if group.id in user_groups:
				response["users"][-1]["groups"].append({
					"id": group.id,
					"display_name": group.display_name
				})
 
	return jsonify(response)

@admin_bp.route('/instances', methods=['GET'])
@login_required
def api_admin_instances():
	if not Permissions.check_permission(current_user.id, Permissions.VIEW_INSTANCES):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	if not utils.docker.is_docker_available():
		return jsonify({
			"success": False, 
			"error": "Docker service is not available, can't retrieve instances"
		}), 503

	instances = DropletInstance.query.all()
 
	response = {
		"success": True,
		"instances": []
	}
 
	for instance in instances:
		try:
			droplet = Droplet.query.filter_by(id=instance.droplet_id).first()
			user = User.query.filter_by(id=instance.user_id).first()
			container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
			response["instances"].append({
				"id": instance.id,
				"created_at": instance.created_at,
				"updated_at": instance.updated_at,
				"ip": container.attrs['NetworkSettings']['Networks']['flowcase_default_network']['IPAddress'],
				"droplet": {
					"id": droplet.id,
					"display_name": droplet.display_name,
					"description": droplet.description,
					"container_docker_image": droplet.container_docker_image,
					"container_docker_registry": droplet.container_docker_registry,
					"container_cores": droplet.container_cores,
					"container_memory": droplet.container_memory,
					"image_path": droplet.image_path
				},
				"user": {
					"id": user.id,
					"username": user.username
				}
			})
		except Exception as e:
			# Skip this instance if we can't get container info
			continue
 
	return jsonify(response)

@admin_bp.route('/droplets', methods=['GET'])
@login_required
def api_admin_droplets():
	if not Permissions.check_permission(current_user.id, Permissions.VIEW_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	droplets = Droplet.query.all()
	droplets = sorted(droplets, key=lambda x: x.display_name)
 
	response = {
		"success": True,
		"droplets": []
	}
 
	for droplet in droplets:
		response["droplets"].append({
			"id": droplet.id,
			"display_name": droplet.display_name,
			"description": droplet.description,
			"image_path": droplet.image_path,
			"droplet_type": droplet.droplet_type,
			"container_docker_image": droplet.container_docker_image,
			"container_docker_registry": droplet.container_docker_registry,
			"container_cores": droplet.container_cores,
			"container_memory": droplet.container_memory,
			"container_persistent_profile_path": droplet.container_persistent_profile_path,
			"server_ip": droplet.server_ip,
			"server_port": droplet.server_port,
			"server_username": droplet.server_username,
			"server_password": "********************************" if droplet.server_password else None,
			"allowed_groups": droplet.allowed_groups if droplet.allowed_groups else "",
			"network_id": droplet.network_id
		})
 
	return jsonify(response)

@admin_bp.route('/droplet', methods=['POST'])
@login_required
def api_admin_edit_droplet():
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	droplet_id = request.json.get('id')
	droplet = Droplet.query.filter_by(id=droplet_id).first()
 
	create_new = False
	if not droplet or droplet_id == "null":
		create_new = True
		droplet = Droplet()
  
	# Validate input
	droplet.description = request.json.get('description', None)
	if droplet.description == "":
		droplet.description = None
	droplet.image_path = request.json.get('image_path', None)
	if droplet.image_path == "":
		droplet.image_path = None

	droplet.display_name = request.json.get('display_name')
	if not droplet.display_name:
		return jsonify({"success": False, "error": "Display Name is required"}), 400

	droplet.droplet_type = request.json.get('droplet_type')
	if not droplet.droplet_type:
		return jsonify({"success": False, "error": "Droplet Type is required"}), 400
 
	if droplet.droplet_type == "container":
		droplet.container_docker_registry = request.json.get('container_docker_registry')
		# Registry is optional
		if not droplet.container_docker_registry:
			droplet.container_docker_registry = None

		droplet.container_docker_image = request.json.get('container_docker_image')
		if not droplet.container_docker_image:
			return jsonify({"success": False, "error": "Docker Image is required"}), 400
	
		droplet.registry_username = request.json.get('registry_username', None)
		if droplet.registry_username == "":
			droplet.registry_username = None

		new_registry_password = request.json.get('registry_password', None)
		if new_registry_password and new_registry_password != "********************************":
			droplet.registry_password = new_registry_password
	
		# Ensure cores and memory are integers
		if not request.json.get('container_cores'):
			return jsonify({"success": False, "error": "Cores is required"}), 400
		if not request.json.get('container_memory'):
			return jsonify({"success": False, "error": "Memory is required"}), 400

		try:
			droplet.container_cores = float(request.json.get('container_cores'))
		except:
			return jsonify({"success": False, "error": "Cores must be a number"}), 400
		try:
			droplet.container_memory = float(request.json.get('container_memory'))
		except:
			return jsonify({"success": False, "error": "Memory must be a number"}), 400

		# Check if cores or memory are negative
		if droplet.container_cores < 0:
			return jsonify({"success": False, "error": "Cores cannot be negative"}), 400
		if droplet.container_memory < 0:
			return jsonify({"success": False, "error": "Memory cannot be negative"}), 400

		droplet.container_persistent_profile_path = request.json.get('container_persistent_profile_path')
		if not droplet.container_persistent_profile_path:
			droplet.container_persistent_profile_path = None
   
		droplet.network_id = request.json.get('network_id')
		if not droplet.network_id:
			droplet.network_id = None
  
	elif droplet.droplet_type == "vnc" or droplet.droplet_type == "rdp" or droplet.droplet_type == "ssh":
		droplet.server_ip = request.json.get('server_ip')
		if not droplet.server_ip:
			return jsonify({"success": False, "error": "Server IP is required"}), 400

		droplet.server_port = request.json.get('server_port')
		if not droplet.server_port:
			return jsonify({"success": False, "error": "Server Port is required"}), 400
  
		droplet.server_username = request.json.get('server_username', None)
		if droplet.server_username == "":
			droplet.server_username = None
   
		new_server_password = request.json.get('server_password', None)
		if new_server_password != "********************************":
			droplet.server_password = new_server_password
  
		droplet.container_cores = 1
		droplet.container_memory = 1024
  
	# Handle allowed groups - convert array to comma-separated string
	allowed_groups = request.json.get('allowed_groups', [])
	if allowed_groups and isinstance(allowed_groups, list):
		droplet.allowed_groups = ','.join(allowed_groups) if allowed_groups else None
	else:
		droplet.allowed_groups = None
  
	if create_new:
		db.session.add(droplet)
 
	db.session.commit()
 
	return jsonify({
		"success": True,
		"droplet_id": droplet.id
	})

@admin_bp.route('/droplet', methods=['DELETE'])
@login_required
def api_admin_delete_droplet():
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403
	
	droplet_id = request.json.get('id')
	droplet = Droplet.query.filter_by(id=droplet_id).first()
	if not droplet:
		return jsonify({"success": False, "error": "Droplet not found"}), 404
 
	db.session.delete(droplet)
	db.session.commit()
 
	# Delete any instances of this droplet
	instances = DropletInstance.query.filter_by(droplet_id=droplet_id).all()
	
	if utils.docker.is_docker_available():
		for instance in instances:
			try:
				container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
				container.remove(force=True)
			except Exception as e:
				pass  # Container might not exist
			db.session.delete(instance)
			db.session.commit()
	else:
		# Even if Docker is not available, we should still delete the DB records
		for instance in instances:
			db.session.delete(instance)
		db.session.commit()
 
	return jsonify({"success": True})

@admin_bp.route('/instance', methods=['DELETE'])
@login_required
def api_admin_delete_instance():
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_INSTANCES):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	instance_id = request.json.get('id')
	instance = DropletInstance.query.filter_by(id=instance_id).first()
	if not instance:
		return jsonify({"success": False, "error": "Instance not found"}), 404
 
	if utils.docker.is_docker_available():
		try:
			container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
			container.remove(force=True)
		except Exception as e:
			pass  # Container might not exist
	
	db.session.delete(instance)
	db.session.commit()
 
	return jsonify({"success": True})

@admin_bp.route('/user', methods=['POST'])
@login_required
def api_admin_edit_user():
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_USERS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	user_id = request.json.get('id')
	user = User.query.filter_by(id=user_id).first()
 
	create_new = False
	if not user or user_id == "null":
		create_new = True
		user = User()
  
	# Validate input
	user.username = request.json.get('username')
	if not user.username:
		return jsonify({"success": False, "error": "Username is required"}), 400
	if " " in user.username:
		return jsonify({"success": False, "error": "Username cannot contain spaces"}), 400

	groups_string = ""
	for group in request.json.get('groups'):
		groups_string += f'{group},'
	user.groups = groups_string[:-1]
	if not user.groups or user.groups == "" or user.groups == "]":
		return jsonify({"success": False, "error": "Groups are required"}), 400

	# Passwords can only be set, not changed
	if create_new:
		if not request.json.get('password'):
			return jsonify({"success": False, "error": "Password is required"}), 400
		from routes.auth import generate_auth_token
		user.password = bcrypt.generate_password_hash(request.json.get('password')).decode('utf-8')
		user.auth_token = generate_auth_token()
 
	if create_new:
		db.session.add(user)
 
	db.session.commit()
 
	return jsonify({"success": True})

@admin_bp.route('/user', methods=['DELETE'])
@login_required
def api_admin_delete_user():
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_USERS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	user_id = request.json.get('id')
	user = User.query.filter_by(id=user_id).first()
	if not user:
		return jsonify({"success": False, "error": "User not found"}), 404
 
	db.session.delete(user)
	db.session.commit()
 
	# Delete any instances of this user
	instances = DropletInstance.query.filter_by(user_id=user_id).all()
	
	if utils.docker.is_docker_available():
		for instance in instances:
			try:
				container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
				container.remove(force=True)
			except Exception as e:
				pass  # Container might not exist
			db.session.delete(instance)
			db.session.commit()
	else:
		# Even if Docker is not available, we should still delete the DB records
		for instance in instances:
			db.session.delete(instance)
		db.session.commit()
 
	return jsonify({"success": True})

@admin_bp.route('/groups', methods=['GET'])
@login_required
def api_admin_groups():
	if not Permissions.check_permission(current_user.id, Permissions.VIEW_GROUPS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	groups = Group.query.all()
 
	response = {
		"success": True,
		"groups": []
	}
 
	for group in groups:
		# Find droplets assigned to this group
		assigned_droplets = []
		droplets = Droplet.query.all()
		for droplet in droplets:
			if droplet.allowed_groups:
				allowed_ids = [g.strip() for g in droplet.allowed_groups.split(',') if g.strip()]
				if group.id in allowed_ids:
					assigned_droplets.append({
						"id": droplet.id,
						"display_name": droplet.display_name
					})

		response["groups"].append({
			"id": group.id,
			"display_name": group.display_name,
			"protected": group.protected,
			"assigned_droplets": assigned_droplets,
			"permissions": {
				"admin_panel": group.perm_admin_panel,
				"view_instances": group.perm_view_instances,
				"edit_instances": group.perm_edit_instances,
				"view_users": group.perm_view_users,
				"edit_users": group.perm_edit_users,
				"view_droplets": group.perm_view_droplets,
				"edit_droplets": group.perm_edit_droplets,
				"view_registry": group.perm_view_registry,
				"edit_registry": group.perm_edit_registry,
				"view_groups": group.perm_view_groups,
				"edit_groups": group.perm_edit_groups
			}
		})
 
	return jsonify(response)

@admin_bp.route('/group', methods=['POST'])
@login_required
def api_admin_edit_group():
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_GROUPS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	group_id = request.json.get('id')
	group = Group.query.filter_by(id=group_id).first()
 
	create_new = False
	if not group or group_id == "null":
		create_new = True
		group = Group()
		group.protected = False
	
	# Validate input
	group.display_name = request.json.get('display_name')
	if not group.display_name:
		return jsonify({"success": False, "error": "Display Name is required"}), 400
 
	group.perm_admin_panel = request.json.get('perm_admin_panel')
	if not group.perm_admin_panel:
		group.perm_admin_panel = False
 
	group.perm_view_instances = request.json.get('perm_view_instances')
	if not group.perm_view_instances:
		group.perm_view_instances = False
 
	group.perm_edit_instances = request.json.get('perm_edit_instances')
	if not group.perm_edit_instances:
		group.perm_edit_instances = False
 
	group.perm_view_users = request.json.get('perm_view_users')
	if not group.perm_view_users:
		group.perm_view_users = False
 
	group.perm_edit_users = request.json.get('perm_edit_users')
	if not group.perm_edit_users:
		group.perm_edit_users = False
 
	group.perm_view_droplets = request.json.get('perm_view_droplets')
	if not group.perm_view_droplets:
		group.perm_view_droplets = False
 
	group.perm_edit_droplets = request.json.get('perm_edit_droplets')
	if not group.perm_edit_droplets:
		group.perm_edit_droplets = False
  
	group.perm_view_registry = request.json.get('perm_view_registry')
	if not group.perm_view_registry:
		group.perm_view_registry = False
  
	group.perm_edit_registry = request.json.get('perm_edit_registry')
	if not group.perm_edit_registry:
		group.perm_edit_registry = False
 
	group.perm_view_groups = request.json.get('perm_view_groups')
	if not group.perm_view_groups:
		group.perm_view_groups = False
 
	group.perm_edit_groups = request.json.get('perm_edit_groups')
	if not group.perm_edit_groups:
		group.perm_edit_groups = False
 
	if create_new:
		db.session.add(group)
		db.session.flush() # Ensure ID is generated

	assigned_droplet_ids = request.json.get('assigned_droplets')
	if assigned_droplet_ids is not None:
		all_droplets = Droplet.query.all()
		for droplet in all_droplets:
			current_allowed = []
			if droplet.allowed_groups:
				current_allowed = [g.strip() for g in droplet.allowed_groups.split(',') if g.strip()]
			
			if droplet.id in assigned_droplet_ids:
				# Should be assigned
				if group.id not in current_allowed:
					current_allowed.append(group.id)
					droplet.allowed_groups = ','.join(current_allowed)
			else:
				# Should NOT be assigned
				if group.id in current_allowed:
					current_allowed = [g for g in current_allowed if g != group.id]
					droplet.allowed_groups = ','.join(current_allowed) if current_allowed else None
 
	db.session.commit()
 
	return jsonify({"success": True})

@admin_bp.route('/group', methods=['DELETE'])
@login_required
def api_admin_delete_group():
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_GROUPS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	group_id = request.json.get('id')
	group = Group.query.filter_by(id=group_id).first()
	if not group:
		return jsonify({"success": False, "error": "Group not found."}), 404
 
	if group.protected:
		return jsonify({"success": False, "error": "This group is protected. Protected groups cannot be deleted."}), 400
 
	db.session.delete(group)
	db.session.commit()
 
	return jsonify({"success": True})

@admin_bp.route('/registry')
@login_required
def api_admin_registry():
	if not Permissions.check_permission(current_user.id, Permissions.VIEW_REGISTRY):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	registry = Registry.query.all()

	response = {
		"success": True,
		"flowcase_version": __version__,
		"registry": []
	}

	for r in registry:
		# Get info
		try:
			import requests
			info = requests.get(f"{r.url}/info.json").json()
			droplets = requests.get(f"{r.url}/droplets.json").json()
		except:
			info = {
				"name": "Failed to get info",
			}
			droplets = []
			from utils.logger import log
			log("ERROR", f"Failed to get registry info from {r.url}")

		response["registry"].append({
			"id": r.id,
			"url": r.url,
			"info": info,
			"droplets": droplets
		})

	return jsonify(response)

@admin_bp.route('/registry', methods=['POST', 'DELETE'])
@login_required
def api_admin_edit_registry():
	if request.method == 'POST':
		if not Permissions.check_permission(current_user.id, Permissions.EDIT_REGISTRY):
			return jsonify({"success": False, "error": "Unauthorized"}), 403

		url = request.json.get('url')
		if not url:
			return jsonify({"success": False, "error": "URL is required"}), 400

		# Check if registry already exists
		registry = Registry.query.filter_by(url=url).first()
		if registry:
			return jsonify({"success": False, "error": "Registry with this URL already exists"}), 400
	
		registry = Registry(url=url)
		db.session.add(registry)
		db.session.commit()
	
		return jsonify({"success": True})

	elif request.method == 'DELETE':
		if not Permissions.check_permission(current_user.id, Permissions.EDIT_REGISTRY):
			return jsonify({"success": False, "error": "Unauthorized"}), 403

		registry_id = request.json.get('id')
		registry = Registry.query.filter_by(id=registry_id).first()
		if not registry:
			return jsonify({"success": False, "error": "Registry not found"}), 404
	
		db.session.delete(registry)
		db.session.commit()
 
		return jsonify({"success": True})

@admin_bp.route('/logs', methods=['GET'])
@login_required
def api_admin_logs():
	if not current_user.has_permission(Permissions.ADMIN_PANEL):
		return jsonify({"success": False, "error": "You do not have permission to view logs"})
	
	page = request.args.get('page', 1, type=int)
	per_page = request.args.get('per_page', 50, type=int)
	log_type = request.args.get('type', None)
	
	query = Log.query
	
	if log_type and log_type.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
		query = query.filter(Log.level == log_type.upper())
	
	logs_pagination = query.order_by(Log.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
	logs = logs_pagination.items
	
	return jsonify({
		"success": True,
		"logs": [
			{
				"id": log.id,
				"created_at": log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
				"level": log.level,
				"message": log.message
			} for log in logs
		],
		"pagination": {
			"page": page,
			"per_page": per_page,
			"total": logs_pagination.total,
			"pages": logs_pagination.pages
		}
	}) 

@admin_bp.route('/images/status', methods=['GET'])
@login_required
def api_admin_images_status():
	"""Get the download status of all droplet images"""
	if not Permissions.check_permission(current_user.id, Permissions.VIEW_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	if not utils.docker.is_docker_available():
		return jsonify({
			"success": False, 
			"error": "Docker service is not available"
		}), 503

	status = utils.docker.get_images_status()
	
	return jsonify({
		"success": True,
		"images": status
	})

@admin_bp.route('/images/pull', methods=['POST'])
@login_required
def api_admin_pull_image():
	"""Pull a specific droplet image"""
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	if not utils.docker.is_docker_available():
		return jsonify({
			"success": False, 
			"error": "Docker service is not available"
		}), 503

	droplet_id = request.json.get('droplet_id')
	registry = request.json.get('registry')
	image = request.json.get('image')
	
	droplet = None
	if droplet_id and droplet_id != "guac":
		droplet = Droplet.query.filter_by(id=droplet_id).first()

	# Prepare auth config
	auth_config = None
	if droplet and droplet.registry_username and droplet.registry_password:
		auth_config = {
			'username': droplet.registry_username,
			'password': droplet.registry_password
		}

	# Handle auto-download case where registry and image are provided directly
	if image:
		success, message = utils.docker.pull_single_image(registry, image, auth_config=auth_config)
		if success:
			return jsonify({
				"success": True,
				"message": message
			})
		else:
			return jsonify({
				"success": False,
				"error": message
			}), 500
	
	# Handle droplet_id case (existing functionality)
	if not droplet_id:
		return jsonify({"success": False, "error": "Droplet ID is required"}), 400

	# Handle special guac droplet
	if droplet_id == "guac":
		from __init__ import __version__
		registry = "https://index.docker.io/v1/"
		image_name = f"flowcaseweb/flowcase-guac:{__version__}"
		# Guac doesn't need auth usually, or it's public
		auth_config = None 
	else:
		if not droplet:
			return jsonify({"success": False, "error": "Droplet not found"}), 404

		if not droplet.container_docker_image:
			return jsonify({"success": False, "error": "Droplet has no Docker image configured"}), 400

		registry = droplet.container_docker_registry
		image_name = droplet.container_docker_image

	# Pull the image
	success, message = utils.docker.pull_single_image(registry, image_name, auth_config=auth_config)
	
	if success:
		return jsonify({
			"success": True,
			"message": message
		})
	else:
		return jsonify({
			"success": False,
			"error": message
		}), 500

@admin_bp.route('/images/pull-all', methods=['POST'])
@login_required
def api_admin_pull_all_images():
	"""Pull all droplet images"""
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	if not utils.docker.is_docker_available():
		return jsonify({
			"success": False, 
			"error": "Docker service is not available"
		}), 503

	try:
		# Use existing pull_images function
		utils.docker.pull_images()
		
		return jsonify({
			"success": True,
			"message": "Started downloading all images. Check logs for progress."
		})
	except Exception as e:
		return jsonify({
			"success": False,
			"error": f"Failed to start image downloads: {str(e)}"
		}), 500 

@admin_bp.route('/images/logs', methods=['GET'])
@login_required
def api_admin_image_logs():
	"""Get recent image download logs and errors"""
	if not Permissions.check_permission(current_user.id, Permissions.VIEW_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	try:
		# Get recent logs related to Docker image operations
		recent_logs = Log.query.filter(
			Log.message.like('%Docker image%')
		).order_by(Log.created_at.desc()).limit(50).all()
		
		logs = []
		for log in recent_logs:
			logs.append({
				"id": log.id,
				"created_at": log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
				"level": log.level,
				"message": log.message
			})
		
		return jsonify({
			"success": True,
			"logs": logs
		})
		
	except Exception as e:
		return jsonify({
			"success": False,
			"error": f"Failed to fetch image logs: {str(e)}"
		}), 500 
@admin_bp.route('/networks', methods=['GET'])
@login_required
def api_admin_networks():
	"""Get all docker networks"""
	if not Permissions.check_permission(current_user.id, Permissions.VIEW_DROPLETS): # Or a new permission? Using view_droplets for now
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	if not utils.docker.is_docker_available():
		return jsonify({
			"success": False, 
			"error": "Docker service is not available"
		}), 503

	# Get existing DB networks
	networks = DockerNetwork.query.all()
	network_list = []
	
	for net in networks:
		network_list.append({
			"id": net.id,
			"name": net.name,
			"subnet": net.subnet,
			"gateway": net.gateway,
			"driver": net.driver,
			"active": True # Assume active if in DB for now, or do a lightweight check? 
			# Doing a lightweight check might still require fetching all networks from docker.
			# Let's skip docker check for speed on this frequent endpoint.
		})

	return jsonify({
		"success": True,
		"networks": network_list
	})

@admin_bp.route('/networks/sync', methods=['POST'])
@login_required
def api_admin_networks_sync():
	"""Sync system docker networks to DB"""
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	if not utils.docker.is_docker_available():
		return jsonify({
			"success": False, 
			"error": "Docker service is not available"
		}), 503

	# Get real docker networks
	try:
		real_networks = {n['name']: n for n in utils.docker.get_networks()}
		
		# Get existing DB networks
		db_networks = {n.name: n for n in DockerNetwork.query.all()}
		
		added_count = 0
		# Sync: Add real networks to DB if missing
		for net_name, net_data in real_networks.items():
			if net_name not in db_networks:
				# Auto-create network in DB
				new_net = DockerNetwork(
					name=net_name,
					driver=net_data['driver'],
					subnet=net_data['subnet'],
					gateway=net_data['gateway']
				)
				db.session.add(new_net)
				added_count += 1
				
		# Commit any new networks
		if added_count > 0:
			db.session.commit()
			
		return jsonify({
			"success": True,
			"message": f"Synced {added_count} new networks",
			"added_count": added_count
		})
	except Exception as e:
		log("ERROR", f"Failed to sync networks: {e}")
		db.session.rollback()
		return jsonify({"success": False, "error": str(e)}), 500

@admin_bp.route('/network', methods=['POST'])
@login_required
def api_admin_edit_network():
	"""Create or edit a docker network"""
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	if not utils.docker.is_docker_available():
		return jsonify({
			"success": False, 
			"error": "Docker service is not available"
		}), 503

	network_id = request.json.get('id')
	name = request.json.get('name')
	subnet = request.json.get('subnet')
	gateway = request.json.get('gateway')
	driver = request.json.get('driver', 'bridge')
	
	if not name:
		return jsonify({"success": False, "error": "Network name is required"}), 400

	network = None
	if network_id:
		network = DockerNetwork.query.filter_by(id=network_id).first()
	
	if not network:
		# Check if name exists
		if DockerNetwork.query.filter_by(name=name).first():
			return jsonify({"success": False, "error": "Network with this name already exists"}), 400
		network = DockerNetwork()
		db.session.add(network)
	
	network.name = name
	network.subnet = subnet
	network.gateway = gateway
	network.driver = driver
	
	db.session.commit()
	
	# Now actually create it in Docker
	# First check if it exists
	real_networks = {n['name']: n for n in utils.docker.get_networks()}
	if name not in real_networks:
		success, msg = utils.docker.create_network(name, driver, subnet, gateway)
		if not success:
			return jsonify({"success": False, "error": f"Failed to create docker network: {msg}"}), 500
	
	return jsonify({"success": True, "id": network.id})

@admin_bp.route('/network', methods=['DELETE'])
@login_required
def api_admin_delete_network():
	"""Delete a docker network"""
	if not Permissions.check_permission(current_user.id, Permissions.EDIT_DROPLETS):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	network_id = request.json.get('id')
	network = DockerNetwork.query.filter_by(id=network_id).first()
	
	if not network:
		return jsonify({"success": False, "error": "Network not found"}), 404

	# Check if any droplet uses this network
	if Droplet.query.filter_by(network_id=network.id).first():
		return jsonify({"success": False, "error": "Cannot delete network: It is being used by one or more droplets"}), 400

	# Delete from Docker
	utils.docker.delete_network(network.name)
	
	# Delete from DB
	db.session.delete(network)
	db.session.commit()
	
	return jsonify({"success": True})
