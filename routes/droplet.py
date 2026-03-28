import os
import re
import time
import base64
import json
import traceback
from typing import Tuple
import docker
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Blueprint, jsonify, request, render_template, redirect, make_response, send_from_directory
from flask_login import login_required, current_user
import psutil
from __init__ import db, __version__
from models.droplet import Droplet, DropletInstance
from models.user import User
from utils.logger import log
import utils.docker
import threading
from pathlib import Path
from datetime import datetime, timedelta


def timeout_wrapper(func, timeout_seconds=300):
	"""Execute a function with a timeout, returning (success, result/error)"""
	result = [None]
	error = [None]
	completed_event = threading.Event()

	def target():
		try:
			result[0] = func()
		except Exception as e:
			error[0] = str(e)
		finally:
			completed_event.set()

	thread = threading.Thread(target=target)
	thread.daemon = True
	thread.start()

	# Wait for completion or timeout using Event
	if completed_event.wait(timeout=timeout_seconds):
		if error[0]:
			return False, error[0]
		return True, result[0]
	else:
		return False, "Operation timed out"

droplet_bp = Blueprint('droplet', __name__)


def cleanup_stale_instances():
    """Remove droplet instances that have been inactive longer than the configured timeout.

    The default timeout is 30 minutes but can be overridden via the
    ``SESSION_TIMEOUT_MINUTES`` Flask config value.
    """
    try:
        from flask import current_app
        from models.setting import Setting

        # Default to database setting, fallback to app config, then 30
        timeout_minutes = int(Setting.get('SESSION_TIMEOUT_MINUTES', current_app.config.get('SESSION_TIMEOUT_MINUTES', 30)))
        threshold = datetime.utcnow() - timedelta(minutes=timeout_minutes)
        stale_instances = DropletInstance.query.filter(DropletInstance.updated_at < threshold).all()
        
        # Record that the worker successfully executed
        try:
            Setting.set('last_cleanup_run_utc', datetime.utcnow().isoformat())
        except Exception:
            pass
        
        if stale_instances:
            log("INFO", f"Cleanup: found {len(stale_instances)} stale instance(s) with threshold={threshold}")
        
        for instance in stale_instances:
            log("INFO", f"Cleanup: removing stale instance {instance.id} (updated_at={instance.updated_at})")
            # attempt to delete associated Docker container
            try:
                if utils.docker.docker_client:
                    container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
                    container.remove(force=True)
                    log("INFO", f"Cleanup: removed Docker container for instance {instance.id}")
            except Exception as e:
                log("WARNING", f"Cleanup: failed to remove Docker container for {instance.id}: {str(e)}")

            # remove nginx configuration if it exists
            config_path = f"/flowcase/nginx/containers.d/{instance.id}.conf"
            try:
                if os.path.exists(config_path):
                    os.remove(config_path)
                    log("INFO", f"Cleanup: removed nginx config for instance {instance.id}")
            except Exception as e:
                log("WARNING", f"Cleanup: failed to remove nginx config for {instance.id}: {str(e)}")

            db.session.delete(instance)
        db.session.commit()
        
        if stale_instances:
            log("INFO", f"Cleanup: completed, removed {len(stale_instances)} instance(s)")
    except Exception as e:
        log("ERROR", f"Error during stale instance cleanup: {str(e)}")


def start_stale_instance_cleaner_thread(app, interval_minutes: int = 1):
    """Start a background thread that runs `cleanup_stale_instances` periodically.

    The thread is skipped when the Flask app is running in TESTING mode.
    """
    if app.config.get("TESTING"):
        log("INFO", "Skipping stale instance cleanup thread in testing mode")
        return

    def worker():
        try:
            with app.app_context():
                from models.setting import Setting
                log("INFO", f"Stale instance cleanup thread started (interval: {interval_minutes} minute(s))")
                timeout_mins = int(Setting.get('SESSION_TIMEOUT_MINUTES', app.config.get('SESSION_TIMEOUT_MINUTES', 30)))
                log("INFO", f"Session timeout configured: {timeout_mins} minutes")
                while True:
                    cleanup_stale_instances()
                    time.sleep(interval_minutes * 60)
        except Exception as e:
            log("ERROR", f"Stale instance cleanup thread crashed: {str(e)}")

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

@droplet_bp.route('/api/droplets', methods=['GET'])
@login_required
def get_droplets():
	from utils.permissions import Permissions
	droplets = Droplet.query.all()
	droplets = sorted(droplets, key=lambda x: x.display_name)

	response = {
		"success": True,
		"droplets": []
	}

	for droplet in droplets:
		# Check if user has access to this droplet based on group membership
		if not Permissions.user_in_groups(current_user.id, droplet.allowed_groups):
			continue

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
			"server_ip": droplet.server_ip,
			"server_port": droplet.server_port,
		})

	return jsonify(response)

@droplet_bp.route('/api/instances', methods=['GET'])
@login_required
def get_instances():
	# purge any expired sessions before returning results
	cleanup_stale_instances()
	instances = DropletInstance.query.filter_by(user_id=current_user.id).all()

	response = {
		"success": True,
		"instances": []
	}

	for instance in instances:
		droplet = Droplet.query.filter_by(id=instance.droplet_id).first()
		response["instances"].append({
			"id": instance.id,
			"created_at": instance.created_at,
			"updated_at": instance.updated_at,
			"droplet": {
				"id": droplet.id,
				"display_name": droplet.display_name,
				"description": droplet.description,
				"image_path": droplet.image_path,
				"droplet_type": droplet.droplet_type,
				"container_docker_image": droplet.container_docker_image,
				"container_docker_registry": droplet.container_docker_registry,
				"container_cores": droplet.container_cores,
				"container_memory": droplet.container_memory,
				"server_ip": droplet.server_ip,
				"server_port": droplet.server_port,
			}
		})

	return jsonify(response)

@droplet_bp.route('/api/instance/request', methods=['POST'])
@login_required
def request_new_instance():
	try:
		# perform cleanup so inactive sessions don't count against resources
		cleanup_stale_instances()
		from utils.permissions import Permissions
		droplet_id = request.json.get('droplet_id')
		droplet = Droplet.query.filter_by(id=droplet_id).first()
		if not droplet:
			return jsonify({"success": False, "error": "Droplet not found"}), 404

		# Check if user has access to this droplet based on group membership
		if not Permissions.user_in_groups(current_user.id, droplet.allowed_groups):
			return jsonify({"success": False, "error": "You do not have access to this droplet"}), 403

		# Check if droplet is a guacamole droplet
		isGuacDroplet: bool = False
		# Handle potential None for droplet_type if data integrity is bad, though model enforces nullable=False
		if droplet.droplet_type in ["vnc", "rdp", "ssh"]:
			isGuacDroplet = True

		# Check if system has enough resources to request this droplet, guacamole droplets do not have resource checks
		if not isGuacDroplet:
			success, error = check_resources(droplet)
			if not success:
				return jsonify({"success": False, "error": error}), 400

		# Check if docker client is available
		if not utils.docker.docker_client:
			log("ERROR", "Docker client not available")
			return jsonify({"success": False, "error": "Docker service is not available"}), 500

		# Check if docker image is downloaded
		try:
			images = utils.docker.docker_client.images.list()
		except Exception as e:
			log("ERROR", f"Failed to list docker images: {str(e)}")
			return jsonify({"success": False, "error": f"Failed to communicate with Docker: {str(e)}"}), 500

		image_name = droplet.container_docker_image
		if droplet.container_docker_registry and "docker.io" not in droplet.container_docker_registry:
			image_name = droplet.container_docker_registry + "/" + image_name

		image_exists = False
		for image in images:
			if isGuacDroplet and f"flowcaseweb/flowcase-guac:{__version__}" in image.tags:
				image_exists = True
				break

			if image.tags and image_name in image.tags:
				image_exists = True
				break

		if not image_exists:
			log("WARNING", f"Docker image {droplet.container_docker_image} not found. Please wait a few minutes and try again.")
			return jsonify({"success": False, "error": "Docker image not found. Image might still be downloading."}), 400

			"""
			try:
				# Use the existing pull_single_image function with timeout
				def pull_with_timeout():
					return utils.docker.pull_single_image(
						droplet.container_docker_registry,
						droplet.container_docker_image
					)

				success, message = timeout_wrapper(pull_with_timeout, timeout_seconds=300)

				if not success:
					if "timed out" in message:
						return jsonify({"success": False, "error": "Image download timed out. Please try again or download manually from the admin panel."}), 408
					else:
						log("ERROR", f"Failed to pull Docker image {image_name}: {message}")
						return jsonify({"success": False, "error": f"Failed to download Docker image. Error: {message}"}), 400

				log("INFO", f"Successfully pulled Docker image {image_name}")
			except Exception as e:
				log("ERROR", f"Failed to pull Docker image {image_name}: {str(e)}")
				return jsonify({"success": False, "error": f"Failed to download Docker image. Error: {str(e)}"}), 400
			"""

		# Create a new instance
		instance = DropletInstance(droplet_id=droplet_id, user_id=current_user.id)
		db.session.add(instance)
		db.session.commit()

		# Create a docker container
		log("INFO", f"Creating new instance for user {current_user.username} with droplet {droplet.display_name}")

		name = f"flowcase_generated_{instance.id}"

		request_resolution = request.json.get('resolution')
		if request_resolution and len(request_resolution) < 10 and re.match(r"[0-9]+x[0-9]+", request_resolution):
			resolution = request_resolution
		else:
			resolution = "1280x720"

		# Persistent Profile
		mount = None
		if (
			droplet.container_persistent_profile_path
			and droplet.container_persistent_profile_path != ""
			and not isGuacDroplet
		):
			profilePath = droplet.container_persistent_profile_path

			# Replace variables
			profilePath = profilePath.replace("{user_id}", str(current_user.id))
			profilePath = profilePath.replace("{username}", current_user.username)
			profilePath = profilePath.replace("{droplet_id}", str(droplet_id))

			profilePath = Path(profilePath).expanduser()

			profilePath.mkdir(parents=True, exist_ok=True)

			# Match Kasm container UID
			KASM_UID = 1000
			KASM_GID = 1000

			os.chown(profilePath, KASM_UID, KASM_GID)

			profilePath = profilePath.resolve()

			# Create the directory with proper error handling
			try:
				# Ensure parent directory exists first
				parent_dir = profilePath.parent
				if not parent_dir.exists():
					log("INFO", f"Creating parent directory: {parent_dir}")
					parent_dir.mkdir(parents=True, exist_ok=True)

				# Create the actual profile directory
				log("INFO", f"Creating profile directory: {profilePath}")
				profilePath.mkdir(parents=True, exist_ok=True)

				# Verify the directory was created successfully
				if not profilePath.exists():
					raise RuntimeError(f"Failed to create profile directory: {profilePath}")
				
				if not profilePath.is_dir():
					raise RuntimeError(f"Profile path exists but is not a directory: {profilePath}")
				
				# Check if directory is writable
				if not os.access(str(profilePath), os.W_OK):
					raise RuntimeError(f"Profile directory exists but is not writable: {profilePath}")
				
				log("INFO", f"Successfully created and verified profile directory: {profilePath}")

			except PermissionError as e:
				error_msg = f"Permission denied creating profile directory {profilePath}: {str(e)}"
				log("ERROR", error_msg)
				db.session.delete(instance)
				db.session.commit()
				return jsonify({"success": False, "error": error_msg}), 500
			except Exception as e:
				error_msg = f"Error creating profile directory {profilePath}: {str(e)}"
				log("ERROR", error_msg)
				db.session.delete(instance)
				db.session.commit()
				return jsonify({"success": False, "error": error_msg}), 500

			mount = docker.types.Mount(
				target="/home/flowcase-user",
				source=str(profilePath),
				type="bind",
				consistency="private"
			)

			# Warm-up hack: first bind initializes profile
			bashrc_path = profilePath / ".bashrc"
			if not bashrc_path.exists():
				try:
					log("INFO", f"Running profile warm-up container for {profilePath}")
					container = utils.docker.docker_client.containers.run(
						image=image_name,
						detach=True,
						mem_limit="512000000",
						cpu_shares=int(droplet.container_cores * 1024),
						mounts=[mount],
					)
					time.sleep(1)
					container.stop()
					container.remove(force=True)
					log("INFO", f"Profile warm-up completed for {profilePath}")
				except Exception as e:
					log("WARNING", f"Profile warm-up container failed: {e}")

		# Create the container
		try:
			network_name = "flowcase_default_network"
			if droplet.network_id:
				from models.network import DockerNetwork
				network = DockerNetwork.query.filter_by(id=droplet.network_id).first()
				if network:
					network_name = network.name

			if not isGuacDroplet:
				container = utils.docker.docker_client.containers.run(
					image=image_name,
					name=name,
					environment={"DISPLAY": ":1", "VNC_PW": current_user.auth_token, "VNC_RESOLUTION": resolution},
					detach=True,
					network=network_name,
					mem_limit=f"{droplet.container_memory}000000",
					cpu_shares=int(droplet.container_cores * 1024),
					mounts=[mount] if mount else None,
				)

				# If we are using a custom network, we MUST also connect to the default network
				# so that the Nginx proxy (which is on the default network) can reach this container.
				if network_name != "flowcase_default_network":
					try:
						default_net = utils.docker.docker_client.networks.list(names=["flowcase_default_network"])
						if default_net:
							default_net[0].connect(container)
							log("INFO", f"Connected {name} to flowcase_default_network for Nginx access")
						else:
							log("WARNING", "flowcase_default_network not found! Nginx might not reach container.")
					except Exception as e:
						log("ERROR", f"Failed to connect {name} to flowcase_default_network: {e}")
			else: # Guacamole droplet
				container = utils.docker.docker_client.containers.run(
					image=f"flowcaseweb/flowcase-guac:{__version__}",
					name=name,
					environment={"GUAC_KEY": current_user.auth_token[:32]},
					detach=True,
					network="flowcase_default_network",
				)

			log("INFO", f"Instance created for user {current_user.username} with droplet {droplet.display_name}")

			# Wait for container to start and verify it's running with timeout
			max_wait_time = 30  # Maximum wait time in seconds
			check_interval = 1  # Check every 1 second
			waited_time = 0

			while waited_time < max_wait_time:
				time.sleep(check_interval)
				waited_time += check_interval

				try:
					container.reload()
					if container.status == 'running':
						log("INFO", f"Container {name} is running after {waited_time} seconds")
						break
					elif container.status in ['exited', 'dead']:
						log("ERROR", f"Container {name} failed to start, status: {container.status}")
						# Get container logs for debugging
						try:
							logs = container.logs().decode('utf-8')[-1000:]  # Last 1000 chars
							log("ERROR", f"Container logs: {logs}")
						except:
							pass
						container.remove(force=True)
						db.session.delete(instance)
						db.session.commit()
						return jsonify({"success": False, "error": f"Container failed to start (status: {container.status})"}), 500
				except Exception as e:
					log("ERROR", f"Error checking container status: {str(e)}")
					container.remove(force=True)
					db.session.delete(instance)
					db.session.commit()
					return jsonify({"success": False, "error": "Failed to verify container status"}), 500

			# Final check if we timed out
			if waited_time >= max_wait_time:
				log("ERROR", f"Container {name} startup timed out after {max_wait_time} seconds")
				try:
					logs = container.logs().decode('utf-8')[-1000:]  # Last 1000 chars
					log("ERROR", f"Container logs: {logs}")
				except:
					pass
				container.remove(force=True)
				db.session.delete(instance)
				db.session.commit()
				return jsonify({"success": False, "error": "Container startup timed out"}), 500

			# Create nginx config - get fresh container info
			try:
				container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
				networks = container.attrs['NetworkSettings']['Networks']

				# Get IP from flowcase_default_network
				ip = None
				# Get IP from network
				ip = None
				if 'flowcase_default_network' in networks:
					ip = networks['flowcase_default_network'].get('IPAddress')
				elif network_name in networks:
					ip = networks[network_name].get('IPAddress')

				# Fallback to the first network found if specific ones aren't there (shouldn't happen)
				if not ip and networks:
					first_net = list(networks.values())[0]
					ip = first_net.get('IPAddress')

				if not ip:
					log("ERROR", f"Could not find IP address for container {name} on flowcase_default_network")
					container.remove(force=True)
					db.session.delete(instance)
					db.session.commit()
					return jsonify({"success": False, "error": "Could not determine container IP address"}), 500

			except Exception as e:
				log("ERROR", f"Error getting container network info: {str(e)}")
				container.remove(force=True)
				db.session.delete(instance)
				db.session.commit()
				return jsonify({"success": False, "error": "Failed to get container network information"}), 500

			# Generate nginx configuration
			nginx_config = generate_nginx_config(instance, droplet, ip, current_user)

			try:
				write_nginx_config(instance, nginx_config)
			except Exception as e:
				log("ERROR", f"Error writing nginx config: {str(e)}")
				container.remove(force=True)
				db.session.delete(instance)
				db.session.commit()
				return jsonify({"success": False, "error": "Failed to write nginx configuration"}), 500

			reload_nginx()

		except Exception as e:
			log("ERROR", f"Error creating container for user {current_user.username}: {str(e)}")
			# Cleanup on failure
			try:
				if 'container' in locals():
					container.remove(force=True)
			except:
				pass
			db.session.delete(instance)
			db.session.commit()
			return jsonify({"success": False, "error": f"Failed to create container: {str(e)}"}), 500

		return jsonify({"success": True, "instance_id": instance.id})
	except Exception as e:
		log("ERROR", f"Unhandled exception in request_new_instance: {str(e)}")
		log("ERROR", traceback.format_exc())
		return jsonify({"success": False, "error": str(e), "traceback": traceback.format_exc()}), 500

def check_resources(droplet: Droplet) -> Tuple[bool, str]:
	instances = DropletInstance.query.all()

	# Collect all droplet IDs and fetch droplets in a single query to avoid N+1 problem
	droplet_ids = [instance.droplet_id for instance in instances]
	droplets = Droplet.query.filter(Droplet.id.in_(droplet_ids)).all() if droplet_ids else []
	droplet_dict = {droplet.id: droplet for droplet in droplets}

	total_allocated_memory = 0
	total_allocated_cores = 0
	for instance in instances:
		instance_droplet = droplet_dict.get(instance.droplet_id)
		if instance_droplet:
			total_allocated_cores += instance_droplet.container_cores
			total_allocated_memory += instance_droplet.container_memory

	# Get system resources
	system_cores = os.cpu_count()
	total_memory = psutil.virtual_memory().total / 1024 / 1024  # Convert to MB

	# Calculate what would be used after adding this droplet
	projected_memory_usage = total_allocated_memory + droplet.container_memory
	projected_core_usage = total_allocated_cores + droplet.container_cores

	# Apply reasonable safety margins and allow oversubscription for CPU
	# CPU: Allow 2x oversubscription (containers share CPU efficiently via CPU shares)
	# Memory: Use 85% of total memory to leave room for system operations
	max_allowed_memory = total_memory * 0.85
	max_allowed_cores = system_cores * 2.0

	if projected_memory_usage > max_allowed_memory:
		log("ERROR", f"Insufficient memory for user {current_user.username} to request droplet {droplet.display_name} - would use {projected_memory_usage}MB of {max_allowed_memory}MB allowed")
		return False, "Insufficient memory to start this droplet"

	if projected_core_usage > max_allowed_cores:
		log("ERROR", f"Insufficient CPU cores for user {current_user.username} to request droplet {droplet.display_name} - would use {projected_core_usage} of {max_allowed_cores} cores allowed")
		return False, "Insufficient CPU cores to start this droplet"

	return True, ""

def generate_nginx_config(instance: DropletInstance, droplet: Droplet, ip: str, user: User) -> str:
	"""Generate nginx configuration for the instance."""
	try:
		authHeader = base64.b64encode(b'flowcase_user:' + user.auth_token.encode()).decode('utf-8')

		if droplet.droplet_type == "container":
			template_path = f"config/nginx/container_template.conf"
		else: # Guacamole droplet
			template_path = f"config/nginx/guac_template.conf"

		log("INFO", f"Reading nginx template from {template_path}")
		with open(template_path, "r") as f:
			nginx_config = f.read()

		nginx_config = nginx_config.replace("{ip}", ip)
		nginx_config = nginx_config.replace("{authHeader}", authHeader)
		nginx_config = nginx_config.replace("{instance_id}", instance.id)

		log("INFO", f"Generated nginx config for instance {instance.id}: IP={ip}, type={droplet.droplet_type}")
		return nginx_config
	except FileNotFoundError as e:
		log("ERROR", f"Nginx template file not found: {str(e)}")
		raise
	except Exception as e:
		log("ERROR", f"Error generating nginx config: {str(e)}")
		raise

def write_nginx_config(instance: DropletInstance, nginx_config: str):
	"""Write nginx configuration for the instance."""
	nginx_dir = "/flowcase/nginx/containers.d"
	config_file = f"{nginx_dir}/{instance.id}.conf"

	try:
		# Ensure directory exists
		os.makedirs(nginx_dir, exist_ok=True)
		log("INFO", f"Writing nginx config to {config_file}")
		with open(config_file, "w") as f:
			f.write(nginx_config)
		log("INFO", f"Successfully wrote nginx config for instance {instance.id}")
	except IOError as e:
		log("ERROR", f"Failed to write nginx config to {config_file}: {str(e)}")
		raise
	except Exception as e:
		log("ERROR", f"Unexpected error writing nginx config: {str(e)}")
		raise

def reload_nginx():
	nginx_container = utils.docker.docker_client.containers.get("flowcase-nginx")
	result = nginx_container.exec_run("nginx -s reload")
	if result.exit_code != 0:
		log("WARNING", f"Failed to reload Nginx: {result.output.decode()}")

@droplet_bp.route('/api/droplet/<int:droplet_id>/pull-image', methods=['POST'])
@login_required
def pull_droplet_image(droplet_id):
	"""Manually pull a droplet's Docker image"""
	droplet = Droplet.query.filter_by(id=droplet_id).first()
	if not droplet:
		return jsonify({"success": False, "error": "Droplet not found"}), 404

	if not droplet.container_docker_image:
		return jsonify({"success": False, "error": "Droplet has no Docker image configured"}), 400

	# Check if docker client is available
	if not utils.docker.docker_client:
		log("ERROR", "Docker client not available")
		return jsonify({"success": False, "error": "Docker service is not available"}), 500

	try:
		# Use the existing pull_single_image function
		success, message = utils.docker.pull_single_image(
			droplet.container_docker_registry,
			droplet.container_docker_image
		)

		if success:
			return jsonify({"success": True, "message": message})
		else:
			return jsonify({"success": False, "error": message}), 500

	except Exception as e:
		log("ERROR", f"Error pulling image for droplet {droplet_id}: {str(e)}")
		return jsonify({"success": False, "error": f"Failed to pull image: {str(e)}"}), 500

def generate_guac_token(droplet: Droplet, user: User) -> str:
	"""Generate a token for the guacamole instance"""
	guac_token = {
		"connection": {
			"type": droplet.droplet_type,
			"settings": {
				"hostname": droplet.server_ip,
				"username": droplet.server_username,
				"password": droplet.server_password,
				"port": droplet.server_port,
			}
		},
	}

	def encrypt_token(token, auth_token):
		iv = os.urandom(16)  # 16 bytes for AES
		auth_token = auth_token[:32]
		cipher = AES.new(auth_token, AES.MODE_CBC, iv)

		# Convert value to JSON and pad it
		padded_data = pad(json.dumps(token).encode(), AES.block_size)

		# Encrypt data
		encrypted_data = cipher.encrypt(padded_data)

		# Encode the IV and encrypted data
		data = {
			'iv': base64.b64encode(iv).decode('utf-8'),
			'value': base64.b64encode(encrypted_data).decode('utf-8')
		}

		# Convert the data dictionary to JSON and then encode it
		json_data = json.dumps(data)
		return base64.b64encode(json_data.encode()).decode('utf-8')

	return encrypt_token(guac_token, user.auth_token.encode())

@droplet_bp.route('/droplet/<string:instance_id>', methods=['GET'])
@login_required
def droplet(instance_id: str):
	instance = DropletInstance.query.filter_by(id=instance_id).first()
	if not instance:
		return redirect("/")

	if instance.user_id != current_user.id:
		return redirect("/")

	# mark activity by updating the timestamp
	try:
		instance.updated_at = datetime.utcnow()
		db.session.commit()
	except Exception:
		# ignore failures to update activity
		pass

	using_guac = False
	guac_token = None
	droplet = Droplet.query.filter_by(id=instance.droplet_id).first()
	if droplet.droplet_type in ["vnc", "rdp", "ssh"]:
		using_guac = True
		guac_token = generate_guac_token(droplet, current_user)

	return render_template('droplet.html', instance_id=instance_id, droplet=droplet, guacamole=using_guac, guac_token=guac_token)

@droplet_bp.route('/api/instance/<string:instance_id>/heartbeat', methods=['POST'])
@login_required
def heartbeat(instance_id: str):
	"""Called by the frontend to mark the instance as active."""

	instance = DropletInstance.query.filter_by(id=instance_id).first()
	if not instance:
		return jsonify({"success": False, "error": "Instance not found"}), 404

	if instance.user_id != current_user.id:
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	try:
		instance.updated_at = datetime.utcnow()
		db.session.commit()
	except Exception:
		# ignore commit errors
		pass

	return jsonify({"success": True})


@droplet_bp.route('/api/instance/<string:instance_id>/destroy', methods=['GET'])
@login_required
def stop_instance(instance_id: str):
	instance = DropletInstance.query.filter_by(id=instance_id).first()
	if not instance:
		return jsonify({"success": False, "error": "Instance not found"}), 404

	if instance.user_id != current_user.id:
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	try:
		if utils.docker.docker_client:
			container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
			container.remove(force=True)
	except Exception as e:
		log("ERROR", f"Error removing container: {str(e)}")
		pass

	# Delete nginx config
	if os.path.exists(f"/flowcase/nginx/containers.d/{instance.id}.conf"):
		os.remove(f"/flowcase/nginx/containers.d/{instance.id}.conf")

	db.session.delete(instance)
	db.session.commit()

	return jsonify({"success": True})


@droplet_bp.route('/api/debug/instances', methods=['GET'])
@login_required
def debug_instances():
	"""Debug endpoint to see all instances and their timestamps (admin only)."""
	from flask import current_app
	from utils.permissions import Permissions
	
	if not Permissions.check_permission(current_user.id, Permissions.ADMIN_PANEL):
		return jsonify({"success": False, "error": "Unauthorized"}), 403

	timeout_minutes = current_app.config.get('SESSION_TIMEOUT_MINUTES', 30)
	threshold = datetime.utcnow() - timedelta(minutes=timeout_minutes)
	
	instances = DropletInstance.query.all()
	response = {
		"success": True,
		"now": datetime.utcnow().isoformat(),
		"threshold": threshold.isoformat(),
		"timeout_minutes": timeout_minutes,
		"instances": []
	}
	
	for inst in instances:
		mins_ago = (datetime.utcnow() - inst.updated_at).total_seconds() / 60
		response["instances"].append({
			"id": inst.id,
			"user_id": inst.user_id,
			"created_at": inst.created_at.isoformat(),
			"updated_at": inst.updated_at.isoformat(),
			"minutes_since_update": round(mins_ago, 2),
			"will_be_cleaned": inst.updated_at < threshold
		})
	
	return jsonify(response)
