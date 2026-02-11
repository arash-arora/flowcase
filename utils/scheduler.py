import threading
import time
from datetime import datetime, timedelta
from flask import current_app
from __init__ import db
from models.droplet import DropletInstance
from utils.logger import log
import utils.docker
import os


def cleanup_inactive_droplets(app):
    """
    Background task to cleanup inactive droplets.
    Runs every 5 minutes.
    """
    while True:
        time.sleep(300)  # Sleep for 5 minutes

        with app.app_context():
            try:
                # Find droplets inactive for more than 30 minutes
                threshold = datetime.now() - timedelta(minutes=30)
                inactive_instances = DropletInstance.query.filter(
                    DropletInstance.last_active_at < threshold
                ).all()

                if not inactive_instances:
                    continue

                log(
                    "INFO",
                    f"Found {len(inactive_instances)} inactive droplets to cleanup",
                )

                for instance in inactive_instances:
                    try:
                        log(
                            "INFO",
                            f"Destroying inactive instance {instance.id} (Last active: {instance.last_active_at})",
                        )

                        # Ensure docker client is available
                        if not utils.docker.docker_client:
                            utils.docker.init_docker()

                        # Remove docker container
                        if utils.docker.docker_client:
                            try:
                                container = utils.docker.docker_client.containers.get(
                                    f"flowcase_generated_{instance.id}"
                                )
                                container.remove(force=True)
                            except Exception as e:
                                # Check for NotFound error (using string check to avoid extra import or if docker lib varies)
                                if "404" in str(e) or "not found" in str(e).lower():
                                    pass
                                else:
                                    log(
                                        "ERROR",
                                        f"Failed to remove container for {instance.id}: {e}",
                                    )
                                    # If container exists but couldn't be removed, do not remove from DB
                                    continue
                        else:
                            log(
                                "ERROR",
                                f"Docker client not available, skipping cleanup for {instance.id}",
                            )
                            continue

                        # Remove nginx config
                        nginx_config_path = (
                            f"/flowcase/nginx/containers.d/{instance.id}.conf"
                        )
                        if os.path.exists(nginx_config_path):
                            try:
                                os.remove(nginx_config_path)
                            except Exception as e:
                                log(
                                    "ERROR",
                                    f"Failed to remove nginx config for {instance.id}: {e}",
                                )

                        # Remove from DB
                        db.session.delete(instance)
                        db.session.commit()

                        log(
                            "INFO",
                            f"Successfully destroyed inactive instance {instance.id}",
                        )

                    except Exception as e:
                        log(
                            "ERROR",
                            f"Error destroying inactive instance {instance.id}: {str(e)}",
                        )
                        # Continue with other instances even if one fails
                        continue

            except Exception as e:
                log("ERROR", f"Error in cleanup_inactive_droplets: {str(e)}")


def start_scheduler(app):
    """Start the background scheduler thread."""
    thread = threading.Thread(target=cleanup_inactive_droplets, args=(app,))
    thread.daemon = True
    thread.start()
