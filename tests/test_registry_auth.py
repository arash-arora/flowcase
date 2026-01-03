
import sys
import os
import uuid
from flask import json
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from __init__ import create_app, db
from models.user import User
from models.registry import Registry
from utils.permissions import Permissions

def test_registry_auth():
    app = create_app()
    app.config['LOGIN_DISABLED'] = True
    
    with app.app_context():
        # Setup
        print("Setting up test data...")
        unique_url = f"registry.example.com:{uuid.uuid4()}"
        unique_mb_user = f"user_{uuid.uuid4()}"
        unique_mb_pass = "supersecret"
        
        # 1. Test POST /api/admin/registry with credentials
        print("\nTesting POST /api/admin/registry...")
        
        # Mock Permissions
        with patch('utils.permissions.Permissions.check_permission', return_value=True):
             with app.test_client() as client:
                # We need to bypass login check. LOGIN_DISABLED=True in config key.
                # But routes uses @login_required decorator.
                # Simulating request:
                
                payload = {
                    "url": unique_url,
                    "username": unique_mb_user,
                    "password": unique_mb_pass
                }
                
                # Mock current_user for the route
                with patch('routes.admin.current_user') as mock_user:
                    mock_user.is_authenticated = True
                    mock_user.id = "admin_id"
                    
                    response = client.post('/api/admin/registry', json=payload)
                    print(f"Response Status: {response.status_code}")
                    print(f"Response Body: {response.get_data(as_text=True)}")
                    
                    if response.status_code != 200:
                         print("FAILURE: API did not return 200")
                         return

        # 2. Verify Database
        print("\nVerifying Database...")
        registry = Registry.query.filter_by(url=unique_url).first()
        if registry:
            print(f"Registry found: {registry.url}")
            if registry.username == unique_mb_user and registry.password == unique_mb_pass:
                print("SUCCESS: Credentials saved correctly.")
            else:
                print(f"FAILURE: Credentials mismatch. Expected {unique_mb_user}/{unique_mb_pass}, got {registry.username}/{registry.password}")
        else:
             print("FAILURE: Registry not found in DB.")
             return

        # 3. Verify Utils Docker Pull
        print("\nVerifying Docker Utility...")
        from utils.docker import pull_single_image, docker_client
        
        # Mock docker_client.images.pull
        with patch('utils.docker.docker_client') as mock_docker:
            mock_docker.images.list.return_value = []
            
            image_name = f"{unique_url}/myimage:latest"
            
            # Call function
            result, msg = pull_single_image(unique_url, "myimage")
            
            print(f"Function Result: {result}, Msg: {msg}")
            
            # Check if auth_config was passed
            # The function signature is docker_client.images.pull(repository, tag, auth_config=..., platform=...)
            # repository = unique_url/myimage
            
            args, kwargs = mock_docker.images.pull.call_args
            print(f"Docker Pull Args: {args}")
            print(f"Docker Pull Kwargs: {kwargs}")
            
            if 'auth_config' in kwargs:
                auth = kwargs['auth_config']
                if auth['username'] == unique_mb_user and auth['password'] == unique_mb_pass:
                    print("SUCCESS: Auth config passed correctly to Docker client.")
                else:
                     print(f"FAILURE: Auth config mismatch: {auth}")
            else:
                print("FAILURE: Auth config NOT passed to Docker client.")

        # Cleanup
        print("\nCleaning up...")
        db.session.delete(registry)
        db.session.commit()

if __name__ == "__main__":
    test_registry_auth()
