
import sys
from unittest.mock import MagicMock, patch
from routes.droplet import request_new_instance

# Mock dependencies
from __init__ import create_app

app = create_app()

def test_multihoming():
    with app.app_context():
        # Mock inputs
        mock_user = MagicMock(id='user1', username='testuser', auth_token='token')
        mock_user.is_authenticated = True # Ensure login_required passes

        mock_droplet = MagicMock(
            id='drop1', 
            display_name='Test Droplet', 
            droplet_type='container',
            network_id='net1', # Custom network
            container_docker_image='alpine',
            container_cores=1,
            container_memory=128,
            container_persistent_profile_path=None
        )
        
        # Mocks
        with patch('routes.droplet.current_user', mock_user), \
             patch('utils.permissions.Permissions.user_in_groups', return_value=True), \
             patch('routes.droplet.Droplet.query.filter_by') as mock_droplet_query, \
             patch('routes.droplet.DropletInstance.query.filter_by') as mock_instance_query, \
             patch('routes.droplet.db.session'), \
             patch('utils.docker.docker_client') as mock_docker, \
             patch('builtins.open', new_callable=MagicMock) as mock_open, \
             patch('routes.droplet.check_resources', return_value=(True, "")):
             
             mock_droplet_query.return_value.first.return_value = mock_droplet
             mock_instance_query.return_value.first.return_value = None
             
             # Setup network mock
             mock_custom_net = MagicMock()
             mock_custom_net.name = "custom_network"
            
             # Mock DockerNetwork if possible, or skip since we can't easily patch local import
             # However, the logic `if network:` depends on it. 
             # If we can't patch it, `network` will be None (or import fail).
             # Let's try to patch `sys.modules` for `models.network` 
             
             with patch.dict('sys.modules', {'models.network': MagicMock()}):
                 # We need the class DockerNetwork inside models.network
                 sys.modules['models.network'].DockerNetwork.query.filter_by.return_value.first.return_value = mock_custom_net
                 
                 # Input: droplet_id, not id
                 with app.test_request_context('/api/instance/request', method='POST', json={'droplet_id': 'drop1'}):
                     
                     # Mock docker client
                     mock_container = MagicMock()
                     mock_container.status = 'running'
                     # Make sure container has logs method returning bytes
                     mock_container.logs.return_value = b""
                     
                     mock_docker.containers.run.return_value = mock_container
                     mock_docker.containers.get.return_value = mock_container # For nginx config gen
                     
                     # Mock container network settings for nginx config gen
                     mock_container.attrs = {'NetworkSettings': {'Networks': {'flowcase_default_network': {'IPAddress': '1.2.3.4'}}}}

                     # Mock networks list for default network
                     mock_default_net = MagicMock()
                     mock_docker.networks.list.return_value = [mock_default_net]
                     
                     # Mock image existence
                     mock_image = MagicMock()
                     mock_image.tags = ['alpine', 'alpine:latest']
                     mock_docker.images.list.return_value = [mock_image]
                     
                     # Execute
                     response = request_new_instance()
                     print(f"Response: {response}")
                     print(f"Network Name logic check: mock_default_net called? {mock_docker.networks.list.called}")
                     print(f"Container created? {mock_docker.containers.run.called}")
                     if mock_docker.containers.run.called:
                         print(f"Run args: {mock_docker.containers.run.call_args}")
                     
                     # Check if connect was called on default network
                     if mock_default_net.connect.called:
                         print("PASSED: Connected to flowcase_default_network")
                         return True
                     else:
                         print("FAILED: Did not connect to flowcase_default_network")
                         return False

if __name__ == "__main__":
    try:
        if test_multihoming():
            print("Verification Successful")
            sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    print("Verification Failed")
    sys.exit(1)
