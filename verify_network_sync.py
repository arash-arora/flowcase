
import requests
import json
import sys
from unittest.mock import MagicMock, patch

from __init__ import create_app, db
from routes.admin import api_admin_networks
from models.network import DockerNetwork

app = create_app()

def test_network_sync():
    with app.app_context():
        # Clean up
        db.session.query(DockerNetwork).filter_by(name="system_net_1").delete()
        db.session.commit()
        
        # Mock get_networks to return a system network
        mock_networks = [
            {'name': 'bridge', 'driver': 'bridge', 'subnet': '172.17.0.0/16', 'gateway': '172.17.0.1'},
            {'name': 'system_net_1', 'driver': 'bridge', 'subnet': '10.0.0.0/8', 'gateway': '10.0.0.1'}
        ]
        
        with patch('routes.admin.Permissions.check_permission', return_value=True), \
             patch('flask_login.utils._get_user', return_value=MagicMock(id='admin')), \
             patch('utils.docker.is_docker_available', return_value=True), \
             patch('utils.docker.get_networks', return_value=mock_networks):
             
             with app.test_request_context('/api/admin/networks'):
                 response = api_admin_networks()
                 
                 if isinstance(response, tuple):
                     data = response[0].get_json()
                 else:
                     data = response.get_json()
                 
                 if not data['success']:
                     print(f"FAILED: {data}")
                     return False
                 
                 # Check if system_net_1 is present
                 found = False
                 for net in data['networks']:
                     if net['name'] == 'system_net_1':
                         found = True
                         break
                 
                 if not found:
                     print("FAILED: system_net_1 not found in response")
                     return False

                 # Verify it was added to DB
                 db_net = DockerNetwork.query.filter_by(name="system_net_1").first()
                 if not db_net:
                     print("FAILED: system_net_1 not found in DB")
                     return False
                     
                 print("PASSED: Network sync successful")
                 
                 # Clean up
                 db.session.delete(db_net)
                 db.session.commit()
                 return True

if __name__ == "__main__":
    if test_network_sync():
        print("Verification Successful")
        sys.exit(0)
    else:
        print("Verification Failed")
        sys.exit(1)
