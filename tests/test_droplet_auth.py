
import unittest
from unittest.mock import MagicMock, patch
from flask import json
from __init__ import create_app, db
from models.droplet import Droplet

class TestDropletAuth(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['LOGIN_DISABLED'] = True
        self.client = self.app.test_client()
        self.created_droplet_ids = []

        # Patch Permissions
        self.perm_patcher = patch('routes.admin.Permissions.check_permission', return_value=True)
        self.perm_patcher.start()
        
        # Patch current_user
        self.user_patcher = patch('routes.admin.current_user')
        self.mock_user = self.user_patcher.start()
        self.mock_user.id = 'test_admin_id'

    def tearDown(self):
        self.perm_patcher.stop()
        self.user_patcher.stop()
        
        # Cleanup created droplets
        with self.app.app_context():
            for d_id in self.created_droplet_ids:
                Droplet.query.filter_by(id=d_id).delete()
            db.session.commit()

    def test_create_droplet_with_creds(self):
        payload = {
            "display_name": "Test Auth Droplet",
            "droplet_type": "container",
            "container_docker_registry": "my.private.registry",
            "container_docker_image": "my/image",
            "container_cores": 1,
            "container_memory": 1024,
            "registry_username": "myuser",
            "registry_password": "mypassword"
        }
        
        response = self.client.post('/api/admin/droplet', 
                                  data=json.dumps(payload),
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        droplet_id = data['droplet_id']
        self.created_droplet_ids.append(droplet_id)
        
        with self.app.app_context():
            droplet = Droplet.query.get(droplet_id)
            self.assertIsNotNone(droplet)
            self.assertEqual(droplet.registry_username, "myuser")
            self.assertEqual(droplet.registry_password, "mypassword")

    @patch('utils.docker.docker_client')
    @patch('utils.docker.init_docker')
    def test_pull_image_with_auth(self, mock_init, mock_client):
        mock_init.return_value = True
        mock_images = MagicMock()
        mock_client.images = mock_images
        
        # 1. Create Droplet via DB directly to avoid overhead
        with self.app.app_context():
            droplet = Droplet(
                display_name="Auth Pull Test",
                droplet_type="container", 
                container_docker_registry="my.private.registry",
                container_docker_image="my/image",
                registry_username="pulluser",
                registry_password="pullpass"
            )
            db.session.add(droplet)
            db.session.commit()
            droplet_id = droplet.id
            self.created_droplet_ids.append(droplet_id)

        # 2. Call Pull API
        payload = {
            "droplet_id": droplet_id
        }
        response = self.client.post('/api/admin/images/pull',
                                  data=json.dumps(payload),
                                  content_type='application/json')
        
        # 3. Verify Mock Call
        self.assertEqual(response.status_code, 200)
        # The API calls pull_single_image which calls docker_client.images.pull
        mock_images.pull.assert_called_with(
            "my.private.registry/my/image", 
            "latest", 
            auth_config={'username': 'pulluser', 'password': 'pullpass'}, 
            platform="linux/amd64"
        )

if __name__ == '__main__':
    unittest.main()
