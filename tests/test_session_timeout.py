import unittest
from datetime import datetime, timedelta
from __init__ import create_app, db
from models.droplet import Droplet, DropletInstance
from routes.droplet import cleanup_stale_instances


class TestSessionTimeout(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

        with self.app.app_context():
            # create a droplet so we can associate an instance with it
            droplet = Droplet(display_name="timeout_test", droplet_type="container")
            db.session.add(droplet)
            db.session.commit()
            self.droplet_id = droplet.id

            # create an instance that is already stale (updated_at > 30m ago)
            inst = DropletInstance(droplet_id=self.droplet_id, user_id="user1")
            inst.updated_at = datetime.utcnow() - timedelta(minutes=31)
            db.session.add(inst)
            db.session.commit()
            self.instance_id = inst.id

    def tearDown(self):
        with self.app.app_context():
            DropletInstance.query.delete()
            Droplet.query.delete()
            db.session.commit()

    def test_cleanup_removes_stale_instance(self):
        with self.app.app_context():
            # verify the instance exists initially
            inst = DropletInstance.query.filter_by(id=self.instance_id).first()
            self.assertIsNotNone(inst)

            # run cleanup
            cleanup_stale_instances()

            # now the instance should be deleted
            inst = DropletInstance.query.filter_by(id=self.instance_id).first()
            self.assertIsNone(inst)

    def test_droplet_access_updates_activity(self):
        # create a fresh active instance and simulate user access via the droplet route
        with self.app.app_context():
            inst = DropletInstance.query.filter_by(id=self.instance_id).first()
            # make it recent
            inst.updated_at = datetime.utcnow() - timedelta(minutes=10)
            db.session.commit()
            old_ts = inst.updated_at

        # call the route in a request context and mock current_user
        from routes.droplet import droplet as droplet_route
        from routes.droplet import current_user as droplet_current_user
        from unittest.mock import patch

        with self.app.test_request_context(f'/droplet/{self.instance_id}', method='GET'):
            with patch('routes.droplet.current_user') as mocked_user:
                mocked_user.id = "user1"
                mocked_user.auth_token = "dummy"
                mocked_user.username = "user1"
                # call the view
                _ = droplet_route(self.instance_id)

        with self.app.app_context():
            inst = DropletInstance.query.filter_by(id=self.instance_id).first()
            self.assertTrue(inst.updated_at > old_ts, "updated_at should be refreshed after access")

    def test_heartbeat_updates_timestamp(self):
        # simulate heartbeat call updating an old instance
        with self.app.app_context():
            inst = DropletInstance.query.filter_by(id=self.instance_id).first()
            inst.updated_at = datetime.utcnow() - timedelta(minutes=20)
            db.session.commit()
            old_ts = inst.updated_at

        # post to heartbeat endpoint
        response = self.client.post(f'/api/instance/{self.instance_id}/heartbeat')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get('success'))

        with self.app.app_context():
            inst = DropletInstance.query.filter_by(id=self.instance_id).first()
            self.assertTrue(inst.updated_at > old_ts, "heartbeat should refresh updated_at")


if __name__ == '__main__':
    unittest.main()
