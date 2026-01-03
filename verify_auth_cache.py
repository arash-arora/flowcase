
import sys
from unittest.mock import MagicMock, patch
from routes.auth import droplet_connect, _auth_cache

# Mock dependencies
from __init__ import create_app

app = create_app()

def test_auth_cache():
    with app.app_context():
        # Setup mock user and request
        mock_user = MagicMock(id='user1', auth_token='token123')
        
        # Helper to setup query mock
        mock_query = MagicMock()
        mock_query.filter_by.return_value.first.return_value = mock_user
        
        with patch('routes.auth.User.query', mock_query):
            
            # 1. First request - should hit DB
            with app.test_request_context('/droplet_connect', headers={'Cookie': 'userid=user1; token=token123'}):
                _auth_cache.clear() # Reset cache
                from flask import request
                print(f"Request cookies: {request.cookies}")
                response = droplet_connect()
                
                if response.status_code != 200:
                    print(f"FAILED: First request returned {response.status_code}")
                    return False
                
                if not mock_query.filter_by.called:
                    print("FAILED: First request did not query DB")
                    return False
                
                print("First request checks passed.")

            # 2. Second request - should NOT hit DB (use cache)
            mock_query.reset_mock()
            
            with app.test_request_context('/droplet_connect', headers={'Cookie': 'userid=user1; token=token123'}):
                response = droplet_connect()
                
                if response.status_code != 200:
                     print(f"FAILED: Second request returned {response.status_code}")
                     return False
                     
                if mock_query.called:
                    print("FAILED: Second request hit the DB (Cache missed)")
                    return False
                
                print("Second request checks passed (Cache hit).")
                return True

if __name__ == "__main__":
    if test_auth_cache():
        print("Verification Successful")
        sys.exit(0)
    else:
        print("Verification Failed")
        sys.exit(1)
