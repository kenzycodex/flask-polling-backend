import unittest
import json
from flask_testing import TestCase
from flask_jwt_extended import JWTManager
from app import create_app  # Import your app factory

class TestPollExpiry(TestCase):
    def create_app(self):
        # Create a test configuration for your Flask app
        app = create_app(config_name='testing')  # Assuming 'testing' configuration exists
        return app

    def setUp(self):
        # Set up any initial state before each test
        self.client = self.app.test_client()
        self.jwt_manager = JWTManager(self.app)
        self.access_token = self._get_access_token()  # Utility to get a valid JWT

    def _get_access_token(self):
        # Mock or generate a valid JWT for authentication
        response = self.client.post('/login', json={'username': 'testuser', 'password': 'testpass'})
        return json.loads(response.data)['access_token']

    def test_create_poll(self):
        response = self.client.post('/create_poll', 
                                    headers={'Authorization': f'Bearer {self.access_token}'},
                                    json={
                                        'question': 'What is your favorite color?',
                                        'options': ['Red', 'Blue', 'Green'],
                                        'days_until_expiry': 1
                                    })
        self.assertEqual(response.status_code, 201)
        self.assertIn('Poll created', str(response.data))

    def test_vote(self):
        # Create a poll first
        response = self.client.post('/create_poll', 
                                    headers={'Authorization': f'Bearer {self.access_token}'},
                                    json={
                                        'question': 'What is your favorite color?',
                                        'options': ['Red', 'Blue', 'Green'],
                                        'days_until_expiry': 1
                                    })
        poll_id = json.loads(response.data)['poll_id']

        # Vote on the poll
        response = self.client.post(f'/vote/{poll_id}/0', 
                                    headers={'Authorization': f'Bearer {self.access_token}'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Vote recorded', str(response.data))

    def test_get_polls(self):
        response = self.client.get('/polls')
        self.assertEqual(response.status_code, 200)
        self.assertIn('polls', str(response.data))

    def test_get_poll(self):
        # Create a poll first
        response = self.client.post('/create_poll', 
                                    headers={'Authorization': f'Bearer {self.access_token}'},
                                    json={
                                        'question': 'What is your favorite color?',
                                        'options': ['Red', 'Blue', 'Green'],
                                        'days_until_expiry': 1
                                    })
        poll_id = json.loads(response.data)['poll_id']

        response = self.client.get(f'/polls/{poll_id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn('question', str(response.data))

    def tearDown(self):
        # Clean up any state after each test
        pass

if __name__ == '__main__':
    unittest.main()