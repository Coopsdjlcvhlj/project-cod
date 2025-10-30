import unittest
from src.app import app

class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_home_page(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome', response.data)

    def test_another_route(self):
        response = self.app.get('/another-route')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Another Route', response.data)

if __name__ == '__main__':
    unittest.main()