import os
import unittest

from phantom_net.auth import (
    clear_login_attempts,
    hash_password,
    is_authenticated,
    is_rate_limited,
    make_session_cookie,
    record_failed_login,
    verify_credentials,
    verify_csrf,
    verify_password,
)


class AuthTests(unittest.TestCase):
    def test_default_credentials_verify(self):
        self.assertTrue(verify_credentials("username=admin&password=phantom-admin"))
        self.assertFalse(verify_credentials("username=admin&password=wrong"))

    def test_password_hash_roundtrip(self):
        encoded = hash_password("secret")

        self.assertTrue(verify_password("secret", encoded))
        self.assertFalse(verify_password("wrong", encoded))

    def test_csrf_verification_requires_cookie_and_form_match(self):
        self.assertTrue(verify_csrf("phantom_csrf=abc", "csrf_token=abc"))
        self.assertFalse(verify_csrf("phantom_csrf=abc", "csrf_token=def"))

    def test_login_rate_limit_tracks_failed_attempts(self):
        source_ip = "192.0.2.44"
        clear_login_attempts(source_ip)
        for index in range(5):
            record_failed_login(source_ip, now=float(index))

        self.assertTrue(is_rate_limited(source_ip, now=6.0))
        clear_login_attempts(source_ip)
        self.assertFalse(is_rate_limited(source_ip, now=7.0))

    def test_session_cookie_roundtrip(self):
        os.environ["PHANTOM_AUTH_SECRET"] = "test-secret"
        cookie = make_session_cookie()
        self.assertTrue(is_authenticated(cookie))
        self.assertFalse(is_authenticated("phantom_session=bad"))


if __name__ == "__main__":
    unittest.main()
