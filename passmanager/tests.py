from unittest.mock import patch

from django.test import TestCase

from passmanager.views import get_file_from_github


class GitHubErrorHandlingTests(TestCase):
    def test_get_file_from_github_returns_user_safe_master_password_error(self):
        with patch("passmanager.views.denc", side_effect=ValueError("MAC check failed")):
            check, error, content = get_file_from_github("encrypted-token", "owner", "repo", "path", "wrong-password")

        self.assertFalse(check)
        self.assertEqual(error, "Incorrect master password.")
        self.assertIsNone(content)

    def test_get_file_from_github_returns_user_safe_invalid_token_error(self):
        response = type("Resp", (), {"status_code": 401, "text": "Bad credentials"})()

        with patch("passmanager.views.requests.get", return_value=response):
            with patch("passmanager.views.denc", return_value="good-token"):
                check, error, content = get_file_from_github("encrypted-token", "owner", "repo", "path", "password")

        self.assertFalse(check)
        self.assertEqual(error, "GitHub token is invalid or expired.")
        self.assertIsNone(content)

    def test_get_file_from_github_returns_vague_generic_error_for_other_server_issues(self):
        response = type("Resp", (), {"status_code": 500, "text": "server blew up", "json": lambda self: {"message": "server blow up"}})()

        with patch("passmanager.views.requests.get", return_value=response):
            with patch("passmanager.views.denc", return_value="good-token"):
                check, error, content = get_file_from_github("encrypted-token", "owner", "repo", "path", "password")

        self.assertFalse(check)
        self.assertEqual(error, "Something went wrong while contacting GitHub. Please try again.")
        self.assertIsNone(content)
