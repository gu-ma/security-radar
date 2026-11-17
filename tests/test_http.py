import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from security_radar.http import SourcePaginationError, SourceSchemaError, _github_next_link, get_github_page


class HTTPTests(unittest.TestCase):
    def test_link_header_cursor(self):
        first = "https://api.github.com/advisories?type=reviewed&per_page=100"
        next_url = first + "&after=eyJwYWdlIjoyfQ"
        header = '<' + next_url + '>; rel="next", <' + first + '>; rel="prev"'
        self.assertEqual(_github_next_link(header, first), next_url)
        self.assertIsNone(_github_next_link("", first))

    def test_rejects_external_next_url(self):
        first = "https://api.github.com/advisories?per_page=100"
        with self.assertRaises(SourcePaginationError):
            _github_next_link('<https://malicious.example/steal>; rel="next"', first)
        with self.assertRaises(SourcePaginationError):
            _github_next_link('<http://api.github.com/advisories?after=1>; rel="next"', first)

    def test_non_list_api_error_not_treated_as_empty(self):
        with patch("security_radar.http._request_json", return_value=({"message": "Bad credentials"}, "")):
            with self.assertRaises(SourceSchemaError):
                get_github_page("https://api.github.com/advisories")


if __name__ == "__main__":
    unittest.main()
