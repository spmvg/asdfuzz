import os
import unittest
from pathlib import Path

from asdfuzz.http.request import Request, NoContentError, UnexpectedKeysError


class TestResponse(unittest.TestCase):
    def setUp(self) -> None:
        self.get_request_file = os.path.join(
            Path(__file__).parent,
            'get_request_with_fragment.txt'
        )
        self.post_request_file = os.path.join(
            Path(__file__).parent,
            'post_request_weird_post_data.txt'
        )
        self.post_request_json_file = os.path.join(
            Path(__file__).parent,
            'post_json_request.txt'
        )
        self.get_request_file_json_in_base64 = os.path.join(
            Path(__file__).parent,
            'get_request_json_in_base64.txt'
        )
        self.get_request_fetch_file = os.path.join(
            Path(__file__).parent,
            'get_request_fetch.txt'
        )
        self.get_request_fetch_file_no_content = os.path.join(
            Path(__file__).parent,
            'get_request_fetch_no_content.txt'
        )
        self.get_request_fetch_file_unexpected_field = os.path.join(
            Path(__file__).parent,
            'get_request_fetch_unexpected_field.txt'
        )
        self.post_request_fetch_file = os.path.join(
            Path(__file__).parent,
            'post_request_fetch.txt'
        )

    def test_get_recreate(self):
        with open(self.get_request_file, 'rb') as f:
            expected_result = f.read()
        request = Request.from_file(self.get_request_file, 1234)
        self.assertEqual(
            expected_result,
            request.recreate()
        )

    def test_post_recreate(self):
        with open(self.post_request_file, 'rb') as f:
            expected_result = f.read()
        request = Request.from_file(self.post_request_file, 1234)
        self.assertEqual(
            expected_result,
            request.recreate()
        )

    def test_post_recreate_with_adjusted_formdata(self):
        with open(self.post_request_file, 'rb') as f:
            expected_result = f.read().replace(
                b'Content-Length: 38',
                b'Content-Length: 62'
            ).replace(
                b'field1=value1',
                b'field1=something_24_characters_longer'
            )
        request = Request.from_file(self.post_request_file, 1234)
        request.form_data[0].value = b'something_24_characters_longer'
        self.assertEqual(
            expected_result,
            request.recreate()
        )

    def test_post_recreate_json(self):
        with open(self.post_request_json_file, 'rb') as f:
            expected_result = f.read()
        request = Request.from_file(self.post_request_json_file, 1234)
        self.assertEqual(
            expected_result,
            request.recreate()
        )

    def test_post_recreate_json_with_adjusted_jsondata(self):
        with open(self.post_request_json_file, 'rb') as f:
            expected_result = f.read().replace(
                b"v112",
                b"modified"
            ).replace(
                b'Content-Length: 82',
                b'Content-Length: 86'
            )
        request = Request.from_file(self.post_request_json_file, 1234)
        request.json_data.json_nodes[2].keys[-1].key = "modified"
        self.assertEqual(
            expected_result,
            request.recreate()
        )

    def test_get_json_in_base64(self):
        with open(self.get_request_file_json_in_base64, 'rb') as f:
            expected_result = f.read().replace(
                b'eyIxIjogMn0',  # {"1": 2}
                b'eyIxIjogM30'  # {"1": 3}
            )

        request = Request.from_file(self.get_request_file_json_in_base64, 1234)

        request.cookies[0].json_in_base64.json_nodes[0].keys[-1].key = 3
        request.cookies[0].update_value_based_on_json_in_base64()

        request.url.parameters[0].json_in_base64.json_nodes[0].keys[-1].key = 3
        request.url.parameters[0].update_value_based_on_json_in_base64()

        self.assertEqual(
            expected_result,
            request.recreate()
        )

    def test_get_fetch(self):
        request = Request.from_fetch_nodejs(self.get_request_fetch_file, 1234)
        self.assertEqual(
            b'GET https://example.com/dir/file.json HTTP/1.1\r\n'
            b'header_key: header value\r\n'
            b'\r\n',
            request.recreate()
        )

    def test_get_fetch_no_content(self):
        with self.assertRaises(NoContentError):
            Request.from_fetch_nodejs(self.get_request_fetch_file_no_content, 1234)

    def test_get_fetch_unexpected_field(self):
        with self.assertRaises(UnexpectedKeysError):
            Request.from_fetch_nodejs(self.get_request_fetch_file_unexpected_field, 1234)

    def test_post_fetch(self):
        request = Request.from_fetch_nodejs(self.post_request_fetch_file, 1234)
        self.assertEqual(
            b'POST https://example.com/dir/file.json HTTP/1.1\r\n'
            b'header_key: header value\r\n'
            b'\r\n'
            b'body_value\r\n'
            b'\r\n',
            request.recreate()
        )
