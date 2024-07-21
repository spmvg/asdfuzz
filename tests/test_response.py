import os
import unittest
from pathlib import Path

from asdfuzz.http.request import Request, NoContentError


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
        request = Request.from_file(self.post_request_file, 1234)
        self.assertEqual(
            b"""POST /a/b HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
content-length: 44
cookie: a_cookie=a_cookie_value; =; qqq=; ; _gat=1

field1=value1%5B%5D&field2=&&=&field4=value4

""".replace(b'\n', b'\r\n'),
            request.recreate()
        )

    def test_post_recreate_with_adjusted_formdata(self):
        request = Request.from_file(self.post_request_file, 1234)
        request.form_data[0].value = b'something_24_characters_longer'
        self.assertEqual(
            b"""POST /a/b HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
content-length: 62
cookie: a_cookie=a_cookie_value; =; qqq=; ; _gat=1

field1=something_24_characters_longer&field2=&&=&field4=value4

""".replace(b'\n', b'\r\n'),
            request.recreate()
        )

    def test_post_recreate_json(self):
        request = Request.from_file(self.post_request_json_file, 1234)
        self.assertEqual(
            b"""POST http://127.0.0.1/v1/jsondata HTTP/1.1
Host: 127.0.0.1
Accept: */*
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
content-length: 82
Connection: keep-alive
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site

{"k0": "v0", "k1": [{"k111": true, "k112": "v112"}, {"k121": "v121"}], "k2": "v2"}

""".replace(b'\n', b'\r\n'),
            request.recreate()
        )

    def test_post_recreate_json_with_adjusted_jsondata(self):
        request = Request.from_file(self.post_request_json_file, 1234)
        request.json_data.json_nodes[2].keys[-1].key = "modified"
        self.assertEqual(
            b"""POST http://127.0.0.1/v1/jsondata HTTP/1.1
Host: 127.0.0.1
Accept: */*
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
content-length: 86
Connection: keep-alive
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site

{"k0": "v0", "k1": [{"k111": true, "k112": "modified"}, {"k121": "v121"}], "k2": "v2"}

""".replace(b'\n', b'\r\n'),
            request.recreate()
        )

    def test_get_json_in_base64(self):
        request = Request.from_file(self.get_request_file_json_in_base64, 1234)

        request.cookies[0].json_in_base64.json_nodes[0].keys[-1].key = 3
        request.cookies[0].update_value_based_on_json_in_base64()

        request.url.parameters[0].json_in_base64.json_nodes[0].keys[-1].key = 3
        request.url.parameters[0].update_value_based_on_json_in_base64()

        self.assertEqual(
            b"""GET /a/b?json_in_base64_url=eyIxIjogM30 HTTP/1.1
Host: 127.0.0.1
Connection: close
cookie: json_in_base64_cookie=eyIxIjogM30

""".replace(b'\n', b'\r\n'),
            request.recreate()
        )

    def test_get_fetch(self):
        request = Request.from_fetch_nodejs(self.get_request_fetch_file, 1234)
        self.assertEqual(
            b'GET http://127.0.0.1/dir/file.json HTTP/1.1\r\n'
            b'header_key: header value\r\n'
            b'connection: close\r\n'
            b'host: 127.0.0.1\r\n'
            b'\r\n',
            request.recreate()
        )

    def test_get_fetch_no_content(self):
        with self.assertRaises(NoContentError):
            Request.from_fetch_nodejs(self.get_request_fetch_file_no_content, 1234)

    def test_post_fetch(self):
        request = Request.from_fetch_nodejs(self.post_request_fetch_file, 1234)
        self.assertEqual(
            b'POST http://127.0.0.1/dir/file.json HTTP/1.1\r\n'
            b'header_key: header value\r\n'
            b'connection: close\r\n'
            b'host: 127.0.0.1\r\n'
            b'content-length: 10\r\n'
            b'\r\n'
            b'body_value\r\n'
            b'\r\n',
            request.recreate()
        )
