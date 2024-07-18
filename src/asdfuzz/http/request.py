import json
import logging
import re
from dataclasses import dataclass
from typing import List, Union
from urllib.parse import urlparse

import typer

from asdfuzz._utils import _NEWLINE, _pre_post, _EQUALS, _COOKIE_SEPARATOR, _AND, _get_header, _get_data
from asdfuzz.http.cookie import Cookie
from asdfuzz.http.form_data import FormData
from asdfuzz.http.json_data import JSONData
from asdfuzz.http.url import URL

logger = logging.getLogger(__name__)

_method_colors = {  # same as swagger colors
    'GET': typer.colors.BLUE,
    'PUT': typer.colors.YELLOW,
    'POST': typer.colors.GREEN,
    'DELETE': typer.colors.RED,
}
_space = b' '
_cookie_line_indicator = b'Cookie: '
_form_data_content_type = b'application/x-www-form-urlencoded'
_json_data_content_types = {
    b'application/json',
    b'application/json;charset=utf-8',
}
_content_length_regex = _NEWLINE + rb'Content-Length: (\d+)' + _NEWLINE


class UnexpectedKeysError(ValueError):
    pass


class NoContentError(ValueError):
    pass


@dataclass
class Request:
    """
    A single HTTP request.
    The HTTP request is interpreted and individual components can be modified for fuzzing.
    To generate a ``bytes`` request again, run ``.recreate``.
    """
    request: bytes
    """ The raw request in bytes. """
    port: int
    """ The port to use for the request. """
    disable_https: bool = False
    """ Whether to use HTTPS ``disable_https=False`` or HTTP ``disable_https=True`` """

    def __post_init__(self):
        self.header: bytes = _get_header(self.request)
        self.data: bytes = _get_data(self.request)
        self.method: str = self.request.splitlines()[0].split(_space)[0].decode()
        self.url: URL = URL(self.request.splitlines()[0].split(_space)[1])
        self.cookies: List[Cookie] = self._cookies()
        self.form_data: List[FormData] = self._form_data()
        self.json_data: Optional[JSONData] = self._json_data()

    @classmethod
    def from_file(cls, filename, port) -> 'Request':
        """
        Extracts a ``Request`` object from a file containing a raw HTTP request, indicated by ``filename``.
        The file should not contain the response: only the request.
        """
        with open(filename, 'rb') as f:
            request = f.read()
            while request[-len(2 * _NEWLINE):] != 2 * _NEWLINE:
                request += _NEWLINE
        return Request(request, port)

    @staticmethod
    def _trim_response(request):
        header_end = request.index(2 * _NEWLINE) + len(2 * _NEWLINE)
        header_part = request[:header_end]

        content_length = 0
        content_length_match = re.search(_content_length_regex, header_part, re.MULTILINE)
        if content_length_match:
            content_length = int(content_length_match.group(1))

        start_of_response = header_end + content_length
        logger.debug(
            f'Header end {header_end}, '
            f'content length: {content_length}, '
            f'start of response: {start_of_response}'
         )
        return request[:start_of_response]

    @classmethod
    def from_zap_message_export(cls, filename, port) -> List['Request']:
        """
        Extracts HTTP requests from an OWASP ZAP message export.
        The ZAP message export can be downloaded by selecting messages in the history view and then selecting:
        `Report - Export Messages To File`.
        The filename of the resulting file should be the ``filename`` parameter.
        The responses in the ZAP message export are ignored.
        """
        print('Extracting messages from ZAP message export...')

        request = b''
        requests = []
        with open(filename, 'rb') as f:
            with typer.progressbar(f.readlines()[1:]) as progress:
                for line in progress:
                    re_match = re.match(rb'^==== (\d+) ==========$', line)
                    if re_match:
                        logger.debug(f'Parsing message before ZAP message number {int(re_match.group(1))}')

                        request_without_response = cls._trim_response(request)

                        requests.append(Request(
                            request=request_without_response,
                            port=port
                        ))
                        request = b''
                        continue
                    request += line
                else:
                    logger.debug('Adding final ZAP message')
                    request_without_response = cls._trim_response(request)
                    requests.append(Request(
                        request=request_without_response,
                        port=port
                    ))
        return requests

    @classmethod
    def from_fetch_nodejs(cls, filename, port) -> 'Request':
        """
        Extracts a HTTP request from a file containing the content of "Copy as fetch (Node.js)" from the Network tab
        of Chrome DevTools.
        "Copy as fetch (Node.js)" is a low-effort way to copy a request from Chrome, since Chrome does not directly
        support extracting a raw HTTP request.
        Make sure that the "Copy as fetch (Node.js)" option is used, not the "Copy as fetch" option.
        """
        regex = re.compile(r'fetch\((.*)\);', re.DOTALL)
        with open(filename, 'r') as f:
            content = f.read()

        match = re.match(
            regex,
            content,
        )
        if not match:
            raise NoContentError(f'No fetch content found in file {filename}')
        fetch_output = match.group(1)
        url, dictionary = json.loads('[' + fetch_output + ']')

        method_key, headers_key, body_key = 'method', 'headers', 'body'
        unexpected_keys = dictionary.keys() - {method_key, headers_key, body_key}
        if unexpected_keys:
            raise UnexpectedKeysError(
                f'Unexpected keys in fetch input: {unexpected_keys}. '
                f'Was the wrong copy option in DevTools used?"'
            )

        method = dictionary[method_key]
        headers = dictionary.get(headers_key, {})
        body = dictionary.get(body_key)

        hostname = urlparse(url).hostname.encode()

        raw_request = method.encode() + b' ' + url.encode() + b' HTTP/1.1' + _NEWLINE + b'Host: ' + hostname
        for key, value in headers.items():
            raw_request += _NEWLINE + key.encode() + b': ' + value.encode()  # no quote needed
        if body is not None:
            raw_request += 2 * _NEWLINE + body.encode()
        return Request(raw_request + 2 * _NEWLINE, port=port)

    @property
    def host(self) -> str:
        """ The host as indicated in the URL. """
        return self.request.splitlines()[1][6:].decode()

    @property
    def colored_method(self):
        """ Colorized HTTP method. """
        color = _method_colors.get(self.method)
        if color:
            return typer.style(self.method, fg=color)
        return self.method

    @property
    def content_type(self):
        """ Content type of the request, as indicated in the ``Content-type`` header. """
        content_type_indicator = b'Content-Type: '
        for line in self.header.splitlines():
            if not line.startswith(content_type_indicator):
                continue
            return line[len(content_type_indicator):]
        return

    def _cookies(self):
        header_lines = self.header.splitlines()
        cookie_line = None
        for line in header_lines:
            if line.startswith(_cookie_line_indicator):
                cookie_line = line
                break
        if not cookie_line:
            return

        return [
            Cookie(key, value) for key, value in [
                _pre_post(key_value, _EQUALS)
                for key_value in cookie_line[len(_cookie_line_indicator):].split(_COOKIE_SEPARATOR)
            ]
        ]

    def _form_data(self):
        if (
                not self.content_type
                or not self.data
                or self.content_type.lower() != _form_data_content_type
        ):
            return
        return [
            FormData(key, value) for key, value in [
                _pre_post(key_value, _EQUALS)
                for key_value in self.data.splitlines()[0].split(_AND)
            ]
        ]

    def _json_data(self):
        if (
                not self.content_type
                or not self.data
                or self.content_type.lower() not in _json_data_content_types
        ):
            return
        return JSONData(self.data.decode())

    def disable_all_fuzzing(self):
        """ When called, recursively disables all fuzzing. """
        self.url.disable_all_fuzzing()
        for cookie in self.cookies or []:
            cookie.fuzz = False
        for form_data in self.form_data or []:
            form_data.fuzz = False
        if self.json_data is not None:
            for node in self.json_data.json_nodes:
                node.fuzz = False

    def _recreate_list(self) -> List[Union[str, bytes]]:
        parts = []

        header_lines = [line.decode() for line in self.header.splitlines()]
        splitted_first_line = header_lines[0].split(_space.decode())
        header_lines[0] = _space.decode().join(
            [
                splitted_first_line[0],
                self.url.colored_url,
            ] + splitted_first_line[2:]
        )
        for line_index in range(len(header_lines)):
            line = header_lines[line_index]
            if not line.startswith(_cookie_line_indicator.decode()):
                continue
            header_lines[line_index] = (
                    _cookie_line_indicator.decode()
                    + _COOKIE_SEPARATOR.decode().join(
                    cookie.key.decode() if cookie.value is None  # result of _pre_post if there is no equals sign at all
                    else (
                        (cookie.key + _EQUALS).decode()
                        + typer.style(
                            cookie.value.decode(),
                            bg=typer.colors.BLUE
                        )
                    )
                    for cookie in self.cookies
                )
            )
        parts.append(_NEWLINE.decode().join(header_lines))

        if not self.data:
            parts.append('')
            return parts

        if self.form_data:
            data = _AND.decode().join(
                form_data.key.decode() if form_data.value is None  # result of _pre_post if there is no equals sign at all
                else (
                    (form_data.key + _EQUALS).decode()
                    + typer.style(
                        form_data.value.decode(),
                        bg=typer.colors.RED
                    )
                )
                for form_data in self.form_data
            )
            self._update_content_length(data, parts)

            parts.append(data)
            parts.append('')
        elif self.json_data:
            data = self.json_data.to_json()
            self._update_content_length(data, parts)

            parts.append(data)
            parts.append('')
        else:
            parts.append(self.data)

        return parts

    def _update_content_length(self, data, parts):
        content_length = len(self._unstyle_encode(data))
        parts[0] = re.sub(
            _content_length_regex.decode(),
            _NEWLINE.decode() + rf'Content-Length: {content_length}' + _NEWLINE.decode(),
            parts[0],
            re.MULTILINE
        )

    @staticmethod
    def _unstyle_encode(data):
        return typer.unstyle(data).encode()

    def recreate(self) -> bytes:
        """ Builds up the request from potentially modified components. """
        return (2 * _NEWLINE).join(
            item if isinstance(item, bytes) else self._unstyle_encode(item) for item in self._recreate_list()
        )
