""" Fuzzing of a single HTTP request. """

import os
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from multiprocessing import Value
from pathlib import Path
from typing import List, Tuple, Optional
from urllib.parse import quote_plus, quote

import typer

from asdfuzz.http.cookie import Cookie
from asdfuzz.http.directory import Directory
from asdfuzz.http.form_data import FormData
from asdfuzz.http.parameter import Parameter
from asdfuzz.http.request import Request
from asdfuzz.http.response import Response
from asdfuzz.fuzzing.fuzz_result import FuzzResult
from asdfuzz._utils import _EQUALS, _NEWLINE, _ORIGINAL_PAYLOAD_MARKER
from asdfuzz.fuzzing.hex_replacements import hex_replacements

SKIP_CURRENT_SECTION = 1
DO_NOT_SKIP = 0


@dataclass()
class Fuzzer:
    """
    Configurable fuzzer for a HTTP request ``request``.
    """
    request: Request
    """ HTTP request to fuzz. """
    payloads: List[str]
    """ List of strings to be used for fuzzing. """
    output_directory: Path
    """ Folder where the performed HTTP requests and responses will be stored for reference. """
    skip_current_shared: Value
    """
    ``multiprocessing.Value`` integer that will cause the rest of the fuzzing of the parameter/directory/cookie/...
    to be skipped.
    This parameter allows a section of the fuzzing to be skipped during runtime.
    This value can be asynchronously updated during runtime, and will be reset after the skipping has been performed.
    If this value is set to ``SKIP_CURRENT_SECTION``, the current section will be skipped.
    If this value is set to ``DO_NOT_SKIP``, the fuzzer will not skip.
    """
    delay: float = 0
    """ Delay between requests in seconds, excluding the duration of the request itself. """
    fuzz_directories: bool = True
    """ Whether to fuzz directories in the URL. """
    fuzz_parameters: bool = True
    """
    Whether to fuzz parameters in the URL.
    Base64-encoded JSON data in parameters will be recursively traversed and every value will be fuzzed.
    """
    fuzz_cookies: bool = True
    """
    Whether to fuzz cookies.
    Base64-encoded JSON data in cookies will be recursively traversed and every value will be fuzzed.
    """
    fuzz_form_data: bool = True
    """ Whether to fuzz form data. """
    fuzz_json_data: bool = True
    """
    Whether to fuzz JSON data.
    The JSON data will be recursively traversed and every value will be fuzzed.
    This parameter does not influence how JSON data in parameters or cookies is handled.
    """
    original_time: Optional[float] = None
    """ Time in seconds of the unmodified request. """
    original_header_size: Optional[int] = None
    """ Header size of the unmodified request in bytes. """
    original_data_size: Optional[int] = None
    """ Data size of the unmodified request in bytes. """

    def fuzz(self):
        """ Execute fuzzing for a single original HTTP request. """
        typer.echo(''.join([
            'Fuzzing request: ',
            self.request.url.colored_url
        ]))
        print('Performing zero measurement with unmodified request:')
        FuzzResult.print_header()
        response = self._perform_and_print_request(_ORIGINAL_PAYLOAD_MARKER, self.request, -1)
        if not response:
            typer.echo(typer.style(
                'Cannot perform original request. Skipping fuzzing for this request.',
                fg=typer.colors.RED
            ))
            return
        self.original_time = response.time
        self.original_header_size = len(response.header)
        self.original_data_size = len(response.data)

        self._write_request_response(
            parameter_index=0,
            fuzzstring_index=-1,
            request=self.request,
            response=response,
            response_type='original',
        )

        time.sleep(self.delay)

        print()
        if self.fuzz_parameters:
            self._fuzz_parameters()
        if self.fuzz_form_data:
            self._fuzz_form_data()
        if self.fuzz_json_data:
            self._fuzz_json_data()
        if self.fuzz_directories:
            self._fuzz_directories()
        if self.fuzz_cookies:
            self._fuzz_cookies()

    def _fuzz_parameters(self):
        # TODO: reduce code duplication with other _fuzz_* functions, without introducing unnecessary abstractions
        for parameter_index in range(len(self.request.url.parameters or [])):
            parameter = self.request.url.parameters[parameter_index]
            if not parameter.fuzz:
                continue

            request_copy = deepcopy(self.request)

            request_copy.disable_all_fuzzing()
            request_copy.url.parameters[parameter_index].fuzz = True

            typer.echo(
                typer.style(f'Parameter {parameter_index}', bg=typer.colors.GREEN) + ' '
                + request_copy.url.colored_url
            )
            FuzzResult.print_header()
            for rownum, (unreplaced_fuzz_string, fuzz_string) in enumerate(
                    self._payloads_with_replacements(
                        (request_copy.url.parameters[parameter_index].value or b'').decode()
                    )
            ):
                if self.skip_current_shared.value == SKIP_CURRENT_SECTION:
                    self.skip_current_shared.value = DO_NOT_SKIP
                    break
                encoded_fuzz_string = quote_plus(fuzz_string).encode()
                request_copy.url.parameters[parameter_index] = Parameter(
                    key=request_copy.url.parameters[parameter_index].key,
                    value=encoded_fuzz_string
                )
                response = self._perform_and_print_request(unreplaced_fuzz_string, request_copy, rownum)
                self._write_request_response(
                    parameter_index=parameter_index,
                    fuzzstring_index=rownum,
                    request=request_copy,
                    response=response,
                    response_type='parameter',
                )
                time.sleep(self.delay)
            print()

            self._fuzz_json_data_in_parameter(parameter_index)

    def _write_request_response(
            self,
            parameter_index: int,
            fuzzstring_index: int,
            request: Request,
            response: Optional[Response],
            response_type: str,
    ):
        folder = Path(os.path.join(
            self.output_directory,
            f'{response_type}_{parameter_index:04}',
        ))
        folder.mkdir(exist_ok=True, parents=True)
        with open(os.path.join(folder, f'fuzzstring_{fuzzstring_index:04}.txt'), 'wb') as f:
            f.write(request.recreate())
            f.write(b'\n')
            if response is not None:
                f.write(response.response)

    def _perform_and_print_request(
            self,
            fuzz_string: str,
            request_copy: Request,
            rownum: int,
    ) -> Optional[Response]:
        # TODO: allow connection to stay open to reduce server overhead and stay true to the original request
        request_copy.header = re.sub(
            br'connection: keep-alive' + _NEWLINE,
            br'connection: close' + _NEWLINE,
            request_copy.header,
            flags=re.MULTILINE | re.IGNORECASE
        )
        request_copy.header = re.sub(
            br'keep-alive: .*?' + _NEWLINE,
            b'',
            request_copy.header,
            flags=re.MULTILINE | re.IGNORECASE
        )

        try:
            response = Response.from_request(request_copy)
        except (
                ConnectionRefusedError,
                ConnectionError,
                ConnectionResetError,
                ConnectionAbortedError,
        ) as e:
            typer.echo(''.join([
                f'{rownum} ',
                typer.style('ERROR FOR PAYLOAD ', fg=typer.colors.RED),
                f'{fuzz_string} ',
                typer.style('WITH MESSAGE: ', fg=typer.colors.RED),
                f'{e}'
            ]))
            return

        result = FuzzResult(
            row_number=rownum,
            response=response,
            fuzz_string=fuzz_string,
            original_time=self.original_time,
            original_header_size=self.original_header_size,
            original_data_size=self.original_data_size,
        )
        result.print()
        return response

    def _fuzz_cookies(self):
        # TODO: reduce code duplication with other _fuzz_* functions, without introducing unnecessary abstractions
        for cookie_index in range(len(self.request.cookies or [])):
            cookie = self.request.cookies[cookie_index]
            if not cookie.fuzz:
                continue

            request_copy = deepcopy(self.request)

            typer.echo(
                typer.style(f'Cookie {cookie_index}', bg=typer.colors.BLUE) + ' '
                + cookie.key.decode() + _EQUALS.decode()
                + typer.style(
                    (cookie.value or b'').decode(),
                    bg=typer.colors.BLUE
                )
            )
            FuzzResult.print_header()
            for rownum, (unreplaced_fuzz_string, fuzz_string) in enumerate(
                    self._payloads_with_replacements(
                        (request_copy.cookies[cookie_index].value or b'').decode()
                    )
            ):
                if self.skip_current_shared.value == SKIP_CURRENT_SECTION:
                    self.skip_current_shared.value = DO_NOT_SKIP
                    break
                encoded_fuzz_string = quote_plus(fuzz_string).encode()
                request_copy.cookies[cookie_index] = Cookie(
                    key=request_copy.cookies[cookie_index].key,
                    value=encoded_fuzz_string
                )
                response = self._perform_and_print_request(unreplaced_fuzz_string, request_copy, rownum)
                self._write_request_response(
                    parameter_index=cookie_index,
                    fuzzstring_index=rownum,
                    request=request_copy,
                    response=response,
                    response_type='cookie',
                )
                time.sleep(self.delay)
            print()

            self._fuzz_json_data_in_cookie(cookie_index)

    def _fuzz_form_data(self):
        # TODO: reduce code duplication with other _fuzz_* functions, without introducing unnecessary abstractions
        for form_data_index in range(len(self.request.form_data or [])):
            form_data = self.request.form_data[form_data_index]
            if not form_data.fuzz:
                continue

            request_copy = deepcopy(self.request)

            typer.echo(
                typer.style(f'Form data {form_data_index}', bg=typer.colors.RED) + ' '
                + form_data.key.decode() + _EQUALS.decode()
                + typer.style(
                    (form_data.value or b'').decode(),
                    bg=typer.colors.RED
                )
            )
            FuzzResult.print_header()
            for rownum, (unreplaced_fuzz_string, fuzz_string) in enumerate(
                    self._payloads_with_replacements(
                        (request_copy.form_data[form_data_index].value or b'').decode()
                    )
            ):
                if self.skip_current_shared.value == SKIP_CURRENT_SECTION:
                    self.skip_current_shared.value = DO_NOT_SKIP
                    break
                encoded_fuzz_string = quote_plus(fuzz_string).encode()
                request_copy.form_data[form_data_index] = FormData(
                    key=request_copy.form_data[form_data_index].key,
                    value=encoded_fuzz_string
                )
                response = self._perform_and_print_request(unreplaced_fuzz_string, request_copy, rownum)
                self._write_request_response(
                    parameter_index=form_data_index,
                    fuzzstring_index=rownum,
                    request=request_copy,
                    response=response,
                    response_type='form_data',
                )
                time.sleep(self.delay)
            print()

    def _fuzz_json_data(self):
        # TODO: reduce code duplication with other _fuzz_* functions, without introducing unnecessary abstractions
        for json_data_index in range(len(
                self.request.json_data.json_nodes
                if self.request.json_data else []
        )):
            json_data = self.request.json_data.json_nodes[json_data_index]
            if not json_data.fuzz:
                continue

            request_copy = deepcopy(self.request)

            typer.echo(
                typer.style(f'JSON data {json_data_index}', bg=typer.colors.RED) + ' ' + str(json_data)
            )
            FuzzResult.print_header()
            for rownum, (unreplaced_fuzz_string, fuzz_string) in enumerate(
                    self._payloads_with_replacements(
                        str(request_copy.json_data.json_nodes[json_data_index].keys[-1].key or '')
                        # TODO: handle other types than string as key
                    )
            ):
                if self.skip_current_shared.value == SKIP_CURRENT_SECTION:
                    self.skip_current_shared.value = DO_NOT_SKIP
                    break
                request_copy.json_data.json_nodes[json_data_index].keys[-1].key = fuzz_string
                response = self._perform_and_print_request(unreplaced_fuzz_string, request_copy, rownum)
                self._write_request_response(
                    parameter_index=json_data_index,
                    fuzzstring_index=rownum,
                    request=request_copy,
                    response=response,
                    response_type='json_data',
                )
                time.sleep(self.delay)
            print()

    def _fuzz_json_data_in_parameter(
            self,
            parameter_index
    ):
        # TODO: reduce code duplication with other _fuzz_* functions, without introducing unnecessary abstractions
        for json_data_index in range(len(
                self.request.url.parameters[parameter_index].json_in_base64.json_nodes
                if self.request.url.parameters[parameter_index].json_in_base64 else []
        )):
            json_data = self.request.url.parameters[parameter_index].json_in_base64.json_nodes[json_data_index]
            if not json_data.fuzz:
                continue

            request_copy = deepcopy(self.request)

            typer.echo(
                typer.style(f'JSON in parameter {json_data_index}', bg=typer.colors.GREEN) + ' '
                + request_copy.url.colored_url
            )
            typer.echo(
                '-> base64 -> ' + typer.style('JSON data', bg=typer.colors.RED) + ' ' + str(json_data)
            )
            FuzzResult.print_header()
            for rownum, (unreplaced_fuzz_string, fuzz_string) in enumerate(
                    self._payloads_with_replacements(str(
                        request_copy.url.parameters[
                            parameter_index
                        ].json_in_base64.json_nodes[
                            json_data_index
                        ].keys[-1].key or ''
                        # TODO: handle other types than string as key
                    ))
            ):
                if self.skip_current_shared.value == SKIP_CURRENT_SECTION:
                    self.skip_current_shared.value = DO_NOT_SKIP
                    break
                request_copy.url.parameters[
                    parameter_index
                ].json_in_base64.json_nodes[
                    json_data_index
                ].keys[-1].key = fuzz_string
                request_copy.url.parameters[parameter_index].update_value_based_on_json_in_base64()
                response = self._perform_and_print_request(unreplaced_fuzz_string, request_copy, rownum)
                self._write_request_response(
                    parameter_index=json_data_index,
                    fuzzstring_index=rownum,
                    request=request_copy,
                    response=response,
                    response_type='json_data_in_parameter',
                )
                time.sleep(self.delay)
            print()

    def _fuzz_json_data_in_cookie(
            self,
            cookie_index
    ):
        # TODO: reduce code duplication with other _fuzz_* functions, without introducing unnecessary abstractions
        for json_data_index in range(len(
                self.request.cookies[cookie_index].json_in_base64.json_nodes
                if self.request.cookies[cookie_index].json_in_base64 else []
        )):
            json_data = self.request.cookies[cookie_index].json_in_base64.json_nodes[json_data_index]
            if not json_data.fuzz:
                continue

            request_copy = deepcopy(self.request)

            typer.echo(
                typer.style(f'JSON in cookie {json_data_index}', bg=typer.colors.BLUE) + ' '
                + self.request.cookies[cookie_index].key.decode() + _EQUALS.decode()
                + typer.style(
                    (self.request.cookies[cookie_index].value or b'').decode(),
                    bg=typer.colors.BLUE
                )
            )
            typer.echo(
                '-> base64 -> ' + typer.style('JSON data', bg=typer.colors.RED) + ' ' + str(json_data)
            )
            FuzzResult.print_header()
            for rownum, (unreplaced_fuzz_string, fuzz_string) in enumerate(
                    self._payloads_with_replacements(str(
                        request_copy.cookies[
                            cookie_index
                        ].json_in_base64.json_nodes[
                            json_data_index
                        ].keys[-1].key or ''
                        # TODO: handle other types than string as key
                    ))
            ):
                if self.skip_current_shared.value == SKIP_CURRENT_SECTION:
                    self.skip_current_shared.value = DO_NOT_SKIP
                    break
                request_copy.cookies[
                    cookie_index
                ].json_in_base64.json_nodes[
                    json_data_index
                ].keys[-1].key = fuzz_string
                request_copy.cookies[cookie_index].update_value_based_on_json_in_base64()
                response = self._perform_and_print_request(unreplaced_fuzz_string, request_copy, rownum)
                self._write_request_response(
                    parameter_index=json_data_index,
                    fuzzstring_index=rownum,
                    request=request_copy,
                    response=response,
                    response_type='json_data_in_cookie',
                )
                time.sleep(self.delay)
            print()

    def _fuzz_directories(self):
        # TODO: reduce code duplication with other _fuzz_* functions, without introducing unnecessary abstractions
        for directory_index in reversed(range(len(self.request.url.directories or []))):
            directory = self.request.url.directories[directory_index]
            if not directory.fuzz:
                continue

            request_copy = deepcopy(self.request)

            request_copy.disable_all_fuzzing()
            request_copy.url.directories[directory_index].fuzz = True

            typer.echo(
                typer.style(f'Directory {directory_index}', bg=typer.colors.YELLOW) + ' '
                + request_copy.url.colored_url
            )
            FuzzResult.print_header()
            for rownum, (unreplaced_fuzz_string, fuzz_string) in enumerate(
                        self._payloads_with_replacements(
                            (request_copy.url.directories[directory_index] or b'').decode()
                        )
            ):
                if self.skip_current_shared.value == SKIP_CURRENT_SECTION:
                    self.skip_current_shared.value = DO_NOT_SKIP
                    break
                encoded_fuzz_string = quote(fuzz_string).encode()
                request_copy.url.directories[directory_index] = Directory(encoded_fuzz_string)
                response = self._perform_and_print_request(unreplaced_fuzz_string, request_copy, rownum)
                self._write_request_response(
                    parameter_index=directory_index,
                    fuzzstring_index=rownum,
                    request=request_copy,
                    response=response,
                    response_type='directory',
                )
                time.sleep(self.delay)
            print()

    def _payloads_with_replacements(self, original_value: str) -> List[Tuple[str, str]]:
        return list(zip(
            self.payloads,
            [
                hex_replacements(
                    payload
                ).replace(
                    _ORIGINAL_PAYLOAD_MARKER,
                    original_value
                )
                for payload in self.payloads
            ]
        ))

    @classmethod
    def from_file(
            cls,
            request: Request,
            filename: Path,
            output_directory: Path,
            fuzz_directories: bool,
            fuzz_parameters: bool,
            fuzz_cookies: bool,
            fuzz_form_data: bool,
            fuzz_json_data: bool,
            delay: float,
            skip_current_shared: Value,
    ) -> 'Fuzzer':
        """
        Loads payloads from a file ``filename`` and returns a ``Fuzzer`` object.
        Besides ``filename``, ``from_file`` takes the same parameters as the ``Fuzzer`` class.
        """
        with open(filename, 'rb') as f:
            payloads = [
                payload.decode() for payload in f.read().splitlines()
            ]
            return Fuzzer(
                request,
                payloads,
                output_directory=output_directory,
                fuzz_directories=fuzz_directories,
                fuzz_parameters=fuzz_parameters,
                fuzz_cookies=fuzz_cookies,
                fuzz_form_data=fuzz_form_data,
                fuzz_json_data=fuzz_json_data,
                delay=delay,
                skip_current_shared=skip_current_shared,
            )
