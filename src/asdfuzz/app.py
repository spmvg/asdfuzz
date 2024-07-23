"""
Entrypoint of the `typer` app.
See the documentation in the `help` sections of every parameter for more information, or run ``python -m asdfuzz --help``.
"""
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from multiprocessing import Value
from pathlib import Path
from typing import Optional, List

import keyboard
import typer

from asdfuzz.fuzzing.fuzzer import Fuzzer, DO_NOT_SKIP
from asdfuzz.http.request import Request
from asdfuzz._utils import _raise

DEFAULT_FUZZ_FILE = os.path.join(
    Path(__file__).parent,
    'wordlists',
    'default.txt',
)

app = typer.Typer()


@dataclass
class RequestMenuItem:
    """
    Simple wrapper over a ``Request`` object. Adds a selected field.
    """
    request: Request
    """ The request that will be fuzzed if this menu item is selected. """
    selected = True
    """ Determines whether the request will be fuzzed. """


_proceed_key = 'y'
_quit_key = 'q'
_select_all_key = 's'
_deselect_all_key = 'd'
_directories_key = 'fd'
_parameters_key = 'fp'
_cookies_key = 'fc'
_form_data_key = 'ff'
_json_data_key = 'fj'


def _display_menu(
        request_menu_items: List[RequestMenuItem],
):
    print('Select requests to fuzz:')
    typer.echo(
        typer.style(
            'ID   Cookies   Form data   JSON data   Fuzz   Request',
            fg=typer.colors.GREEN,
        )
    )
    for menu_index, menu_item in enumerate(request_menu_items):
        cookies_number = 0
        for cookie in menu_item.request.cookies or []:
            cookies_number += 1 + (len(cookie.json_in_base64.json_nodes) if cookie.json_in_base64 else 0)

        typer.echo(''.join([
            f'{menu_index}'.ljust(5),
            f'{cookies_number or "-"}'.rjust(7),
            f'{len(menu_item.request.form_data) if menu_item.request.form_data else "-"}'.rjust(12),
            f'{len(menu_item.request.json_data.json_nodes) if menu_item.request.json_data else "-"}'.rjust(12),
            '   ',
            typer.style(
                ' YES   ',
                fg=typer.colors.GREEN,
            ) if menu_item.selected else typer.style(
                '  NO   ',
                fg=typer.colors.RED,
            ),
            menu_item.request.colored_method + ' ',
            menu_item.request.url.colored_url
        ]))
    print()
    print(
        f'Commands: [{_proceed_key}] proceed, '
        f'[{_quit_key}] quit, '
        f'[{_select_all_key}] select all, '
        f'[{_deselect_all_key}] deselect all, '
        f'[any number] to toggle the corresponding ID'
    )
    print(
        'Toggle what will be fuzzed: '
        f'[{_directories_key}] directories, '
        f'[{_parameters_key}] parameters, '
        f'[{_cookies_key}] cookies, '
        f'[{_form_data_key}] form data, '
        f'[{_json_data_key}] JSON data'
    )


def _bool_as_str(boolean):
    return typer.style('YES', fg=typer.colors.GREEN) if boolean else typer.style(' NO', fg=typer.colors.RED)


def main(
        filename: Optional[Path] = typer.Option(
            None, help='File containing a single HTTP request to fuzz in raw HTTP format.',
        ),
        zap_export: Optional[Path] = typer.Option(
            None, help='File containing one or multiple HTTP requests to fuzz in OWASP ZAP message export format.'
        ),
        fetch_nodejs: Optional[Path] = typer.Option(
            None, help=(
                'File containing a single HTTP request to fuzz in "Copy as fetch (Node.js)" format from Chrome '
                'DevTools.'
            )
        ),
        wordlist_file: Optional[Path] = typer.Option(
            None, help=(
                'File containing the wordlist used for fuzzing. A default wordlist is used if this parameter is empty. '
                'In the wordlist, use template <original> to refer dynamically to the value in the original request.'
            ),
        ),
        port: int = typer.Option(
            443, help='Port used for the connection.'
        ),
        https: bool = typer.Option(
            True, help='Use HTTPS.'
        ),
        filter_hostname_endswith: Optional[str] = typer.Option(
            None, help='Only keep requests ending with this hostname.'
        ),
        delay_seconds: float = typer.Option(
            0, help='Seconds of delay between requests.'
        ),
        directories: bool = typer.Option(
            True, help='Fuzz directories in the URL.'
        ),
        parameters: bool = typer.Option(
            True, help='Fuzz values of parameters in the URL.'
        ),
        cookies: bool = typer.Option(
            False, help='Fuzz the values of cookies.'
        ),
        form_data: bool = typer.Option(
            True, help='Fuzz the values of HTTP form data.'
        ),
        json_data: bool = typer.Option(
            True, help='Fuzz the values of JSON data.'
        ),
        confirmation: bool = typer.Option(
            True, help='Enter the interactive menu.'
        ),
        output_directory: Path = typer.Option(
            'asdfuzz_output', help='Directory where the fuzzed requests and responses will be stored.'
        ),
        debug: bool = typer.Option(
            False, help='Enable debug mode.'
        ),
):
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(name)s - %(message)s',
        level=logging.DEBUG if debug else logging.ERROR
    )
    logger = logging.getLogger(__name__)

    if not filename and not zap_export and not fetch_nodejs:
        _raise('Either --filename, --zap-export or --fetch-nodejs should be given.')

    if not wordlist_file:
        wordlist_file = DEFAULT_FUZZ_FILE

    requests = []
    if filename:
        logger.debug('Loading requests from file')
        requests = [Request.from_file(filename, port)]
    if zap_export:
        logger.debug('Loading requests from ZAP message export')
        requests = Request.from_zap_message_export(zap_export, port)
    if fetch_nodejs:
        logger.debug('Loading requests from Node.js fetch')
        requests = [Request.from_fetch_nodejs(fetch_nodejs, port)]

    if not https:
        for request in requests:
            request.disable_https = True
        logger.debug('Disabled HTTPS')

    if filter_hostname_endswith:
        requests_before = len(requests)
        requests = [
            request for request in requests
            if request.url.netloc.endswith(filter_hostname_endswith)
        ]
        logger.debug(f'Requests left after hostname filtering: {len(requests)} out of {requests_before}')

    requests = [
        RequestMenuItem(
            request=request
        ) for request in sorted(
            requests,
            key=lambda sortable_request: sortable_request.url.url,
        )
    ]

    while True and confirmation:
        print()
        print('The following will be fuzzed, if present:')
        typer.echo(f'    {_bool_as_str(directories).rjust(4)} Directories')
        typer.echo(f'    {_bool_as_str(parameters).rjust(4)} Parameters')
        typer.echo(f'    {_bool_as_str(cookies).rjust(4)} Cookies')
        typer.echo(f'    {_bool_as_str(form_data).rjust(4)} Form data')
        typer.echo(f'    {_bool_as_str(json_data).rjust(4)} JSON data')
        print()
        _display_menu(requests)

        print()
        response = typer.prompt('Command', default=_proceed_key)
        if response == _proceed_key:
            break
        elif response == _quit_key:
            exit()
        elif response == _select_all_key:
            for request in requests:
                request.selected = True
            continue
        elif response == _deselect_all_key:
            for request in requests:
                request.selected = False
            continue
        elif response == _directories_key:
            directories = not directories
            continue
        elif response == _parameters_key:
            parameters = not parameters
            continue
        elif response == _cookies_key:
            cookies = not cookies
            continue
        elif response == _form_data_key:
            form_data = not form_data
            continue
        elif response == _json_data_key:
            json_data = not json_data
            continue
        elif re.match(r'\d+', response):
            row_index = int(response)
            if not (0 <= row_index < len(requests)):
                continue
            requests[row_index].selected = not requests[row_index].selected

    requests = [
        request.request for request in requests if request.selected
    ]
    if not requests:
        exit()

    session_directory = datetime.utcnow().strftime('%Y-%m-%dT%H%M%S.%fZ')
    base_directory = os.path.join(output_directory, session_directory)

    skip_current_shared = Value('i', DO_NOT_SKIP)

    def set_skip(skip_current: Value = skip_current_shared):
        skip_current.value = 1

    keyboard.add_hotkey('ctrl+space', set_skip, args=tuple())
    print()
    print('Press [control]+[spacebar] to skip the rest of the current section. Press [control]+[c] to stop.')

    print()
    for request in requests:
        fuzzer = Fuzzer.from_file(
            request,
            wordlist_file,
            output_directory=base_directory,
            fuzz_directories=directories,
            fuzz_parameters=parameters,
            fuzz_cookies=cookies,
            fuzz_form_data=form_data,
            fuzz_json_data=json_data,
            delay=delay_seconds,
            skip_current_shared=skip_current_shared,
        )
        fuzzer.fuzz()
