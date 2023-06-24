"""
This file contains functions that are used internally throughout the package.
The implementations might change, even in minor versions.
Do not rely on these functions outside of this package.
"""

import base64
import json
from typing import Optional, Tuple
from urllib.parse import unquote_plus, quote_plus

import typer


def _pre_post(bytestring: bytes, separator: bytes) -> Tuple[bytes, bytes]:
    """
    Splits a bytestring into 2 sections: the part before and the part after the separator.
    If there is no part after the separator, ``None`` will be returned as the second return value.
    """
    pre_fragment = bytestring.split(separator)[0]
    post_fragment_parts = bytestring.split(separator)[1:]  # possibly multiple hashtags, but those are all 1 fragment
    post_fragment = separator.join(post_fragment_parts) if post_fragment_parts else None
    return pre_fragment, post_fragment


def _raise(message):
    """ Simple wrapper over ``typer.Abort()``, adding a message for the user. """
    typer.echo(typer.style(message, fg=typer.colors.RED))
    raise typer.Abort()


def _get_header(request: bytes) -> bytes:
    """ Returns the header section of a HTTP request. """
    return request.split(2 * _NEWLINE)[0]


def _get_data(request: bytes) -> bytes:
    """ Returns the data section of a HTTP request. """
    newline_index = request.index(2 * _NEWLINE)
    return request[newline_index + len(2 * _NEWLINE):]


def _get_json_from_base64_urlencoded(
        json_in_base64_in_url: str,
) -> Optional[str]:
    """
    Given base64-URL encoded JSON ``json_in_base64_in_url``, returns the original JSON.
    If decoding fails, ``None`` is returned.
    """
    json_in_base64_encoding = unquote_plus(json_in_base64_in_url) + '==='

    try:
        json_bytestring = base64.b64decode(json_in_base64_encoding)
    except ValueError:
        try:
            json_bytestring = base64.b64decode(  # RFC4648
                json_in_base64_encoding.replace(
                    '-',
                    '+'
                ).replace(
                    '_',
                    '/'
                )
            )
        except ValueError:
            return

    try:
        json_string = json_bytestring.decode()
    except UnicodeDecodeError:
        return

    try:
        json.loads(json_string)
    except json.decoder.JSONDecodeError:
        return

    return json_string


def _to_json_base64_urlencoded(
        json_string: str
) -> str:
    """ Returns a base64-URL encoded string. """
    return quote_plus(
        base64.b64encode(
            json_string.encode()
        ).replace(
            b'=',
            b''
        ).replace(
            b'+',
            b'-'
        ).replace(
            b'/',
            b'_'
        )
    )


_NEWLINE = b'\r\n'
_COOKIE_SEPARATOR = b'; '
_EQUALS = b'='
_AND = b'&'
_ORIGINAL_PAYLOAD_MARKER = '<original>'
