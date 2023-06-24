"""
To provide a file with payloads, several characters such as carriage return and line feed have to be special characters.
In order to be able to fuzz special characters, they must be written in brackets.
For example: in a payload string, the value `<hex00>` indicates the null byte.

Supported replacements:

* `<hex00>`: null byte
* `<hex0a>`: line feed
* `<hex0d>`: carriage return
"""

_hex_replacements = {
    '<hex00>': '\x00',
    '<hex0a>': '\x0a',
    '<hex0d>': '\x0d',
}
_inverse_hex_replacements = {
    value: key for key, value in _hex_replacements.items()
}


def hex_replacements(
        payload,
):
    """ Replace bracket notation such as `<hex00>` with the actual strings in the payload. """
    for before, after in _hex_replacements.items():
        payload = payload.replace(before, after)
    return payload


def inverse_hex_replacements(
        payload,
):
    """ Replace actual strings with bracket notation such as `<hex00>` in the payload. """
    for before, after in _inverse_hex_replacements.items():
        payload = payload.replace(before, after)
    return payload
