from dataclasses import dataclass
from typing import Optional

from asdfuzz.http.json_data import JSONData
from asdfuzz._utils import _get_json_from_base64_urlencoded, _to_json_base64_urlencoded


@dataclass
class Cookie:
    """ A cookie in a HTTP header. """
    key: bytes
    """ The key of the cookie (part before the equals-sign). """
    value: Optional[bytes]
    """ The value of the cookie (part after the equals-sign). Can be empty. """
    fuzz = True
    """ Whether to fuzz this cookie. """

    def __post_init__(self):
        self.json_in_base64: Optional[JSONData] = None
        json_string = _get_json_from_base64_urlencoded(self.value.decode()) if self.value else None
        if json_string:
            self.json_in_base64 = JSONData(json_string)

    def update_value_based_on_json_in_base64(self):
        """
        Base64-urlencoded JSON data in the cookie can be fuzzed by modifying the ``json_in_base64`` parameter.
        After updating ``json_in_base64``, call ``update_value_based_on_json_in_base64`` to reflect the JSON data in the
        ``value`` parameter.
        """
        if not self.json_in_base64:
            return
        self.value = _to_json_base64_urlencoded(self.json_in_base64.to_json()).encode()
