import unittest

from asdfuzz._utils import _get_json_from_base64_urlencoded, _to_json_base64_urlencoded
from parameterized import parameterized


class TestUtils(unittest.TestCase):
    @parameterized.expand([
        ('not@base64', None),
        ('eyIxIjogMn0%3d', '{"1": 2}'),
        ('eyIxIjogMn0%3D', '{"1": 2}'),
        ('eyIxIjogMn0', '{"1": 2}'),
        ('bm90X2pzb24%3d', None),  # not json
        ('nA%3d%3d', None),  # not UTF-8
    ])
    def test_get_json_from_base64_urlencoded(self, json_in_base64, expected_result):
        result = _get_json_from_base64_urlencoded(json_in_base64)
        self.assertEqual(
            expected_result,
            result
        )

    @parameterized.expand([
        ('eyIxIjogMn0', '{"1": 2}'),
    ])
    def test_to_json_base64_urlencoded(self, expected_result, json_string):
        self.assertEqual(
            expected_result,
            _to_json_base64_urlencoded(json_string)
        )
