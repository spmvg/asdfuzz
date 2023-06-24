import unittest

from parameterized import parameterized
from asdfuzz.fuzzing.hex_replacements import hex_replacements, inverse_hex_replacements

before_after = [
    ('no_replacement', 'no_replacement'),
    ('<hex00>', '\x00'),
    ('<hex0a>', '\x0a'),
    ('<hex0d>', '\x0d'),
]


class TestHexReplacements(unittest.TestCase):
    @parameterized.expand(before_after)
    def test_hex_replacements(self, before, after):
        self.assertEqual(
            after,
            hex_replacements(before),
        )

    @parameterized.expand(before_after)
    def test_inverse_hex_replacements(self, after, before):
        self.assertEqual(
            after,
            inverse_hex_replacements(before),
        )
