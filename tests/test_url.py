import unittest

import typer

from asdfuzz.http.url import URL
from parameterized import parameterized


class TestURL(unittest.TestCase):
    @parameterized.expand([
        (b'http://www.example.com',),
        (b'http://www.example.com/',),
        (b'http://www.example.com/c',),
        (b'https://www.example.com/',),
        (b'https://www.example.com/c',),
        (b'https://a.b.example.com/',),
        (b'https://a.b.example.com/c',),
        (b'/a/b?name1=value1&name2=val?ue2##asd#asd',),
        (b'/a/b?name1=value1&name2=val?ue2#',),
        (b'/a/b?name1=value1&name2=val?ue2',),
        (b'/a/b?name1=value1&&name2=val?ue2',),
        (b'/a/b?name1=value1',),
        (b'/a/b?name1=',),
        (b'/a/b?name1&name2=value2',),
        (b'/a/b?=',),
        (b'/a/b?',),
        (b'/a/b',),
        (b'/a',),
    ])
    def test_unstyle(self, url):
        unstyled_url = typer.unstyle(URL(url).colored_url).encode()
        self.assertEqual(
            url,
            unstyled_url,
        )

    @parameterized.expand([
        (b'http://www.example.com', []),
        (b'http://www.example.com/', [b'', b'']),
        (b'http://www.example.com/c', [b'', b'c']),
        (b'https://www.example.com/', [b'', b'']),
        (b'https://www.example.com/c', [b'', b'c']),
        (b'https://a.b.example.com/', [b'', b'']),
        (b'https://a.b.example.com/c', [b'', b'c']),
        (b'/a/b?name1=value1&name2=val?ue2##asd#asd', [b'', b'a', b'b']),
        (b'/a/b?name1=value1&name2=val?ue2#', [b'', b'a', b'b']),
        (b'/a/b?name1=value1', [b'', b'a', b'b']),
        (b'/a', [b'', b'a']),
        (b'', []),
    ])
    def test_directories(self, url, expected_directories):
        directories = URL(url).directories
        self.assertEqual(
            expected_directories,
            directories
        )
