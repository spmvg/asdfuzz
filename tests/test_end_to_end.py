import os
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from parameterized import parameterized

from asdfuzz.app import main

# relative imports of test data
from get_request_json_in_base64_call_args import get_request_json_in_base64_call_args
from post_json_request_call_args import post_json_request_call_args
from post_request_weird_post_data_call_args import post_request_weird_post_data_call_args
from get_request_with_fragment_call_args import get_request_with_fragment_call_args


class EndToEndTest(unittest.TestCase):
    @parameterized.expand([
        (
            os.path.join(
                Path(__file__).parent,
                'get_request_json_in_base64.txt'
            ),
            get_request_json_in_base64_call_args
        ),
        (
            os.path.join(
                Path(__file__).parent,
                'post_json_request.txt'
            ),
            post_json_request_call_args
        ),
        (
            os.path.join(
                Path(__file__).parent,
                'post_request_weird_post_data.txt'
            ),
            post_request_weird_post_data_call_args
        ),
        (
            os.path.join(
                Path(__file__).parent,
                'get_request_with_fragment.txt'
            ),
            get_request_with_fragment_call_args
        ),
    ])
    @patch('ssl.create_default_context')
    @patch('socket.create_connection')
    def test_get_request(self, input_file, expected_calls, create_connection, create_default_context):
        ssock = MagicMock()
        ssock.sendall = MagicMock()
        ssock.recv.side_effect = [
            b'HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n',
            b''
        ] * 10000
        create_default_context.return_value.wrap_socket.return_value.__enter__.return_value = ssock

        main(
            filename=input_file,  # have to give all options because we don't have typer handling the typer.Option
            zap_export=None,
            fetch_nodejs=None,
            wordlist_file=None,
            port=443,
            https=True,
            filter_hostname_endswith=None,
            delay_seconds=0,
            directories=True,
            parameters=True,
            cookies=True,
            form_data=True,
            json_data=True,
            confirmation=False,
            output_directory='asdfuzz_output',
            debug=False,
        )

        call_args = [
            call[0] for call in ssock.sendall.call_args_list
        ]
        if call_args != expected_calls:
            print(call_args)
        self.assertEqual(
            expected_calls,
            call_args
        )
