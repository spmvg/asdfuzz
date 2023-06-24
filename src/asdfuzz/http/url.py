from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

import typer

from asdfuzz.http.directory import Directory
from asdfuzz.http.parameter import Parameter
from asdfuzz._utils import _pre_post, _EQUALS, _AND


@dataclass
class URL:
    """
    A URL in the request.
    Several properties, such as parameters and directories, are derived upon initialization.
    """
    url: bytes
    """ The raw URL in the request. """
    slash = b'/'
    hashtag = b'#'
    question = b'?'

    def __post_init__(self):
        parsed = urlparse(self.url.decode())
        self.netloc: str = parsed.netloc
        self.scheme: str = parsed.scheme
        start_of_rest_of_url_index = (
            (len(self.scheme) + len(':') if self.scheme else 0)
            + (len('//') + len(self.netloc) if self.netloc else 0)
        )
        rest_of_url = self.url[start_of_rest_of_url_index:]

        pre_fragment, fragment = _pre_post(rest_of_url, self.hashtag)
        self.fragment: Optional[bytes] = fragment
        pre_question_mark, post_question_mark = _pre_post(pre_fragment, self.question)

        self.parameters: List[Parameter] = [
            Parameter(key, value) for key, value in [
                _pre_post(key_value, _EQUALS) for key_value in post_question_mark.split(_AND)
            ]
        ] if post_question_mark is not None else None

        directories = []
        if pre_question_mark:
            directories = [Directory(directory) for directory in pre_question_mark.split(self.slash)]
            directories[0].fuzz = False  # the first part before the slash is always empty: so don't fuzz
        self.directories: List[Directory] = directories

    @property
    def colored_url(self) -> str:
        """ Printable and colored representation of the URL. """
        # str instead of bytes, since the URL should be UTF-8 decodable and typer works with strings
        colored_url = ''

        scheme_and_netloc = (
            (self.scheme + ':' if self.scheme else '')
            + ('//' + self.netloc if self.netloc else '')
        )
        colored_url += scheme_and_netloc

        colored_path = self.slash.decode().join([
            typer.style(directory.decode(), bg=typer.colors.CYAN if directory.fuzz else None)
            for directory in self.directories
        ])
        colored_url += colored_path

        if self.parameters is not None:
            colored_url += self.question.decode() + _AND.decode().join(
                parameter.key.decode() if parameter.value is None  # result of _pre_post if there is no equals sign at all
                else (
                        parameter.key.decode()
                        + _EQUALS.decode()
                        + typer.style(
                        parameter.value.decode(),
                        bg=typer.colors.GREEN if parameter.fuzz else None
                    )
                )
                for parameter in self.parameters
            )

        if self.fragment is not None:
            colored_url += (self.hashtag + self.fragment).decode()

        return colored_url

    def disable_all_fuzzing(self):
        """ When called, disables all fuzzing in the URL. """
        for directory in self.directories or []:
            directory.fuzz = False
        for parameter in self.parameters or []:
            parameter.fuzz = False
