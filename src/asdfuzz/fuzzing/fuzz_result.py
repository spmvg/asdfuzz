from dataclasses import dataclass
from typing import Optional

import typer

from asdfuzz.http.response import Response
from asdfuzz.fuzzing.hex_replacements import inverse_hex_replacements
from asdfuzz._utils import _ORIGINAL_PAYLOAD_MARKER


@dataclass
class FuzzResult:
    """
    After the fuzzer executes a request and response sequence, a ``FuzzResult`` is created, containing the response
    and utility functions for highlighting.
    """
    row_number: int
    """ Row number of the fuzz result in the current section. Will be printed. """
    response: Response
    """ HTTP response from the server. """
    fuzz_string: str
    """ String that was used for the fuzz replacement. """
    deviation_for_highlighting: float = 0.1
    """
    Relative deviation above and below which the response duration or size will be highlighted.
    A value of `0.1` indicates that the response duration or size will be highlighted if it deviates more than 10% from
    the original request.
    """
    original_time: Optional[float] = None
    """ Time in seconds of the unmodified request. """
    original_header_size: Optional[int] = None
    """ Header size of the unmodified request in bytes. """
    original_data_size: Optional[int] = None
    """ Data size of the unmodified request in bytes. """

    @staticmethod
    def print_header():
        """ Print the header that appears above every fuzzing section. """
        typer.echo('  '.join([
            typer.style('  ID', fg=typer.colors.GREEN) + '        ',
            typer.style('Payload', fg=typer.colors.GREEN),
            typer.style('Code', fg=typer.colors.GREEN) + '     ',
            typer.style('Time', fg=typer.colors.GREEN) + ' ',
            typer.style('Header (bytes)', fg=typer.colors.GREEN) + ' ',
            typer.style('Data (bytes)', fg=typer.colors.GREEN),
        ]))

    def print(self):
        """ Print the highlighted results of a single fuzz result. """
        typer.echo('  '.join([
            f'{self.row_number}'.rjust(4),
            f'{inverse_hex_replacements(self.fuzz_string).replace(_ORIGINAL_PAYLOAD_MARKER, "…")}'.rjust(15),
            ' '+typer.style(
                f'{self.response.statuscode}',
                fg=self._status_color(self.response.statuscode)
            ),
            typer.style(
                f'{int(self.response.time * 1000): 6d} ms',
                fg=self._time_color(self.response.time)
            ),
            typer.style(
                f'{len(self.response.header): 15d}',
                fg=self._header_color(len(self.response.header))
            ),
            typer.style(
                f'{len(self.response.data): 13d}',
                fg=self._data_color(len(self.response.data))
            ),
        ]))

    def _time_color(self, time):
        if self.original_time is None:
            return
        if time < self.original_time * (1-self.deviation_for_highlighting):
            return typer.colors.BRIGHT_GREEN
        if time > self.original_time * (1+self.deviation_for_highlighting):
            return typer.colors.BRIGHT_RED

    def _header_color(self, header_size):
        if self.original_header_size is None:
            return
        if header_size < self.original_header_size * (1-self.deviation_for_highlighting):
            return typer.colors.BRIGHT_GREEN
        if header_size > self.original_header_size * (1+self.deviation_for_highlighting):
            return typer.colors.BRIGHT_RED

    def _data_color(self, data_size):
        if self.original_data_size is None:
            return
        if data_size < self.original_data_size * (1-self.deviation_for_highlighting):
            return typer.colors.BRIGHT_GREEN
        if data_size > self.original_data_size * (1+self.deviation_for_highlighting):
            return typer.colors.BRIGHT_RED

    @staticmethod
    def _status_color(statuscode):
        if statuscode < 200:
            return
        if statuscode < 300:
            return typer.colors.BRIGHT_YELLOW
        if statuscode < 400:
            return typer.colors.BRIGHT_GREEN
        if statuscode < 500:
            return typer.colors.BRIGHT_BLUE
        else:
            return typer.colors.BRIGHT_RED
