from dataclasses import dataclass


@dataclass
class FormData:
    """ A single key-value pair of form data in the HTTP data section of the request. """
    key: bytes
    """ The key of the form data (part before the equals-sign) """
    value: bytes
    """ The value of the form data (part after the equals-sign) """
    fuzz = True
    """ Whether to fuzz this form data. """
