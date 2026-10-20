""" Module providing a set of utility functions for data reading and writing """
import html
import json
import pathlib
import re
import urllib.request
import datetime
import subprocess
import lzma
import os
from typing import Any, TypeAlias, Sequence
from collections.abc import Hashable

import numpy as np
import pandas
import pandas.core.frame

SPDX_DATE_PATTERN = '%Y-%m-%dT%H:%M:%SZ'
StrPath:TypeAlias = str|os.PathLike[str]

def load_text_file(path:StrPath, convert_to_absolute:bool=True, encoding:str='utf-8') -> str:
    """ Read a text file and return its contents. """
    if convert_to_absolute:
        path = absolute_path(path)
    with open(path, encoding=encoding) as f:
        fread = f.read()
    return fread

def load_binary_data(path:StrPath, convert_to_absolute:bool=True) -> bytes:
    """ Load binary data from a local file """
    if convert_to_absolute:
        path = absolute_path(path)
    with open(path, mode='rb') as f:
        fread = f.read()
    return fread

def save_text_file(
        path:StrPath,
        text:str,
        convert_to_absolute:bool=True,
        mode:str='w',
        encoding:str='utf-8'
    ) -> None:
    """ Write the specified text to a text file. """
    if convert_to_absolute:
        path = absolute_path(path)
    with open(path, mode=mode, encoding=encoding) as f:
        f.write(text)

def save_binary_data(path:StrPath, data:bytes, convert_to_absolute:bool=True):
    """ Save binary data as a local file """
    if convert_to_absolute:
        path = absolute_path(path)
    with open(path, mode='wb') as f:
        f.write(data)

def make_dir(path:StrPath, convert_to_absolute:bool=True) -> None:
    """ Create the specified directory. """
    if convert_to_absolute:
        path = absolute_path(path)
    if not exists(path):
        pathlib.Path(path).mkdir()

def delete_file(path:StrPath, convert_to_absolute:bool=True) -> None:
    """ Delete file. """
    if convert_to_absolute:
        path = absolute_path(path)
    pathlib.Path(path).unlink(missing_ok=True)

def download_binarydata(url:str) -> bytes:
    """ Get binary text of a web page from the specified URL. """
    binary_data:bytes
    with urllib.request.urlopen(url) as web_file:
        binary_data = web_file.read()
    return binary_data

def extract_xzfile(binary_data:bytes) -> str:
    """ Extract xz file binary data (lzma) to string data """
    return lzma.decompress(binary_data).decode()

def download_html(
        url:str,
        *,
        unescape:bool=True,
        additional_headers:dict[str, str]|None=None
    ) -> str:
    """ Get the text of a web page from the specified URL. """
    headers = {
        'User-Agent':   'Mozilla/5.0 (Windows NT 6.1; WOW64) '
                        'AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/56.0.2924.76 Safari/537.36'
    }
    if additional_headers is not None:
        headers = {**headers, **additional_headers}
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request) as response:
        htmltext = response.read()
    text = htmltext.decode('utf-8')
    if unescape:
        text = html.unescape(text)
    return text

def jsontext_to_dict(jsontext:str, json_decoder=json.JSONDecoder) -> dict:
    """ Convert JSON-formatted text to a dictionary. """
    if jsontext is None or jsontext == "":
        return {}
    return json.loads(jsontext, cls=json_decoder)

def dict_to_jsontext(dictionary:dict, json_encoder=json.JSONEncoder) -> str:
    """ Convert a dictionary to JSON-formatted text. """
    return json.dumps(dictionary, ensure_ascii=False, indent=2, cls=json_encoder)

def absolute_path(path:StrPath) -> pathlib.Path:
    """ Get the absolute path from this Python file. """
    path_from_file = pathlib.Path(__file__).resolve().parents[1] / pathlib.Path(path)
    return path_from_file

def is_absolute(path:StrPath) -> bool:
    """ Check if the path is an absolute path. """
    return pathlib.Path(path).is_absolute()

def exists(path:StrPath, convert_to_absolute:bool=True) -> bool:
    """ Check if the path exists. """
    if convert_to_absolute:
        path = absolute_path(path)
    return pathlib.Path(path).exists()

def join_path(*args:StrPath) -> pathlib.Path:
    """ Combines paths and returns it as a pahtlib.Path object """
    joined_path = pathlib.Path(args[0])
    for path in args[1:]:
        joined_path = joined_path / path
    return joined_path

def get_suffix(path:StrPath) -> str:
    """
    Get an suffix of the path. No period.
    An empty string will return if the path doesn't have any suffix.
    """
    return pathlib.Path(path).suffix[1:]

def parse_list_with_colon(list_text:str) -> dict[str, str]:
    """
    Parse a list to a dictionary. The list should be like follows:

    xx: hoge
    yy: huga
        huga

    In this case, this function will return a dictionary like:

    {'xx': 'hoge', 'yy': 'huga\nhuga'}
    """
    ret_dict = {'additionalInfo':''}
    key = 'additionalInfo'
    for line in list_text.split('\n'):
        if re.match(r'[^ ]*: ', line):
            key, value = line.split(": ", maxsplit=1)
            ret_dict[key] = value
        else:
            ret_dict[key] += ' ' + line
    return ret_dict

def datetime_to_spdx_date_pattern(dt: datetime.datetime) -> str:
    """Convert from `datetime.datetime` to SPDX-formatted date string."""
    return dt.strftime(SPDX_DATE_PATTERN)

def timestamp(filename:StrPath, convert_to_absolute:bool=True) -> str:
    """ Get timestamp of the file. """
    if convert_to_absolute:
        filename = absolute_path(filename)
    stat_acquire = pathlib.Path(filename).stat()
    dt_acquire = datetime.datetime.fromtimestamp(stat_acquire.st_mtime)
    return datetime_to_spdx_date_pattern(dt_acquire)

def today_spdx_date_pattern() -> str:
    """ Get a string representing the current time in the format specified by spdx. """
    now = datetime.datetime.now(datetime.timezone.utc)
    return datetime_to_spdx_date_pattern(now)

def diff_spdx_format_date(target_date:str, base_date:str) -> int:
    """ Returns the difference in seconds between two SPDX-formatted date strings """
    target_unix = spdx_date_pattern_to_unixtime(target_date)
    base_unix   = spdx_date_pattern_to_unixtime(base_date)
    return target_unix - base_unix

def spdx_date_pattern_to_unixtime(time_spdx:str) -> int:
    """ Convert SPDX-formattted string into UNIX time """
    dt_local = datetime.datetime.strptime(time_spdx, SPDX_DATE_PATTERN)
    dt_utc = dt_local.replace(tzinfo=datetime.timezone.utc)
    return int(dt_utc.timestamp())

def elapsed_time_second(filename:StrPath, convert_to_absolute:bool=True) -> int:
    """ Get the elapsed time in seconds since the file was created """
    file_date = timestamp(filename, convert_to_absolute=convert_to_absolute)
    elapsed_sec = diff_spdx_format_date(file_date, today_spdx_date_pattern())
    return elapsed_sec

def run_command(*parameters:str) -> str:
    """ Run commnads. """
    return subprocess.run(
        [param for param in parameters],
        capture_output=True,
        text=True,
        check=False
    ).stdout

def xlsx_to_dict(
        filepath:StrPath,
        *,
        sheet_name:str|list[str]|None = None,
        header:int|Sequence[int]|None = 0,
        index_col:int|Sequence[int]|None = None,
        replace_nan:bool = True,
        dropna:bool = True
    ) -> dict[str, dict[Hashable, Any]]:
    """ Load xlsx file and convert to dict object """

    if isinstance(sheet_name, str):
        sheets:dict[str, pandas.core.frame.DataFrame] = {
            sheet_name: pandas.read_excel(
                filepath, sheet_name=sheet_name, header=header, index_col=index_col
            )
        }
    else:
        sheets:dict[str, pandas.core.frame.DataFrame] = pandas.read_excel(
            filepath, sheet_name=sheet_name, header=header, index_col=index_col
        )
    converted_dict: dict[str, dict[Hashable, Any]] = {}
    for sheet_name, sheet in sheets.items():
        if replace_nan:
            sheet = sheet.replace(np.nan, None)
        if dropna:
            sheet = sheet.dropna(how='all')
        converted_dict[sheet_name] = sheet.to_dict(orient='index')

    return converted_dict
