""" Module getting information from pypi. """

import urllib.error
from typing import Any

from . import file_io

_BASE_URL = 'https://pypi.org'
_SIMPLE_API_HEADER = {'Accept': 'application/vnd.pypi.simple.v1+json'}
_JSON_API_HEADER   = {'Accept': 'application/json'}

def list_all_projects() -> list[str]:
    """ List all package names in pypi.
        Refer: https://docs.pypi.org/api/index-api/
    """
    url = f'{_BASE_URL}/simple/'
    json_text = file_io.download_html(url, additional_headers=_SIMPLE_API_HEADER, unescape=False)
    index = file_io.jsontext_to_dict(json_text)
    projects = index['projects']
    return [pkg['name'] for pkg in projects]

def get_distributions_for_project(project_name:str) -> dict[str, Any]|None:
    """ Get all of the distribution download URLs.
        Refer: https://docs.pypi.org/api/index-api/
    """
    url = f'{_BASE_URL}/simple/{project_name}/'
    try:
        json_text = file_io.download_html(url, additional_headers=_SIMPLE_API_HEADER, unescape=False)
    except urllib.error.HTTPError:
        return None
    index = file_io.jsontext_to_dict(json_text)
    return index

def get_project(project_name:str, *, version:str|None=None) -> dict[str, Any]|None:
    """ Get details of the project. Metadata, a list of all releases, URLs.
        Refer: https://docs.pypi.org/api/json/
    """
    url = f"{_BASE_URL}/pypi/{project_name}/{(version + '/') if version is not None else ''}json"
    try:
        json_text = file_io.download_html(url, additional_headers=_JSON_API_HEADER, unescape=False)
    except urllib.error.HTTPError:
        return None
    dict_package = file_io.jsontext_to_dict(json_text)
    return dict_package

def get_release(project_name:str, version:str) -> dict[str, Any]|None:
    """ Get metadata about an individual release at a specific version.
        Refer: https://docs.pypi.org/api/json/
    """
    return get_project(project_name, version=version)
