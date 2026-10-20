""" Module getting information from npm. """
# REF: https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
# NOTE: There's no official API to get the whole packages in npm
#       There's an unofficial project https://replicate.npmjs.com/_all_docs
#       but this takes a long time to download

import urllib.error
from typing import Any

from . import file_io

BASE_URL = 'https://registry.npmjs.org'

def get_package(package_name:str) -> dict[str, Any]|None:
    """Get npm package information

    Args:
        package_name (str): name of the package

    Returns:
        Dict[str, Any]: package information.
        Refer: https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md#Package
    """
    url = f'{BASE_URL}/{package_name}'
    try:
        json_text = file_io.download_html(url, unescape=False)
    except urllib.error.HTTPError as e:
        json_text = e.read().decode('utf-8')
    dict_pkg = file_io.jsontext_to_dict(json_text)
    if 'name' not in dict_pkg:
        return None
    else:
        return dict_pkg

def search_projects(text:str, *, size:int=20) -> dict[str, Any]:
    """Search npm projects

    Args:
        `text` (`str`): full-text search to apply
        `size` (`int`): How many results should be returned. Defaults to 20.

    Returns:
        `Dict[str, Any]`: search results. Keys are `objects`, `total` and `time`.
        Refer: https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
    """
    # NOTE: `text` query is required. API's default of `size` query is 250, not 20
    #       (`REGISTRY-API.md` seems to be wrong)
    url = f'{BASE_URL}/-/v1/search?text={text}&size={size}'
    json_text = file_io.download_html(url, unescape=False)
    projects = file_io.jsontext_to_dict(json_text)
    return projects
