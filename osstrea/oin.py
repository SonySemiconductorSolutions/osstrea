""" A module to use data of Open Invention Network (OIN). """
import re
import datetime
import urllib.error

from typing import Any, TypedDict, Literal

from . import file_io
from . import html_parser

LATEST_VERSION = 12
OLD_URL_DIR = 'https://openinventionnetwork.com/linux-system/'
NEW_URL_DIR = 'https://openinventionnetwork.com/linux-system-definition/'

class OINArguments(TypedDict):
    """ Data set of `Table`'s arguments """
    dir_name      :str
    file_name     :str
    mode          :Literal['old', 'new']
    load_from_file:bool

def get_package(
        pkg_name:str,
        *,
        dir_name:str='ointable',
        file_name:str='table',
        mode:Literal['old', 'new']='old',
        load_from_file:bool=True
    ) -> dict[str, Any]|None:
    """
    Returns the package whose name exactly matches the input query.
    Returns information about the most recent table if there is more than one.
    """
    table_args:OINArguments = {
        'dir_name':       dir_name,
        'file_name':      file_name,
        'mode':           mode,
        'load_from_file': load_from_file
    }
    candidates:list[dict[str, Any]] = [
        pkg for pkg in list_candidate_packages(pkg_name, **table_args) if pkg['name'] == pkg_name]
    if len(candidates) == 0:
        return None
    candidates.sort(key=lambda pkg: pkg['OINTableID'], reverse=True)
    return candidates[0]

def list_candidate_packages(
        pkg_name:str,
        *,
        dir_name:str='ointable',
        file_name:str='table',
        mode:Literal['old', 'new']='old',
        load_from_file:bool=True
    ) -> list[dict[str, Any]]:
    """
    Explore Package Candidates.
    Return a list of packages where the input query is part of the name
    """
    table_args:OINArguments = {
        'dir_name':       dir_name,
        'file_name':      file_name,
        'mode':           mode,
        'load_from_file': load_from_file
    }
    packages:list[dict[str, Any]] = list_all_packages(**table_args)
    candidate_packages:list[dict[str, Any]] = [
        pkg for pkg in packages if pkg_name.lower() in pkg['name'].lower()
    ]
    return candidate_packages

def list_all_packages(
        *,
        dir_name:str='ointable',
        file_name:str='table',
        mode:Literal['old', 'new']='old',
        load_from_file:bool=True
    ) -> list[dict[str, Any]]:
    """ Aggregate packages for all tables. """
    table_args:OINArguments = {
        'dir_name':       dir_name,
        'file_name':      file_name,
        'mode':           mode,
        'load_from_file': load_from_file
    }
    packages:list[dict[str, Any]] = []
    for version in range(2, LATEST_VERSION+1):
        try:
            packages += Table(version, **table_args).packages
        except urllib.error.HTTPError:
            pass

    return packages

class Table:
    """ A Class to get table """
    def __init__(
            self,
            version:int=LATEST_VERSION,
            *,
            dir_name:str='ointable',
            file_name:str='table',
            mode:Literal['old', 'new']='old',
            load_from_file:bool=True
        ):
        """ Initializes the Table class. """
        def table_url() -> str:
            if self.mode == 'new':
                return NEW_URL_DIR

            if version == 1 or version == 2:
                return OLD_URL_DIR + 'tables-1-2/'
            else:
                return OLD_URL_DIR + f'table-{self.version}/'

        # Version must be an int with a minimum of 1 and a maximum of LATEST_VERSION
        if not 1 <= version <= LATEST_VERSION:
            version = LATEST_VERSION
        self.version = version

        # Accomodate the page specification changes of Table 12,
        # which is the latest table of OIN as of 2025-04-03.
        # This may need to be changed when a new table is published.
        self.mode = mode
        if self.version >= 12:
            self.mode = 'new'

        # Set directory's name
        self.dir = dir_name
        if not file_io.exists(self.dir):
            file_io.make_dir(self.dir)
        self.path = file_io.join_path(self.dir, file_name + f'{self.version}.json')

        # Get datum from the database file, if it exists.
        # Otherwise, get datum from the website, parse table, and write them to the database file.
        if file_io.exists(self.path) and load_from_file:
            txt = file_io.load_text_file(self.path)
            self.info = file_io.jsontext_to_dict(txt)
            self.effective_date        = self.info['effectiveDate']
            self.info_acquisition_date = self.info['infoAcquisitionDate']
            self.url                   = self.info['tableURL']
            self.packages              = self.info['packages']
        else:
            self.url = table_url()
            htmlfile_path = file_io.join_path(self.dir, file_name + f'{version}.html')

            # Load from cache
            if file_io.exists(htmlfile_path) and load_from_file:
                txt = file_io.load_text_file(htmlfile_path)
            else:
                txt = file_io.download_html(self.url)
                file_io.save_text_file(htmlfile_path, txt)
            txt = ' '.join(txt.split('\n'))
            txt = ' '.join(txt.split('         '))
            packages = self.parse_table(txt)

            # Get effective date of the table
            OIN_DATE_PATTERN = r'((?<=Effective\s)|(?<=Promulgated\s))[a-zA-Z]*\s[0-9]*,\s[0-9]*'
            search_result = re.search(OIN_DATE_PATTERN, txt)
            if search_result is not None:
                effective_date = search_result.group()
                dt = datetime.datetime.strptime(effective_date, '%B %d, %Y')
                self.effective_date = dt.strftime(file_io.SPDX_DATE_PATTERN)
            else:
                self.effective_date = 'NOTFOUND'

            self.info_acquisition_date = file_io.timestamp(htmlfile_path)

            self.packages = []
            for pkg in packages:
                pkg['getInformationFrom'] = 'oin'
                pkg['OINTableID'] = self.version
                pkg['effectiveDate'] = self.effective_date
                pkg['infoAcquisitionDate'] = self.info_acquisition_date
                self.packages.append(pkg)

            self.info = {
                'OINtableID'      : self.version,
                'effectiveDate'      : self.effective_date,
                'infoAcquisitionDate': self.info_acquisition_date,
                'tableURL'     : self.url,
                'packages'     : self.packages
                }
            txt = file_io.dict_to_jsontext(self.info)
            file_io.save_text_file(self.path, txt)

        self.package_names = [pkg['name'] for pkg in self.packages]

    def parse_table(self, txt:str) -> list:
        """ Extracts package information from an HTML table. """
        def parse_link(txt):
            """ Extracts URLs from HTML link tags. """
            # txt should be <a>[URL]</a> or <a>[URL]</a><br /><span>@hoge</span>
            rtxt = ''.join([atxt for atxt in html_parser.rawdata(txt, 'a', tag_cut=True)])
            if html_parser.includes_tag(txt, 'span'):
                rtxt += ' ' + ''.join([stxt for stxt in html_parser.rawdata(txt, 'span', tag_cut=True)])
            return rtxt.strip()

        def parse_comment(txt):
            """ Extracts comments from HTML comment tags. """
            rtxt = ''.join([h4 for h4 in html_parser.rawdata(txt, 'h4', tag_cut=True)])
            rtxt = ''.join([li for li in html_parser.rawdata(txt, 'li', tag_cut=True)])
            return rtxt

        keys = []
        packages = []

        for trtxt in html_parser.rawdata(txt, 'tr'):
            if html_parser.includes_tag(trtxt, 'th'):
                keys = [key.strip().strip(' ') for key in html_parser.rawdata(trtxt, 'th', tag_cut=True)]
                # change 'Package Name' to 'name'
                keys = [key if key != 'Package Name' else 'name' for key in keys]
                # change 'Version' to 'versionInfo'
                keys = [key if key != 'Version' else 'versionInfo' for key in keys]
                # change 'S.no' to 'No.' # table 1-11 -> S.no, table 12 -> No.
                keys = [key if key != 'S.no' else 'No.' for key in keys]
                # change 'Description' to 'description'
                keys = [key if key != 'Description' else 'description' for key in keys]
                # change 'Project URL' to 'homepage'
                keys = [key if key != 'Project URL' else 'homepage' for key in keys]
                # change 'Proj Download URL' to 'downloadLocation'
                keys = [key if key != 'Proj Download URL' else 'downloadLocation' for key in keys]
                # change 'PkgVer Download Link' to 'sourceInfo'
                keys = [key if key != 'PkgVer Download Link' else 'sourceInfo' for key in keys]
                continue
            values = []
            for tdtxt in html_parser.rawdata(trtxt, 'td', tag_cut=True):
                if html_parser.includes_tag(tdtxt, 'a'):
                    values.append(parse_link(tdtxt))
                elif html_parser.includes_tag(tdtxt, 'h4'):
                    values.append(parse_comment(tdtxt))
                else:
                    values.append(tdtxt.strip().strip(' '))
            # Skip rows without any cell (e.g. layout-only rows)
            if len(values) == 0:
                continue
            if re.fullmatch('[0-9]*', values[0]):
                # Broken format @ autoyast2-installation, No. 179, Table 10
                if len(keys) != len(values):
                    for _ in range(len(keys) - len(values)):
                        values.append('')
                package = dict(zip(keys, values))
                packages.append(package)
            elif len(packages) > 0:
                # A comment row belongs to the previous package.
                # Ignore it when no package has been parsed yet.
                packages[-1]['comment'] = values[0]
        for pkg in packages:
            pkg['No.'] = int(pkg['No.'])
        return packages
