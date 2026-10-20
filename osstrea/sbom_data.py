""" A method for SBOM data. """
import abc
import datetime
from typing import Sequence, Any

from . import file_io
from . import package

class SBOMUnparseableError(Exception):
    """Exception thrown when parsing SBOM fails."""

class SBOMParser(abc.ABC):
    """ Abstract class for interpreting arbitrary form of SBOM """
    @abc.abstractmethod
    def __init__(self, filepath):
        self.data:dict[str, Any]
        self.dict_software_entities:list[dict[str, Any]]
        self.filepath:file_io.StrPath = filepath

    @abc.abstractmethod
    def get_dict_software_entities(self) -> list[dict[str, Any]]:
        """ Return packages listed in SBOM """

    def get_data(self) -> dict[str, Any]:
        """ Getter for `data` member """
        return self.data

    @staticmethod
    def remove_duplication(packages:list[dict[str, Any]]) -> list[dict[str, Any]]:
        """ Remove packages with duplicate names and versions """
        # When two elements are duplicated, record the one with the higher index.
        # That is, only the first duplicate is not recorded.
        # Finally, the unrecorded ones are picked up and returned as a list.
        dupl_num = set()
        for i, dict_pkg in enumerate(packages):
            for j, dict_pkg2 in enumerate(packages):
                if i != j and (dict_pkg['name'], dict_pkg['version']) == (dict_pkg2['name'], dict_pkg2['version']):
                    dupl_num.add(max(i, j))
        return [ pkg for i, pkg in enumerate(packages) if i not in dupl_num ]

class JsonSBOMParser(SBOMParser, abc.ABC):
    """ Abstract class. Parser for json file """
    def __init__(self, filepath):
        super().__init__(filepath)
        text = file_io.load_text_file(filepath, convert_to_absolute=False)
        self.data = file_io.jsontext_to_dict(text)
        self.dict_software_entities = self.get_dict_software_entities()

    @abc.abstractmethod
    def get_dict_software_entities(self) -> list[dict[str, Any]]:
        ...

class XlsxSBOMParser(SBOMParser, abc.ABC):
    """Abstract class. Parser for xlsx file

    Args:
        filepath (StrPath):
            Specify the path of SBOM
        sheet_name (str):
            Specify the sheet name to read
        pkg_name_column (str):
            Specify the column name to use as the pkg name
        keys_replace (dict[str, str], default=None): Keys to replace.
            If None, only replace `pkg_name_column` to 'name'
        query_column (str, default=None): Specify the query to search for header index.
            If None, `pkg_name_column` is used as query.
        index_col (int, Sequence[int], default=None):
            (almost) same as `index_col` in pandas.read_excel
    """
    def __init__(
            self,
            filepath,
            *,
            sheet_name:str,
            pkg_name_column:str,
            keys_for_replacement:dict[str, str]|None=None,
            query_column:str|None=None,
            index_col:int|Sequence[int]|None=None
        ):
        def format_str(value):
            """
            Format string.
            Remove trailing whitespace and if value is `''`, returns `None`.
            """
            if isinstance(value, str):
                value = value.strip()
                if value == '':
                    return None
                else:
                    return value
            else:
                return value

        super().__init__(filepath)

        self.sheet_name      = sheet_name
        self.pkg_name_column = pkg_name_column
        self.keys_for_replacement = keys_for_replacement
        self.index_col       = index_col
        self.header_index    = self.search_header_index(query_column)
        self.data = file_io.xlsx_to_dict(
            filepath,
            sheet_name=self.sheet_name,
            header    =self.header_index,
            index_col =self.index_col
        )
        self.oss_sheet = {
            str(index): {
                str(column): format_str(value)
                for column, value in row.items()
            }
            for index, row in self.data[self.sheet_name].items()
        }
        self.dict_software_entities = self.get_dict_software_entities()

    def search_header_index(self, query_column:str|None=None) -> int:
        """Identify index of header row"""
        if query_column is None:
            query_column = self.pkg_name_column
        try:
            xlsx_dict = file_io.xlsx_to_dict(
                self.filepath, sheet_name=None, index_col=None, header=None, dropna=False
            )
            header = 0
            for index, row in xlsx_dict[self.sheet_name].items():
                if query_column in row.values():
                    header = index
                    break
        except KeyError as e:
            raise SBOMUnparseableError(f"`{query_column}` cannot be found.", repr(e)) from e

        if not isinstance(header, (int, str)):
            raise SBOMUnparseableError(
                f"The file type could not be determined."
                f" `header` type is strange ({type(header) = })")

        return int(header)

    def get_dict_software_entities(self) -> list[dict[str, Any]]:
        packages = [
            dict_pkg
            for dict_pkg in self.oss_sheet.values()
            if dict_pkg[self.pkg_name_column] is not None
                and self.pkg_judgement_conditions(dict_pkg)
        ]
        self.replace_keys(packages, self.keys_for_replacement)
        for pkg in packages:
            pkg['originalSBOMFileName'] = self.filepath
        return packages

    def replace_keys(self, packages:list[dict[str, Any]], keys:dict[str, str]|None) -> None:
        """Replace the key names. `self.pkg_name_column` automatically be replaced to `name`."""
        if keys is None:
            keys = {}
        keys = {self.pkg_name_column: 'name', **keys}
        for pkg in packages:
            for key_bef, key_aft in keys.items():
                pkg[key_aft] = pkg.pop(key_bef, '')

    def replace_timestamp_to_spdx_date_pattern(self):
        """ Convert datetime to SPDX-formatted string """
        for dict_pkg in self.dict_software_entities:
            for key in dict_pkg:
                if isinstance(dict_pkg[key], datetime.datetime):
                    dict_pkg[key] = file_io.datetime_to_spdx_date_pattern(dict_pkg[key])

    def convert_to_boolean(self, key:str):
        """ Convert the value of `key` to boolean """
        for dict_pkg in self.dict_software_entities:
            value = dict_pkg.get(key)
            if isinstance(value, float):
                dict_pkg[key] = bool(value)

    @classmethod
    @abc.abstractmethod
    def pkg_judgement_conditions(cls, dict_pkg:dict[str, Any]) -> bool:
        """Specify the judgement condition of `dict_pkg`.
        NOTE: This function is executed BEFORE being executed function `replace_keys`,
        so keys in `dict_pkg` should be the original keys.
        """

class SpdxJsonSBOMParser(JsonSBOMParser):
    """ Parser for spdx format """
    def get_dict_software_entities(self):
        packages = self.data['packages']
        # Delete pkg if package is a container.
        packages:list[dict[str, Any]] = [
            pkg for pkg in packages if pkg.get('primaryPackagePurpose', None) != 'CONTAINER' ]
        for pkg in packages:
            if (refs := pkg.get('externalRefs')) is not None:
                for ref in refs:
                    if ref.get('referenceType') == 'purl':
                        pkg['purl'] = ref['referenceLocator']
        return packages

# Template-SPDX_Lite_SWPKG-VER_DATE.xlsx
class SPDXLiteXlsxSBOMParser(XlsxSBOMParser):
    """Parser for xlsx files in PSDX Lite format."""
    def __init__(self, filepath):
        super().__init__(
            filepath,
            sheet_name='Package Information',
            pkg_name_column='PackageName',
            query_column='Tag',
            keys_for_replacement={
                'PackageComment': 'PackageComment:ModificationRecord',
                'Unnamed: 15'   : 'PackageComment:CompileOptions',
                'Unnamed: 16'   : 'PackageComment:Any other sub-tags',
                'Unnamed: 17'   : 'PackageComment:LinkMethodology',
            },
        )

    @classmethod
    def pkg_judgement_conditions(cls, dict_pkg: dict[str, Any]) -> bool:
        return dict_pkg['Tag'] not in (
            'SAMPLE',
            'Format\nhttps://spdx.github.io/spdx-spec/v2.3/',
            'Description',
        )

class SoftwareEntityListPkgXlsxSBOMParser(XlsxSBOMParser):
    """ Parser for xlsx file (Software Entity List) """
    def __init__(self, filepath):
        super().__init__(
            filepath,
            sheet_name='Pkg',
            pkg_name_column='name'
        )
        self.replace_timestamp_to_spdx_date_pattern()
        self.convert_to_boolean('consultationRequired')

    def search_header_index(self, query_column=None) -> int:
        return 0

    @classmethod
    def pkg_judgement_conditions(cls, dict_pkg: dict[str, Any]) -> bool:
        return dict_pkg['Unnamed: 0'] is not None

class SoftwareEntityListUsageHistoryXlsxSBOMParser(XlsxSBOMParser):
    """ Parser for xlsx file (Software Entity List) """
    def __init__(self, filepath):
        super().__init__(
            filepath,
            sheet_name='UsageHistory',
            pkg_name_column='name'
        )
        self.replace_timestamp_to_spdx_date_pattern()
        self.convert_to_boolean('consultationRequired')

    def search_header_index(self, query_column=None) -> int:
        return 1

    @classmethod
    def pkg_judgement_conditions(cls, dict_pkg: dict[str, Any]) -> bool:
        return dict_pkg['Unnamed: 0'] is not None

class SoftwareEntityListConsultationHistoryXlsxSBOMParser(XlsxSBOMParser):
    """ Parser for xlsx file (Software Entity List) """
    def __init__(self, filepath):
        super().__init__(
            filepath,
            sheet_name='ConsultationHistory',
            pkg_name_column='name'
        )
        self.replace_timestamp_to_spdx_date_pattern()
        self.convert_to_boolean('consultationRequired')

    def search_header_index(self, query_column=None) -> int:
        return 1

    @classmethod
    def pkg_judgement_conditions(cls, dict_pkg: dict[str, Any]) -> bool:
        return dict_pkg['Unnamed: 0'] is not None

file_formats = [
    'spdx-json',
    'spdx-xlsx',
]

def get_format(path:str) -> str:
    """ Determine format by extension """
    file_extension:str = path.split('.')[-1]
    if file_extension == 'json':
        file_format = 'spdx-json'
    elif file_extension == 'xlsx':
        file_format = 'spdx-xlsx'
    else:
        file_format = 'spdx-json'
    return file_format

def select_parser(file_format:str) -> type[SBOMParser]:
    """ Select the appropriate parser from `file_format` """
    if file_format == 'spdx-json':
        parser = SpdxJsonSBOMParser
    elif file_format == 'spdx-xlsx':
        parser = SPDXLiteXlsxSBOMParser
    else:
        parser = SpdxJsonSBOMParser
    return parser

class SwEntData:
    """ A class that represents Software Entity List data. """
    def __init__(
            self,
            *,
            filepath_package:file_io.StrPath|None=None,
            filepath_usage_history:file_io.StrPath|None=None,
            filepath_consultation_history:file_io.StrPath|None=None,
            parser_package:type[SBOMParser]|None=None,
            parser_usage_history:type[SBOMParser]|None=None,
            parser_consultation_history:type[SBOMParser]|None=None
        ):
        """ Initialize the SoftwareEntityListData object. """
        self.filepath_package = filepath_package
        self.filepath_usage_history = filepath_usage_history
        self.filepath_consultation_history = filepath_consultation_history
        self.parser_package = parser_package
        self.parser_usage_history = parser_usage_history
        self.parser_consultation_history = parser_consultation_history

        self.packages = self.get_packages()
        self.usage_histories = self.get_usage_histories()
        self.consultation_histories = self.get_consultation_histories()

    def get_packages(self) -> list[package.Pkg]:
        """ Parse packages using the specified parser. """
        parser = self.parser_package
        filepath = self.filepath_package
        if parser is None or filepath is None:
            return []
        dict_packages = parser(filepath).dict_software_entities
        return [package.Pkg({**{'type':''}, **pkg}) for pkg in dict_packages]

    def get_usage_histories(self) -> list[package.UsageHistory]:
        """ Parse usage histories using the specified parser. """
        parser = self.parser_usage_history
        filepath = self.filepath_usage_history
        if parser is None or filepath is None:
            return []
        dict_usage_histories = parser(filepath).dict_software_entities
        return [package.UsageHistory({**{'type':''}, **usage}) for usage in dict_usage_histories]

    def get_consultation_histories(self) -> list[package.ConsultationHistory]:
        """ Parse consultation histories using the specified parser. """
        parser = self.parser_consultation_history
        filepath = self.filepath_consultation_history
        if parser is None or filepath is None:
            return []
        dict_consultation_histories = parser(filepath).dict_software_entities
        return [package.ConsultationHistory({**{'type':''}, **consultation})
                for consultation in dict_consultation_histories]

class SBOMData(SwEntData):
    """ A class that represents SBOM (Software Bill of Materials) data. """
    def __init__(self, filepath:file_io.StrPath, parser:type[SBOMParser], name_cases='lower'):
        """ Initialize the SBOMData object. """
        self.filepath   = filepath
        self.name_cases = name_cases
        super().__init__(filepath_package=self.filepath, parser_package=parser)

    def get_packages(self):
        assert self.parser_package is not None, "parser_package must be set during initialization"
        assert self.filepath_package is not None, "filepath_package must be set during initialization"

        parser = self.parser_package
        filepath = self.filepath_package

        dict_entities = parser(filepath).dict_software_entities
        packages = [package.Pkg({**{'type':'SBOM'}, **pkg}) for pkg in dict_entities]
        for pkg in packages:
            purl = package.PURL(pkg.purl if pkg.purl != '' else None)
            if purl.type is not None:
                pkg.type = purl.type
        if self.name_cases == 'lower':
            for pkg in packages:
                pkg.name = pkg.name.lower()
        return packages

    def search_with_spdxid(self, spdxid:str):
        """ Search package with spdxid """
        for pkg in self.packages:
            if pkg.dict_pkg.get('SPDXID') == spdxid:
                return pkg
        return None

class SoftwareEntityListData(SwEntData):
    """ A class that represents Software Entity List data. """
    def __init__(self, filepath:file_io.StrPath):
        """ Initialize the SoftwareEntityListData object. """
        super().__init__(
            filepath_package=filepath,
            filepath_usage_history=filepath,
            filepath_consultation_history=filepath,
            parser_package=SoftwareEntityListPkgXlsxSBOMParser,
            parser_usage_history=SoftwareEntityListUsageHistoryXlsxSBOMParser,
            parser_consultation_history=SoftwareEntityListConsultationHistoryXlsxSBOMParser
        )
