""" A module managing software package database. """
import pathlib
import datetime
import collections.abc
import typing
from typing import Any, TypeAlias, Literal, Sequence, TypeGuard

from . import file_io
from . import oin
from . import dpkg
from . import apt
from . import utils
from . import package
from . import npm
from . import pypi
from . import osstrea_obj
from . import sbom_data

StrPath:TypeAlias = str|pathlib.Path
DBSwEnt:TypeAlias = Literal['package', 'usage-history', 'consultation-history', 'all-entities']

class SearchFailureException(Exception):
    """ Exception thrown when package lookup fails """

class DBUpdateFailureException(TypeError):
    """ Exception thrown when """

class DatetimeJSONEncoder(osstrea_obj.JSONEncoder):
    """Convert `datetime` object to str for json encoding."""
    def default(self, o):
        if isinstance(o, datetime.datetime):
            return file_io.datetime_to_spdx_date_pattern(o)
        else:
            return super().default(o)

def initialize(
        *initializer:str,
        dir_name :str='database',
        file_name:str='database.json',
        dpkg_path:StrPath='dpkg_status'
    ):
    """ Initialize the database file. """
    packages:list[package.Pkg] = []
    # NOTE: 'getInformationFrom' is same as 'type'
    if 'oin' in initializer:
        oin_pkgs = oin_packages()
        for pkg in oin_pkgs:
            pkg['type'] = 'oin'
        packages += [package.Pkg(pkg) for pkg in oin_pkgs]
    if 'dpkg' in initializer:
        dpkg_pkgs = dpkg_packages(dpkg_path)
        for pkg in dpkg_pkgs:
            pkg['type'] = 'dpkg'
        packages += [package.Pkg(pkg) for pkg in dpkg_pkgs]
    if 'apt' in initializer:
        apt_pkgs = apt_packages()
        for pkg in apt_pkgs:
            pkg['type'] = 'apt'
        packages += [package.Pkg(pkg) for pkg in apt_pkgs]

    if not file_io.exists(dir_name):
        file_io.make_dir(dir_name)
    save_database(packages=packages, path=file_io.join_path(dir_name, file_name))

def oin_packages(
        dir_name:str='ointable',
        tableid_first:int=1,
        tableid_last:int=oin.LATEST_VERSION
    ) -> list[dict[str, Any]]:
    """ Import OIN data. """
    packages = []
    for version in range(tableid_first, tableid_last+1):
        table = oin.Table(version, dir_name=dir_name)
        packages += table.packages
    return packages

def dpkg_packages(
        file_path:StrPath,
        dir_name :str='database',
        file_name:str='dpkg.json'
    ) -> list[dict[str, Any]]:
    """ Import dpkg data. """
    dpkg_list = dpkg.List(file_path, dir_name=dir_name, file_name=file_name)
    return dpkg_list.packages

def apt_packages(*,
        dir_name:str='database',
        update_source:bool=False
    ) -> list[dict[str, str]]:
    """ Import package data using apt. """
    return apt.get_all_packages(dir_name=dir_name, update_source=update_source)

def save_database(
        *,
        path:StrPath,
        packages:Sequence[package.Pkg]|None=None,
        usage_histories:Sequence[package.UsageHistory]|None=None,
        consultation_histories:Sequence[package.ConsultationHistory]|None=None,
        clear_existing_database:bool=False
    ) -> None:
    """ Save packages, usage histories and consultation histories to the database. """
    if clear_existing_database or not file_io.exists(path):
        database:dict[str, Any] = {}
    else:
        database = load_database(path)

    if packages is not None:
        database['packages'] = packages
    if usage_histories is not None:
        database['usage_histories'] = usage_histories
    if consultation_histories is not None:
        database['consultation_histories'] = consultation_histories

    database['metadata'] = {
        'last_updated': file_io.today_spdx_date_pattern()
    }

    jsontext = file_io.dict_to_jsontext(database, json_encoder=DatetimeJSONEncoder)
    file_io.save_text_file(path, jsontext)

def is_pkg_list(
        entities:package.AnySwEntSequence
    ) -> TypeGuard[list[package.Pkg]]:
    """[For Typing] Check that entities are assignable to `list[package.Pkg]`"""
    return all(isinstance(ent, package.Pkg) for ent in entities)

def is_usage_history_list(
        entities:package.AnySwEntSequence
    ) -> TypeGuard[list[package.UsageHistory]]:
    """[For Typing] Check that entities are assignable to `list[package.UsageHistory]`"""
    return all(isinstance(ent, package.UsageHistory) for ent in entities)

def is_consultation_history_list(
        entities:package.AnySwEntSequence
    ) -> TypeGuard[list[package.ConsultationHistory]]:
    """[For Typing] Check that entities are assignable to `list[package.ConsultationHistory]`"""
    return all(isinstance(ent, package.ConsultationHistory) for ent in entities)

@typing.overload
def add_entities(
        entities:Sequence[package.Pkg],
        dir_name:StrPath,
        file_name:StrPath,
        get_information_from:str='local'
    ) -> list[package.Pkg]:
    ...

@typing.overload
def add_entities(
        entities:Sequence[package.UsageHistory],
        dir_name:StrPath,
        file_name:StrPath,
        get_information_from:str='local'
    ) -> list[package.UsageHistory]:
    ...

@typing.overload
def add_entities(
        entities:Sequence[package.ConsultationHistory],
        dir_name:StrPath,
        file_name:StrPath,
        get_information_from:str='local'
    ) -> list[package.ConsultationHistory]:
    ...

def add_entities(
        entities:package.AnySwEntSequence,
        dir_name:StrPath,
        file_name:StrPath,
        get_information_from:str='local'
    ) -> package.AnySwEntSequence:
    """ Add packages to the database. """
    if not isinstance(entities, collections.abc.Sequence):
        raise DBUpdateFailureException('`entities` must be a `Sequence` (like `list` or `tuple`)')
    if len(entities) == 0:
        raise DBUpdateFailureException('Cannot identify `entities`\' type. `entities` is empty.')
    if not all(isinstance(ent, type(entities[0])) for ent in entities):
        raise DBUpdateFailureException('All objects in `entities` must be of the same type.')
    if not isinstance(entities[0], package.SoftwareEntity):
        raise DBUpdateFailureException(
            f"The elements in `package` must be a {osstrea_obj.typename(entities[0])} object."
        )

    # Formatting entities
    entities_copy = entities[:]
    for ent in entities_copy:
        if 'getInformationFrom' not in ent.dict_pkg:
            ent.dict_pkg['getInformationFrom'] = get_information_from
        if 'infoAcquisitionDate' not in ent.dict_pkg:
            ent.dict_pkg['infoAcquisitionDate'] = file_io.today_spdx_date_pattern()

    # merge with database
    db = Database(dir_name=dir_name, file_name=file_name)
    if is_pkg_list(entities):
        db.packages = package.merge_software_entities_lists(
            db.packages,
            entities,
            keys=('infoAcquisitionDate',),
            mode='difference'
        )
        updated_list = db.packages
    elif is_usage_history_list(entities):
        db.usage_histories = package.merge_software_entities_lists(
            db.usage_histories,
            entities,
            keys=('infoAcquisitionDate',),
            mode='difference'
        )
        updated_list = db.usage_histories
    elif is_consultation_history_list(entities):
        db.consultation_histories = package.merge_software_entities_lists(
            db.consultation_histories,
            entities,
            keys=('infoAcquisitionDate',),
            mode='difference'
        )
        updated_list = db.consultation_histories
    else:
        raise NotImplementedError()
    db.save_database()

    return updated_list

def add_entities_SwEntData(
        data:sbom_data.SwEntData,
        dir_name:StrPath,
        file_name:StrPath
    ) -> tuple[list[package.Pkg]|None,list[package.UsageHistory]|None,list[package.ConsultationHistory]|None]:
    """ Add entities from SoftwareEntityListData to the database. """
    packages = data.packages
    usage_histories = data.usage_histories
    consultation_histories = data.consultation_histories

    if len(packages) != 0:
        updated_packages = add_entities(
            packages, dir_name=dir_name, file_name=file_name, get_information_from='local')
    else:
        updated_packages = None

    if len(usage_histories) != 0:
        updated_usage_histories = add_entities(
            usage_histories, dir_name=dir_name, file_name=file_name, get_information_from='usage')
    else:
        updated_usage_histories = None

    if len(consultation_histories) != 0:
        updated_consultation_histories = add_entities(
            consultation_histories, dir_name=dir_name, file_name=file_name, get_information_from='consultation')
    else:
        updated_consultation_histories = None

    return updated_packages, updated_usage_histories, updated_consultation_histories

def load_database(path:StrPath) -> dict[str, Any]:
    """ Load data from the path. """
    text = file_io.load_text_file(path)
    data = file_io.jsontext_to_dict(text, json_decoder=osstrea_obj.JSONDecoder)
    return data

def load_database_last_updated(path:StrPath) -> str:
    """ Load the last updated timestamp from the database. """
    data = load_database(path)
    return data.get('metadata', {}).get('last_updated', 'unknown')

def load_packages(path:StrPath) -> list[package.Pkg]:
    """ Load packages from the database. """
    data = load_database(path)
    return data.get('packages', [])

def load_usage_histories(path:StrPath) -> list[package.UsageHistory]:
    """ Load usage histories from the database. """
    data = load_database(path)
    return data.get('usage_histories', [])

def load_consultation_histories(path:StrPath) -> list[package.ConsultationHistory]:
    """ Load consultation histories from the database. """
    data = load_database(path)
    return data.get('consultation_histories', [])

def delete_database(path:StrPath, entities:DBSwEnt|Sequence[DBSwEnt]) -> bool:
    """ Delete database file. """
    if isinstance(entities, str):
        entities = [entities]
    for entity in entities:
        if entity not in typing.get_args(DBSwEnt):
            raise TypeError(f"`{entity}` cannot be assigned to parameter `entities`.")

    if 'all-entities' in entities:
        save_database(
            path=path, packages=None, usage_histories=None,
            consultation_histories=None,
            clear_existing_database=True)
    else:
        packages               = None if 'package' in entities else load_packages(path)
        usage_histories        = None if 'usage-history' in entities else load_usage_histories(path)
        consultation_histories = None if 'consultation-history' in entities else load_consultation_histories(path)
        save_database(
            path=path, packages=packages, usage_histories=usage_histories,
            consultation_histories=consultation_histories,
            clear_existing_database=True)

    packages_empty               = load_packages(path) == []
    usage_histories_empty        = load_usage_histories(path) == []
    consultation_histories_empty = load_consultation_histories(path) == []

    if 'package' in entities or 'all-entities' in entities:
        if not packages_empty:
            return False
    if 'usage-history' in entities or 'all-entities' in entities:
        if not usage_histories_empty:
            return False
    if 'consultation-history' in entities or 'all-entities' in entities:
        if not consultation_histories_empty:
            return False
    return True

def load_results(path:StrPath) -> list[dict[str, Any]]:
    """ Load results from a file. """
    text = file_io.load_text_file(path, convert_to_absolute=False)
    results = file_io.jsontext_to_dict(text, json_decoder=osstrea_obj.JSONDecoder)['results']
    return results

def load_results_metadata(path:StrPath) -> dict[str, Any]:
    """ Load results from a file. """
    text = file_io.load_text_file(path, convert_to_absolute=False)
    metadata = file_io.jsontext_to_dict(text, json_decoder=osstrea_obj.JSONDecoder).get('metadata', {})
    return metadata

def line_up_pkg_candidates(pkg_name:str) -> list[package.Pkg]:
    """ Search package candidates from database """
    related_pkg:list[package.Pkg] = []
    for deb_pkg in apt.get_packages(pkg_name) + apt.search_packages_with_binary(pkg_name):
        related_pkg.append(package.Pkg({**{'type':'deb'}, **deb_pkg}))
    return related_pkg

def search_pkg(pkg:package.Pkg) -> package.Pkg|None:
    """ Search for packages in each package manager """
    try:
        if pkg.type == 'npm':
            dict_pkg = npm.get_package(pkg.name)
        elif pkg.type == 'pypi':
            project = pypi.get_project(pkg.name)
            if project is None:
                dict_pkg = None
            else:
                dict_pkg = project['info']
        elif pkg.type == 'deb':
            upstream = None
            purl = package.PURL(pkg.purl)
            if purl.qualifiers is not None:
                for field, value in package.PURL.parse_query_string(purl.qualifiers):
                    if field == 'upstream':
                        upstream = value
            packages = apt.get_packages((upstream if upstream is not None else pkg.name))
            dict_pkg = packages[0] if len(packages) > 0 else None
        elif pkg.type == 'oin':
            dict_pkg = oin.get_package(pkg.name)
        else:
            dict_pkg = None

        if dict_pkg is not None:
            # TODO: Avoid having to define these
            dict_pkg['type'] = pkg.type
            dict_pkg['infoAcquisitionDate'] = file_io.today_spdx_date_pattern()
            dict_pkg['getInformationFrom']  = pkg.type
            ret_pkg = package.Pkg(dict_pkg)
        else:
            ret_pkg = None

        return ret_pkg
    except Exception as e:
        raise SearchFailureException from e

def get_popularity(pkg:package.Pkg) -> str|None:
    """ Get package popularity (e.g. number of downloads) """
    try:
        if pkg.type == 'deb':
            data = apt.get_popularity(pkg.name)
            return str(data) if data is not None else None
        else:
            return None
    except Exception as e:
        raise SearchFailureException from e

class Database(metaclass=utils.Singleton):
    """ A class that represents a database of software packages. """

    def __init__(
            self,
            *,
            dir_name:StrPath='database',
            file_name:StrPath='database.json',
            name_cases='lower',
        ):
        self.dir = dir_name
        self.path = file_io.join_path(self.dir, file_name)

        if not file_io.exists(self.path):
            raise FileNotFoundError(str(self.path) + ' not found. Initialize it first.')
        self.last_updated = load_database_last_updated(self.path)
        self.packages:list[package.Pkg]
        self.usage_histories:list[package.UsageHistory]
        self.consultation_histories:list[package.ConsultationHistory]
        self.load_database()

        if len(self.packages) == len(self.usage_histories) == len(self.consultation_histories) == 0:
            print("Database is empty! Please initialize the database or add items to the database.")
            print(f"Database last modified: {file_io.timestamp(self.path)}")

        self.packages_not_oin = [
            pkg for pkg in self.packages if pkg.type not in ('oin',)
        ]

        self.name_cases = name_cases
        if self.name_cases == 'lower':
            for pkg in self.packages:
                pkg.name = pkg.name.lower()

    def load_database(self) -> bool:
        """ Load database """
        self.packages = load_packages(self.path)
        self.usage_histories = load_usage_histories(self.path)
        self.consultation_histories = load_consultation_histories(self.path)

        return None not in (self.packages, self.usage_histories, self.consultation_histories)

    def reset_database(self, save=False):
        """ Initialize database. """
        self.packages = []
        if save:
            self.save_database()

    def save_database(self):
        """ Update database file """
        save_database(
            packages=self.packages,
            usage_histories=self.usage_histories,
            consultation_histories=self.consultation_histories,
            path=self.path
        )

    def matched_entities(
            self,
            dict_pkg:dict[str, str],
            search_mode:Literal['exact', 'exact_ignore_cases', 'partial']='exact',
            swap:bool=False
        ) -> list[package.SoftwareEntity]:
        """ Check if package attributes exactly match packages in the database. """
        def partially_match(str_a:str, str_b:str, lower_cases=True) -> bool:
            if lower_cases:
                str_a = str_a.lower()
                str_b = str_b.lower()
            if swap:
                return (str_a in str_b) or (str_b in str_a)
            else:
                return  str_a in str_b
        def judgement(pkg:package.SoftwareEntity, frozenpkg:frozenset) -> bool:
            if 'exact' in search_mode:
                return len(pkg.freeze(keys) - frozenpkg) == 0
            else:
                for key, value in dict(frozenpkg).items():
                    if not (key in pkg.dict_pkg and partially_match(value, pkg.dict_pkg[key])):
                        return False
                return True
        if not isinstance(dict_pkg, dict):
            raise TypeError('The argument `dict_pkg` must be a dictionary.')

        if search_mode in ('exact', ):
            frozenpkg = frozenset(dict_pkg.items())
        else:
            frozenpkg = frozenset({
                key.lower():value.lower()
                for key, value in dict_pkg.items()}.items()
            )
        keys = dict_pkg.keys()
        return [pkg for pkg in self.packages + self.usage_histories + self.consultation_histories if judgement(pkg, frozenpkg)]

    def name_exact_match(self, name:str) -> list[package.SoftwareEntity]:
        """ Check if a package name exactly matches a package in the database. """
        if not isinstance(name, str):
            raise TypeError('The argument `name` must be a string.')
        return self.matched_entities({'name':name})

    def name_partial_match(self, name:str) -> list[package.SoftwareEntity]:
        """ Check if a package name partially matches a package in the database. """
        if not isinstance(name, str):
            raise TypeError('The argument `name` must be a string.')
        return self.matched_entities({'name':name}, search_mode='partial', swap=True)
