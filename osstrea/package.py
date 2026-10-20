""" A module managing software packages. """
import pprint
import re
import urllib.parse
import abc
from typing import Any, TypeAlias, Literal, Sequence, TypeVar

from useful_types import Iterable, SequenceNotStr

from . import osstrea_obj

FrozenSwEnt:TypeAlias = frozenset[tuple[str, Any]]

class SoftwareEntity(osstrea_obj.Obj, abc.ABC):
    """Generalized class for software entity"""
    @abc.abstractmethod
    def __init__(self, dict_pkg:dict[str, Any]):
        if not isinstance(dict_pkg, dict):
            raise TypeError('Argument `pkg` must be a dict object.')
        self.dict_pkg = dict_pkg
        self.name :str = self._get('name')
        self.type :str = self._get('type')
        self.free_field :str|None = self._get('freeField')

    def dumps(self) -> dict[str, Any]:
        """ Convert contents to dictionary """
        return self.dict_pkg

    def update(self, pkg:dict[str, Any]):
        """ Update contents of this package """
        # Values on the right will overwrite the values on the left
        self.__dict__ = {**self.__dict__, **pkg}
        self.dict_pkg = {**self.dict_pkg, **pkg}

    def freeze(
            self,
            keys:Iterable[str]|None=None,
            *,
            mode:Literal['intersection', 'difference']|None=None,
        ) -> FrozenSwEnt:
        """Convert `SoftwareEntity` to `FrozenSwEnt`:`frozenset[tuple[str, Any]]`
        to make `SoftwareEntity` hashable

        `intersection` mode: Returns a `FrozenPkg` containing elements ONLY with the specified keys
        e.g.
        ```python
        pkg = Pkg({'name':'pkg', 'type':'sample', 'hoge':'huga'})
        frozen_pkg = pkg.freeze(('name', 'hoge'), mode='intersection')
        # frozen_pkg == frozenset({('name', 'pkg'), ('hoge', 'huga')})
        ```
        `difference` mode: Returns a `FrozenPkg` containing elements OTHER THAN the specified keys
        ```python
        pkg = Pkg({'name':'pkg', 'type':'sample', 'hoge':'huga'})
        frozen_pkg = pkg.freeze(('name', 'hoge'), mode='difference')
        # frozen_pkg == frozenset({('type', 'sample')})
        ```

        If `mode` is `None`, `mode` is treated as `intersection`;
        however, if neither `keys` nor `mode` is specified,
        a `FrozenPkg` containing all the elements that the `Pkg` has is returned.
        ```python
        pkg = Pkg({'name':'pkg', 'type':'sample', 'hoge':'huga'})
        frozen_pkg = pkg.freeze()
        # frozen_pkg == frozenset({('type', 'sample'), ('name', 'pkg'), ('hoge', 'huga')})
        ```
        """
        if mode is None:
            if keys is None:
                mode = 'difference'
            else:
                mode = 'intersection'
        if mode not in ('intersection', 'difference'):
            raise ValueError('Argument `mode` must be `include` or `exclude`.')

        if keys is None:
            keys = []
        if mode in ('intersection',):
            return frozenset(
                {
                    key:value for key, value in self.dict_pkg.items() if key in keys
                }.items()
            )
        elif mode in ('difference',):
            return frozenset(
                {
                    key:value for key, value in self.dict_pkg.items() if key not in keys
                }.items()
            )

    def __str__(self):
        return pprint.pformat(self.to_dict())

    def __repr__(self) -> str:
        return pprint.pformat(self.to_dict()['__value'])

    def _get(self, key:str, default:Any=None) -> Any:
        return self.dict_pkg.get(key, default)

    def _set(self, key:str, value:Any):
        self.update({key:value})

    def to_dict(self):
        return {'__type': osstrea_obj.typename(self), '__value': self.dict_pkg}

    @classmethod
    def from_dict(cls, d:dict):
        return cls(d)

AnySwEnt = TypeVar('AnySwEnt', bound=SoftwareEntity)

class Pkg(SoftwareEntity):
    """
    A class that abstracts database and SBOM packages.
    """
    # NOTE: The definition of "package" depends on the ecosystem.
    #       This class stores information in "package" as defined by the ecosystem.
    #       Therefore, `type` (= ecosystem) and `name` fields are required.
    def __init__(self, dict_pkg:dict[str, Any]):
        super().__init__(dict_pkg)
        if 'name' not in dict_pkg or not isinstance(dict_pkg['name'], str):
            raise KeyError('Attribute `name` is required.')
        if 'type' not in dict_pkg or not isinstance(dict_pkg['type'], str):
            raise KeyError('Attribute `type` is required.')
        self.source               :str |None      = self._get('source')
        self.foundation           :str |None      = self._get('foundation')
        # NOTE: `restriced` and `conditional_use` are written in character string.
        #       e.g. "Refer here." "Check this conditions."
        self.consultation_required:bool|None      = self._get('consultationRequired')
        self.conditional_use      :str |None      = self._get('conditionalUse')
        self.last_updated_date    :str |None      = self._get('infoAcquisitionDate')
        self.technical_category   :list[str]|None = self._get('technicalCategory')
        self.statistics           :dict|None      = self._get('Statistics')
        self.alternative_packages :list[Pkg]|None = self._get('alternativePackages')
        self.purl                 :str |None      = self._get('purl')

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        if self.name == other.name and self.type == other.type:
            return True
        return False

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        return pprint.pformat(self.dumps())

    # NOTE: Both old and NEW structure of `osstrea.package.Pkg` can be loaded,
    #       but only outputs NEW one.
    #       The old structure will be deprecated in the future.
    @classmethod
    def from_dict(cls, d):
        try:
            # to load old structure of `osstrea.package.Pkg`
            return Pkg(d['dict_pkg'])
        except KeyError as e:
            if 'dict_pkg' in e.args:
                # to load NEW structure of `osstrea.package.Pkg`
                return Pkg(d)
            else:
                raise e

class UsageHistory(SoftwareEntity):
    """ Dataclass represents usage history """
    def __init__(
            self,
            dict_pkg: dict[str, Any]
        ):
        super().__init__(dict_pkg)

        self.pkg           :Pkg      = Pkg(dict_pkg)
        self.project_name  :str|None = self._get('projectName')
        self.version       :str|None = self._get('versionInfo')
        self.usage_date    :str|None = self._get('usageDate')
        self.product_usage :str|None = self._get('productUsage')
        self.purl          :str|None = self._get('purl')
        self.build_options :str|None = self._get('buildOptions')

class ConsultationHistory(SoftwareEntity):
    """ Dataclass represents history of consultations """
    def __init__(
            self,
            dict_pkg: dict[str, Any]
        ):
        super().__init__(dict_pkg)

        self.pkg          :Pkg      = Pkg(dict_pkg)
        self.project_name :str|None = self._get('projectName')
        self.version      :str|None = self._get('versionInfo')
        self.talk_date    :str|None = self._get('talkDate')
        self.purl         :str|None = self._get('purl')
        self.attendees    :SequenceNotStr[str]|None = self._get('attendees')

        if isinstance(self.attendees, str):
            self.attendees = list(self.attendees)

AnySwEntSequence:TypeAlias = Sequence[Pkg] | Sequence[UsageHistory] | Sequence[ConsultationHistory]

def get_frozen_ent(ent:SoftwareEntity, exclude_keys:list[str]|None=None) -> FrozenSwEnt:
    """Convert `SoftwareEntity` to frozenset to make them hashable"""
    if exclude_keys is None:
        exclude_keys = ['infoAcquisitionDate']
    return frozenset(
        {
            key:value for key, value in ent.dict_pkg.items() if key not in exclude_keys
        }.items()
    )

def get_frozen_software_entities(
        entities:Sequence[SoftwareEntity],
        keys:Iterable[str]|None=None,
        *,
        mode:Literal['intersection', 'difference']|None=None
    ) -> frozenset[FrozenSwEnt]:
    """Hashable `SoftwareEntity` list"""
    return frozenset(ent.freeze(keys, mode=mode) for ent in entities)

def get_ent_diff(ent1:SoftwareEntity, ent2:SoftwareEntity) -> set[tuple[str, Any]]:
    """Get difference between two OSS entities.
    This returns what is in the element of the first argument but not in the second argument.

    e.g.
    ```
    pkg1.name = 'pkg1', pkg1.type = 'example',
    pkg2.name = 'pkg2', pkg2.type = 'example', pkg2.source = 'example'
    get_pkg_diff(pkg1, pkg2) -> {('name', 'pkg1')}
    get_pkg_diff(pkg2, pkg1) -> {('name', 'pkg2'), ('source', 'example')}
    ```
    """
    return ent1.dict_pkg.items() - ent2.dict_pkg.items()

def get_ent_symmetric_diff(ent1:SoftwareEntity, ent2:SoftwareEntity) -> set[tuple[str, Any]]:
    """Get symmetric difference between two packages
    This returns what is in the element of the first argument but not in the second argument
    OR
    what is in the element of the second argument but not in the first argument

    e.g.
    ```
    ```
    pkg1.name = 'pkg1', pkg1.type = 'example',
    pkg2.name = 'pkg2', pkg2.type = 'example', pkg2.source = 'example'
    get_pkg_diff(pkg1, pkg2) -> {('name', 'pkg1'), ('name', 'pkg2'), ('source', 'example')}
    get_pkg_diff(pkg2, pkg1) -> {('name', 'pkg1'), ('name', 'pkg2'), ('source', 'example')}
    ```
    ```
    """
    return ent1.dict_pkg.items() ^ ent2.dict_pkg.items()

def is_identical(
        ent1:SoftwareEntity,
        ent2:SoftwareEntity,
        keys:Iterable[str]|None=None,
        *,
        mode:Literal['intersection', 'difference']|None=None
    ) -> bool:
    """
    Check entities' identity. Check if elements match except for exclude keys.
    When specifies `None` for `keys`, it will be `['infoAcquisitionDate']`
    """
    if mode is None:
        if keys is None:
            mode = 'difference'
        else:
            mode = 'intersection'
    if mode not in ('intersection', 'difference'):
        raise ValueError('Argument `mode` must be `intersection` or `difference`.')

    if keys is None:
        keys = []
    symdiff = get_ent_symmetric_diff(ent1, ent2)
    if mode == 'intersection':
        key_diff = set(keys) - dict(symdiff).keys()
    elif mode == 'difference':
        key_diff = dict(symdiff).keys() - set(keys)
    else:
        key_diff = set()
    return len(key_diff) == 0

def get_software_entities_diff(
        entities1:Sequence[AnySwEnt],
        entities2:Sequence[AnySwEnt],
        keys:Iterable[str]|None=None,
        *,
        mode:Literal['intersection', 'difference']|None=None
    ) -> list[AnySwEnt]:
    """
    Returns software entities
    that are in the first argument list but not in the second argument list
    """
    frozen_entities1 = get_frozen_software_entities(entities1, keys, mode=mode)
    frozen_entities2 = get_frozen_software_entities(entities2, keys, mode=mode)
    entities_diff = frozen_entities1 - frozen_entities2
    return [ent for ent in entities1 if ent.freeze(keys, mode=mode) in entities_diff]

def eliminate_duplicate(entities:Sequence[AnySwEnt]) -> list[AnySwEnt]:
    """ Eliminate duplicates from the package list. """
    if len(get_frozen_software_entities(entities)) == len(entities):
        return list(entities)
    return list(
        entities[i] for i in range(len(entities)) if not is_in_ent_list(entities[i], entities[:i])
    )

def merge_software_entities_lists(
        entities1:Sequence[AnySwEnt],
        entities2:Sequence[AnySwEnt]|None=None,
        keys:Iterable[str]|None=None,
        *,
        mode:Literal['intersection', 'difference']|None=None
    ) -> list[AnySwEnt]:
    """ Merge two package lists. """
    if entities2 is None:
        entities2 = []
    return list(entities1) + get_software_entities_diff(entities2, entities1, keys, mode=mode)

def is_in_ent_list(
        target_ent:AnySwEnt,
        entities:Sequence[AnySwEnt],
        keys:Iterable[str]|None=None,
        *,
        mode:Literal['intersection', 'difference']|None=None
    ) -> bool:
    """Check that `target_ent` is identically matches an package in `entities`"""
    return len(get_software_entities_diff([target_ent], entities, keys, mode=mode)) == 0

class PURL():
    """ Class to handle PURL(Package URL) """
    def __init__(self, purl:str|None=None):
        self.purl       :str|None = None
        self.scheme     :str|None = None
        self.type       :str|None = None
        self.namespace  :str|None = None
        self.name       :str|None = None
        self.version    :str|None = None
        self.qualifiers :str|None = None
        self.subpath    :str|None = None
        self.combined_name   :str = ''

        self.parse_set_purl(purl)

    def parse_set_purl(self, purl:str|None):
        """ Decompose a PURL into individual elements """
        if purl is None:
            self.purl          = None
            self.scheme        = None
            self.type          = None
            self.namespace     = None
            self.name          = None
            self.version       = None
            self.qualifiers    = None
            self.subpath       = None
            self.combined_name = ''
            return

        pattern = r'^(?P<scheme>[^:]+):(?P<type>[^/]+)(?:/(?P<namespace>[^/]+))?/(?P<name>[^@?#]+)?(?:@(?P<version>[^?#]+))?(?:\?(?P<qualifiers>[^#]+))?(?:#(?P<subpath>.+))?$'
        matched = re.match(pattern, purl)

        if matched:
            self.purl       = purl
            self.scheme     = matched.group('scheme')
            self.type       = matched.group('type')
            self.namespace  = matched.group('namespace')
            self.name       = matched.group('name')
            self.version    = matched.group('version')
            self.qualifiers = matched.group('qualifiers')
            self.subpath    = matched.group('subpath')

            combined_name = self.name if self.name is not None else ''
            if self.namespace is not None:
                combined_name = self.namespace + '/' + combined_name
            if self.qualifiers is not None:
                combined_name += '/' + self.qualifiers
            if self.subpath is not None:
                combined_name += '/' + self.subpath
            self.combined_name = urllib.parse.unquote(combined_name)
        else:
            raise ValueError(f'Invalid PURL format. {purl}')

    def make_purl(
            self,
            *components:Literal['all', 'namespace', 'version', 'qualifiers', 'subpath']
        ) -> str|None:
        """ Generate a PURL with the specified elements """
        if self.scheme is None or self.type is None or self.name is None:
            return None
        purl  = self.scheme     # required
        purl += ':' + self.type # required
        if 'namespace' in components or 'all' in components:
            purl += ('/' + self.namespace)  if self.namespace  is not None else ''
        purl += '/' + self.name # required
        if 'version' in components or 'all' in components:
            purl += ('@' + self.version)    if self.version    is not None else ''
        if 'qualifiers' in components or 'all' in components:
            purl += ('?' + self.qualifiers) if self.qualifiers is not None else ''
        if 'subpath' in components or 'all' in components:
            purl += ('#' + self.subpath)    if self.subpath    is not None else ''
        return purl

    @classmethod
    def parse_query_string(cls, query_string:str) -> list[tuple[str, str]]:
        """ Decompose a query string into elements """
        elements = set()
        for element in query_string.split('&'):
            field = element.split('=')[0]
            value = element.split('=')[1]
            elements.add((field, value))
        return list(elements)
