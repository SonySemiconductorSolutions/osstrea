""" Module for expressing flowchart """
import abc
import inspect
import pprint

from . import database
from . import package
from . import osstrea_obj
from . import utils
from . import output

class CheckResult(osstrea_obj.Obj):
    """ A format of `PkgAttribute`'s check result """
    def __init__(self,
            pkg:package.Pkg,
            pkg_attribute:'PkgAttribute',
            conclusion:bool,
            category:str,
            related_packages:list[package.AnySwEnt],
            next_attribute:int|None = None
        ):
        self.pkg              = pkg
        self.pkg_attribute    = pkg_attribute
        self.conclusion       = conclusion
        self.category         = category
        self.related_packages = related_packages
        self.next_attribute   = next_attribute

class CheckOutput(osstrea_obj.Obj):
    """ A format of `PkgAttribute`'s check output """
    def __init__(self,
            name:str, category:str, pkg_attribute:'PkgAttribute',
            *, category_colour:tuple=('yellow',),
            brief_info:str='',detailed_info:str='',
            level:str='normal', detailed_level:str='comprehensive',
            attribute_num:int|None=None
        ):
        self.name = name
        self.category = category
        self.pkg_attribute = pkg_attribute
        self.attribute_num = attribute_num if attribute_num is not None else pkg_attribute.get_num()
        self.category_colour = category_colour
        self.brief_info = brief_info
        self.detailed_info = detailed_info
        self.level = level
        self.detailed_level = detailed_level

class PkgAttribute(osstrea_obj.Obj, abc.ABC):
    """ Abstract class for each package attributes in flowchart """
    _attribute_true_num:int|None  = None
    _attribute_false_num:int|None = None
    _num:int  = 0
    _name:str = ''

    def __init__(self,
            num:int,
            name:str,
            *,
            when_true:int|None=None,
            when_false:int|None=None
        ):
        self.set_num(num)
        self.set_name(name)
        self.set_next_attributes(when_true, when_false)

    @abc.abstractmethod
    def check(self, pkg:package.Pkg, db:database.Database) -> CheckResult:
        """ Determine whether the attributes applies """

    @abc.abstractmethod
    def output(self,
            result:CheckResult
        ) -> CheckOutput:
        """ Returns information needed for output """

    @classmethod
    def set_next_attributes(cls,
            when_true:int|None,
            when_false:int|None
        ) -> None:
        """ Setter for next `PkgAttribute` """
        cls._attribute_true_num  = when_true
        cls._attribute_false_num = when_false
    @classmethod
    def set_num(cls, num:int) -> None:
        """ Setter for `PkgAttribute` number """
        cls._num = num
    @classmethod
    def set_name(cls, name:str) -> None:
        """ Setter for `PkgAttribute` name """
        cls._name = name

    @classmethod
    def get_next_attribute_num(cls, check_result:bool) -> int|None:
        """ Call the next `PkgAttribute`'s instance """
        if check_result is True:
            return cls._attribute_true_num
        else:
            return cls._attribute_false_num
    @classmethod
    def get_num(cls) -> int:
        """ Getter for `PkgAttribute` number """
        return cls._num
    @classmethod
    def get_name(cls) -> str:
        """ Getter for `PkgAttribute` name """
        return cls._name

    @staticmethod
    def sorted_list(target_list:list[package.AnySwEnt]) -> list[package.AnySwEnt]:
        """
        Sort results from most recent information.
        The order of priority for sorting is the length of the name,
        followed by the date the information was obtained.
        """
        sort_result = sorted(
            target_list,
            key=lambda dbpkg:dbpkg.dict_pkg['infoAcquisitionDate'],
            reverse=True)
        sort_result = sorted(
            sort_result[:],
            key=lambda dbpkg:len(dbpkg.name),
            reverse=True)
        return sort_result

class PkgAttributeList(osstrea_obj.Obj):
    """List of `PkgAttribute`s.

    NOTE: This class is intended to be subclassed and filled in by the user.
          By defining your own `PkgAttribute` subclasses (as nested classes here),
          you can evaluate packages from various perspectives. The nested classes
          are automatically collected in `__init__` and made accessible via
          `self.attributes` (keyed by each attribute's number).

    Example:
    ```python
    class MyAttributeList(PkgAttributeList):
        class IsOinPackage(PkgAttribute):
            def __init__(self):
                super().__init__(
                    num=0, name='is_oin_package',
                    when_true=1, when_false=None
                )

            def check(self, pkg, db):
                ...

            def output(self, result):
                ...
    ```
    """
    def __init__(self):
        # Get classes in `PkgAttributeList`. Note that this also contains `__class__`
        classes = inspect.getmembers(self, inspect.isclass)
        # Get `PkgAttribute` Objects
        attributes:list[PkgAttribute] = [
            attribute[1]() for attribute in classes if attribute[0] != '__class__'
        ]
        # Enable to access `PkgAttribute` Objects by its number
        self.attributes = {
            attribute.get_num():attribute
            for attribute in attributes
            if isinstance(attribute, PkgAttribute)
        }
    class ExampleAttribute(PkgAttribute):
        """ Example attribute showing how to implement your own `PkgAttribute`.

        Subclass `PkgAttribute` and implement three things:
          1. `__init__`: register the attribute's number/name and the next
             attribute numbers (`when_true` / `when_false`) used to navigate
             the flowchart.
          2. `check`: inspect `pkg` (and `db` if needed) and return a
             `CheckResult` describing the conclusion. The judgement logic below
             is intentionally left as a placeholder that always returns `True`.
          3. `output`: return a `CheckOutput` with the information to display
             when the conclusion is `True`.
        """
        def __init__(self):
            super().__init__(
                num=0, name='example_attribute',
                when_true=None, when_false=None
            )

        def check(self, pkg, db):
            # NOTE: Implement your own judgement here. This example always
            #       concludes `True` regardless of the package.
            conclusion = True
            return CheckResult(pkg, self, conclusion, 'Example Category', [], None)

        def output(self, result):
            return CheckOutput(
                result.pkg.name, 'Example Category', self,
                category_colour=('cyan', ), level='brief',
                brief_info='< This is an example attribute. >',
                detailed_info='< This is an example attribute. >',
                detailed_level='expanded'
            )

class FlowChart(osstrea_obj.Obj):
    """ Class supervising package attributes """
    def __init__(self, attributes:dict[int, PkgAttribute], first_attribute_num=0):
        self.attributes = attributes
        self.first_attribute_num = first_attribute_num

    def check_pkg(self, pkg:package.Pkg, db:database.Database) -> list[CheckResult]:
        """ Determine package category and return information """
        check_results = []
        output.print_to_tty(f"CHECKING: {pkg.type}/{pkg.name}", end='\r', pad=' ')

        for attribute_num in self.attributes:
            attribute = self.attributes[attribute_num]
            results = attribute.check(pkg, db)
            check_results.append(results)
        return sorted(check_results, key=lambda result: result.pkg_attribute.get_num())

    def output(self, result:CheckResult):
        """ Returns information needed for output """
        output.print_to_tty(
            f"OUTPUTTING: {result.pkg.type}/{result.pkg.name}", end='\r', pad=' ')
        if result.conclusion:
            return result.pkg_attribute.output(result)
        else:
            return None
