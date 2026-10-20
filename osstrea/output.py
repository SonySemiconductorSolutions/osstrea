""" Module printing results """
import sys
import pprint
import shutil
from typing import Literal, Any, TYPE_CHECKING

from useful_types import SequenceNotStr

from . import file_io
from . import package_checker
from . import package
from . import osstrea_obj

if TYPE_CHECKING:
    from . import flowchart

def as_log(
        search_results:list[dict[str, Any]],
        sbom_path:str,
        output_minimum_level:str,
        colourise_output:bool=True
    ) -> None:
    """ Print information of results """
    def level_num(level:str) -> int:
        if level == 'full':
            return  0
        elif level == 'comprehensive':
            return 10
        elif level == 'expanded':
            return 20
        elif level == 'normal':
            return 30
        elif level == 'brief':
            return 40
        elif level == 'silent':
            return 50
        else:
            return level_num('normal')
    # The following print_* functions accept the same keyword arguments as the print statement.
    def print_considering_level(
            *values,
            level:int=level_num('normal'),
            sep=' ', end='\n', file=None, flush=False
        ) -> bool:
        """
        Prints output based on the specified level.
        Returns `True` if printed, `False` otherwise.
        """
        if level >= level_num(output_minimum_level):
            print(*values, sep=sep, end=end, file=file, flush=flush)
            return True
        return False
    def print_silent(*values, sep=' ', end='\n', file=None, flush=False):
        print_considering_level(
            *values, level=level_num('silent'),
            sep=sep, end=end, file=file, flush=flush)
    def colourise(value, *commands:str) -> str|None:
        def sequence(command):
            command_num = {
                'reset'     :0,
                'bold'      :1,
                'italic'    :3,
                'underline' :4,
                'reverse'   :7,
                'invisible' :8,
                'black'     :30,
                'red'       :31,
                'green'     :32,
                'yellow'    :33,
                'blue'      :34,
                'magenta'   :35,
                'cyan'      :36,
                'white'     :37,
                'fg_default':39,
                'bg_black'  :40,
                'bg_red'    :41,
                'bg_green'  :42,
                'bg_yellow' :43,
                'bg_blue'   :44,
                'bg_magenta':45,
                'bg_cyan'   :46,
                'bg_white'  :47,
                'bg_default':49,
                'overline'  :53,
                'hi_black'  :90,
                'hi_red'    :91,
                'hi_green'  :92,
                'hi_yellow' :93,
                'hi_blue'   :94,
                'hi_magenta':95,
                'hi_cyan'   :96,
                'hi_white'  :97,
                }
            return f'\033[{command_num.get(command, 0)}m'
        if value is None:
            return None
        if not colourise_output or not sys.stdout.isatty():
            return value
        string = str(value)
        for command in commands:
            string = sequence(command) + string
        return string + sequence('reset')
    def line_with_message(message:str, line_char:str) -> str:
        if message != '':
            message = ' ' + message + ' '
        full_line_length = (shutil.get_terminal_size().columns - len(message))
        number_of_characters =  full_line_length // len(line_char)
        line = line_char * (number_of_characters // 2)
        return line + message + line
    def colourise_purl(purl:str) -> str:
        p = package.PURL(purl)
        p.type        = colourise(p.type,       'cyan')
        p.namespace   = colourise(p.namespace,  'green')
        p.name        = colourise(p.name,       'green')
        p.version     = colourise(p.version,    'magenta')
        p.qualifiers  = colourise(p.qualifiers, 'green')
        p.subpath     = colourise(p.subpath,    'green')
        coloured_purl = p.make_purl('all')
        return coloured_purl if coloured_purl is not None else ''
    def get_pkg_version(pkg:package.Pkg) -> str:
        if isinstance(pkg.purl, str) and pkg.purl != '':
            purl = package.PURL(pkg.purl)
            return purl.version if purl.version is not None else ''
        versions = ''
        for key in pkg.dict_pkg.keys():
            if 'version' in key.lower() or 'バージョン' in key:
                versions += f'{pkg.dict_pkg.get(key, None)} ({key}) '
        return versions.strip()
    if len(search_results) == 0:
        print('No results.')
        return

    # Print results for each packages.
    output_minimum_level = output_minimum_level.lower()
    analyzer = package_checker.ResultAnalyzer(search_results)
    print(f'{sbom_path} results:')
    print()
    for result in analyzer.analyze_results():
        pkg:package.Pkg = result['pkg']
        outputs:list[dict[str, Any]] = result['results']

        purl = package.PURL(None)
        if isinstance(pkg.purl, str) and pkg.purl != '':
            try:
                purl.parse_set_purl(pkg.purl)
            except ValueError as e:
                print(e)
        else:
            purl.scheme = 'pkg'
            purl.type = pkg.type
            original_name = pkg.dict_pkg.get('name', None)
            purl.name = original_name
            purl.version = get_pkg_version(pkg)
            purl.purl = purl.make_purl('all')
        if purl.purl is None:
            purl.purl = f"pkg:{pkg.type}/{pkg.name}@{get_pkg_version(pkg)}"
        print(f"{colourise_purl(purl.purl)}")
        no_outputs = True
        for output in outputs:
            info:flowchart.CheckOutput = output['info']
            if info is None:
                continue
            printed = print_considering_level(
                '> ', colourise(info.category, *info.category_colour),
                f"(Attribute: {colourise(info.attribute_num, 'bold')})",
                info.brief_info, level=level_num(info.level))
            if printed:
                no_outputs = False
            if info.detailed_info != '':
                print_considering_level(
                    info.detailed_info, level=level_num(info.detailed_level))
        if no_outputs:
            print_considering_level(
                ' ', colourise('No issues to report at this output level.', 'italic', 'underline'),
                level=level_num('brief'))
        print_considering_level('SBOM:\n', pprint.pformat(pkg.dumps()), level=level_num('expanded'))
        # NOTE: DANGER: container might stop
        # print_considering_level(pprint.pformat(result), level=level_num('full'))
        print()

    # Print statistics.
    # If both OIN and OIN_HP are present, they are output together.
    statistics = analyzer.statistics()
    print_silent(line_with_message('statistics', line_char='='))
    category_max_width = max([len(category) for category, _ in statistics])
    for category, num in statistics:
        print(f"{category}{' '*(category_max_width - len(category))}: {num:3d}")
    print_silent(line_with_message('', line_char='-'))
    print(f"PKG TOTAL{' '*(category_max_width - len('PKG TOTAL'))}: {len(analyzer.search_results):3d}")
    print_silent(line_with_message('', line_char='='))

def display_software_entities(packages_list:list[package.SoftwareEntity]) -> None:
    """Print information of listed software entities."""
    for pkg in packages_list:
        pprint.pprint(pkg.dumps())

def save_results(
        results:list[dict[str, Any]],
        sbom_path:str,
        output_path:str,
        convert_to_absolute=False) -> None:
    """ Save results to a file. """
    json_results = file_io.dict_to_jsontext(
        {'results':results, 'metadata': {'sbom_path': sbom_path}}, json_encoder=osstrea_obj.JSONEncoder)
    file_io.save_text_file(output_path, json_results, convert_to_absolute=convert_to_absolute)

def print_pkg_list_diff(
        packages_before:package.AnySwEntSequence,
        packages_after :package.AnySwEntSequence,
        keys:SequenceNotStr[str]|None=None,
        *,
        mode:Literal['intersection', 'difference']|None=None
    ) -> None:
    """Show the difference of Pkg list"""
    added_packages = package.get_software_entities_diff(
        packages_after, packages_before, keys, mode=mode)
    if len(added_packages) > 0:
        print(f'{len(added_packages)} packages updated.')
        for pkg in added_packages:
            print('+', pkg.name)
    else:
        print('No packages updated.')

    deleted_packages = package.get_software_entities_diff(
        packages_before, packages_after, keys, mode=mode)
    if len(deleted_packages) > 0:
        print(f'{len(deleted_packages)} packages deleted.')
        for pkg in deleted_packages:
            print('-', pkg.name)
    else:
        print('No packages deleted.')

def print_to_tty(*values, pad:str|None=None, sep=' ', end='\n', flush=False) -> None:
    """ Print text only when the output is a terminal (tty). """
    def trailing_chars() -> str:
        if pad is None or pad == '':
            return ''
        length_without_fill = len(sep.join(str(value) for value in values) + end)
        extra_len = shutil.get_terminal_size().columns - length_without_fill
        if extra_len <= 0:
            return ''
        return pad * (extra_len // len(pad)) + (pad[0:extra_len % len(pad)])

    if sys.stdout.isatty():
        print(*values, sep=sep, end=trailing_chars()+end, flush=flush)
