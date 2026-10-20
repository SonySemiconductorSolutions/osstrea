""" Main file of osstrea. """
import argparse
import importlib.metadata
import sys

import typing

from osstrea import output
from osstrea import package_checker
from osstrea import database
from osstrea import sbom_data
from osstrea import flowchart
from osstrea import file_io
from osstrea import package

def main():
    """ Controller of this package """
    def parse_argument():
        """ Parse arguments and perform appropriate processing. """
        def command_help(args:argparse.Namespace):
            print(parser.parse_args([args.command, '--help']))
            sys.exit()

        def get_osstrea_version() -> str:
            try:
                __version__ = importlib.metadata.version('osstrea')
            except importlib.metadata.PackageNotFoundError:
                __version__ = 'unknown'
            return __version__

        def get_database_version() -> str:
            db = database.Database()
            return db.last_updated

        parser = argparse.ArgumentParser(
            description='OSSTREA is a tool to help evaluate risk of patents contained within OSS.')
        subparsers = parser.add_subparsers()

        # check SBOM
        parser_check = subparsers.add_parser('check', help='Contrasting SBOMs with Databases.')
        parser_check.add_argument('sbom_path', help='Specifies a file path for the SBOM.')
        parser_check.add_argument('--pkgnames', nargs='*', help='Specify package names.')
        parser_check.add_argument(
            '--output-level',
            default='normal',
            choices=['full', 'comprehensive', 'expanded', 'normal', 'brief', 'silent'],
            help='Specify the level of output (how much detail is output).')
        parser_check.add_argument(
            '-o', '--output-path',
            default='out.json',
            help='Specify where to save.')
        parser_check.add_argument(
            '-f', '--file-format',
            choices=sbom_data.file_formats,
            help='Specify the file format')
        parser_check.add_argument(
            '--processes',
            type=int,
            default=8,
            help='Specify the number of proceeses to use for paralel processing.'
        )
        parser_check.add_argument(
            '--no-colourise', '--no-colorise',
            action='store_true'
        )
        parser_check.set_defaults(handler=command_check)

        # search packages
        parser_search = subparsers.add_parser('search', help='Search database by package name.')
        parser_search.add_argument('pkgname', help='Specify Package Name.')
        parser_search.add_argument(
            '-m', '--search-mode',
            default='exact',
            choices=['exact', 'exact_ignore_cases', 'partial'],
            help='Specify the search mode.')
        parser_search.add_argument(
            '-d', '--include-description',
            action='store_true',
            help='Search with description in addition to name.')
        parser_search.add_argument(
            '-s', '--sbom',
            help='Specify the path of the sbom to search from it.'
        )
        parser_search.add_argument(
            '-f', '--file-format',
            choices=sbom_data.file_formats,
            help='Specify the file format')
        parser_search.set_defaults(handler=command_search)

        # review results if saved results exist
        parser_review = subparsers.add_parser('review', help='Review saved results.')
        parser_review.add_argument(
            'results_path',
            nargs='*',
            help='Specify the path to the results file.')
        parser_review.add_argument('--pkgnames', nargs='*', help='Specify package names.')
        parser_review.add_argument(
            '--output-level',
            default='normal',
            choices=['full', 'comprehensive', 'expanded', 'normal', 'brief', 'silent'],
            help='Specify the level of output (how much detail is output).')
        parser_review.add_argument(
            '--no-colourise', '--no-colorise',
            action='store_true'
        )
        parser_review.set_defaults(handler=command_review)

        # initialize the database
        parser_init = subparsers.add_parser('init', help='Initialize the database.')
        parser_init.add_argument(
            'initializer',
            nargs='*',
            choices=['oin', 'apt', 'dpkg'],
            help='Select the initializer to initialize.\nAavailable choices: oin, dpkg, apt')
        parser_init.set_defaults(handler=command_init)

        # reset the database
        parser_reset = subparsers.add_parser('reset', help='Reset the database.')
        parser_reset.add_argument(
            'entities',
            nargs='*',
            choices=typing.get_args(database.DBSwEnt),
            default=['all-entities'],
            help='Specify the entity to reset'
        )
        parser_reset.add_argument(
            '--path',
            default='database/database.json',
            help='Specify the path to the database.')
        parser_reset.set_defaults(handler=command_reset)

        # add packages to the database
        parser_add = subparsers.add_parser('add', help='Add a package to the database.')
        parser_add.add_argument(
            'entity',
            choices=('package', 'usage-history', 'consultation-history', 'all-entities'),
            help='Which entity to add packages as'
        )
        parser_add.add_argument(
            'list_path',
            nargs='*',
            help='Specify the path to the list of packages to add.'
        )
        parser_add.add_argument(
            '-f', '--file-format',
            choices=sbom_data.file_formats,
            help='Specify the file format'
        )
        parser_add.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Verbosely list added packages'
        )
        parser_add.set_defaults(handler=command_add)

        # show help
        parser_help = subparsers.add_parser('help', help='Show help for subcommands.')
        parser_help.add_argument('command', help='Subcommand for which you want help.')
        parser_help.set_defaults(handler=command_help)

        # show version
        parser.add_argument(
            '-v', '--version',
            action='version',
            version=f'osstrea {get_osstrea_version()}\n'
                    f'(Database last updated: {get_database_version()})'
        )

        args = parser.parse_args()

        if hasattr(args, 'handler'):
            args.handler(args)
        else:
            # Show if you forgot to specify a subcommand.
            # If an incorrect subcommand is given, this block is not executed,
            # but instead is processed in parser.parse_args().
            parser.print_help()

    def command_check(args:argparse.Namespace):
        """ Contrasting SBOMs with Databases. """
        file_format:str|None = args.file_format
        if file_format is None:
            file_format = sbom_data.get_format(args.sbom_path)
        sbom_parser = sbom_data.select_parser(file_format)

        data = database.Database()
        sbom = sbom_data.SBOMData(args.sbom_path, sbom_parser, name_cases=data.name_cases)
        if args.pkgnames is not None:
            sbom.packages = [pkg for pkg in sbom.packages if pkg.name in args.pkgnames]
            name_diff = set(args.pkgnames) - set(pkg.name for pkg in sbom.packages)
            if len(name_diff) > 0:
                print(f"No such package(s): {name_diff}")
        attributes = flowchart.PkgAttributeList().attributes
        fc   = flowchart.FlowChart(attributes)

        results = package_checker.check_packages(sbom, data, fc, processes=args.processes)
        output.as_log(
            results,
            sbom_path=args.sbom_path,
            output_minimum_level=args.output_level,
            colourise_output=not args.no_colourise
        )
        output.save_results(
            results, sbom_path=args.sbom_path, output_path=args.output_path)

    def command_search(args:argparse.Namespace):
        """ Search database and sbom by package name. """
        packages:list[package.SoftwareEntity] = []
        if args.sbom is not None:
            if args.file_format is None:
                file_format = sbom_data.get_format(args.sbom)
            else:
                file_format = args.file_format
            sbom_parser = sbom_data.select_parser(file_format)
            sbom = sbom_data.SBOMData(args.sbom, sbom_parser)
            if args.search_mode == 'partial_search':
                packages = [pkg for pkg in sbom.packages if args.pkgname in pkg.name]
            else:
                packages = [pkg for pkg in sbom.packages if args.pkgname == pkg.name]
        else:
            data = database.Database()
            packages = data.matched_entities({'name':args.pkgname}, search_mode=args.search_mode)
            if args.include_description:
                desc_matched = data.matched_entities(
                    {'description':args.pkgname},
                    search_mode='partial')
                packages += [pkg for pkg in desc_matched if pkg not in packages]
        output.display_software_entities(packages)

    def command_review(args:argparse.Namespace):
        """ Review saved results. """
        for path in args.results_path:
            results  = database.load_results(path)
            metadata = database.load_results_metadata(path)
            if args.pkgnames is not None:
                results = [result for result in results if result['pkg'].name in (args.pkgnames)]
                diff = set(args.pkgnames) - set(result['pkg'].name for result in results)
                if len(diff) > 0:
                    print(f"No such package(s): {diff}")
            output.as_log(
                results,
                sbom_path=metadata.get('sbom_path', ''),
                output_minimum_level=args.output_level,
                colourise_output=not args.no_colourise
            )

    def command_init(args:argparse.Namespace):
        """ Initialize the database. """
        database.initialize(*args.initializer)

    def command_reset(args:argparse.Namespace):
        """ Reset the database. """
        if not file_io.exists(args.path):
            print(f"Database {args.path} not found.")
            return

        user_input = input(f"Reset {args.entities} in database {args.path}? ")
        if user_input.lower() in ('y', 'yes'):
            delete_success = database.delete_database(args.path, args.entities)
            if delete_success:
                print(f"Successfully resetting {args.path}.")
            else:
                print(f"Error occured while resetting {args.path}.")
        elif user_input.lower() in ('n', 'no'):
            print("Process aborted.")
        else:
            print("Please input 'y'/'yes' or 'n'/'no'.")
            print("Process aborted.")

    def command_add(args:argparse.Namespace):
        """ Add a package to the database. """
        db_path = 'database/database.json'
        if not file_io.exists(db_path):
            file_io.save_text_file(db_path, '')
        print(f'Save to {db_path}.')
        for oss_list_path in args.list_path:
            print(f'Loading {oss_list_path}.')
            db = database.Database()
            old_lists = (db.packages.copy(), db.usage_histories.copy(), db.consultation_histories.copy())
            try:
                if args.entity == 'all-entities':
                    data = sbom_data.SoftwareEntityListData(oss_list_path)
                else:
                    file_format = args.file_format
                    if file_format is None:
                        file_format = sbom_data.get_format(oss_list_path)
                    sbom_parser = sbom_data.select_parser(file_format)

                    oss_list = sbom_data.SBOMData(oss_list_path, sbom_parser)

                    if args.entity == 'usage-history':
                        oss_list.usage_histories = [package.UsageHistory(pkg.dict_pkg) for pkg in oss_list.packages]
                        oss_list.packages = []
                    elif args.entity == 'package':
                        pass
                    elif args.entity == 'consultation-history':
                        oss_list.consultation_histories = [package.ConsultationHistory(pkg.dict_pkg) for pkg in oss_list.packages]
                        oss_list.packages = []
                    else:
                        pass

                    data = oss_list

                if args.verbose:
                    for entities in (data.packages, data.usage_histories, data.consultation_histories):
                        print(f'{len(entities)} packages loaded.')

                try:
                    updated_lists = database.add_entities_SwEntData(data, 'database', 'database.json')
                except database.DBUpdateFailureException as e:
                    print(f"{type(e).__name__}: {e}")
                    updated_lists = ([], [], [])

            except sbom_data.SBOMUnparseableError as e:
                print(f'Unable to load {oss_list_path}.', repr(e))
            except TypeError as e:
                if 'Object of type Timestamp is not JSON serializable' in e.args:
                    print(repr(e), e)
                    print(
                        'This may be due to an unexpected version change to the date type.'
                    )
                    print(
                        'Check that the input data is valid.'
                    )
                else:
                    raise e
            else:
                if args.verbose:
                    for i in range(3):
                        old_list = old_lists[i]
                        updated_list = updated_lists[i]
                        if updated_list is None:
                            continue
                        output.print_pkg_list_diff(
                            old_list,
                            updated_list,
                            ('infoAcquisitionDate',),
                            mode='difference'
                        )

    parse_argument()

if __name__ == "__main__":
    main()
