""" Module getting information from apt. """
from typing import Literal
from . import file_io

distributions:dict[Literal['focal', 'jammy', 'noble'], int] = {'focal':20, 'jammy':22, 'noble':24}

def get_all_packages(
        *,
        dir_name:str='database',
        update_source:bool=False
    ) -> list[dict[str, str]]:
    """ List all packages of apt """
    packages:list[dict[str, str]] = []
    for distro in distributions:
        packages += PkgList(distro=distro, dir_name=dir_name, update_source=update_source).packages
    return packages

def get_packages(
        pkg_name:str,
        *,
        dir_name:str='database',
        update_source:bool=False
    ) -> list[dict[str, str]]:
    """ Search the package with a name """
    packages = get_all_packages(dir_name=dir_name, update_source=update_source)
    return [pkg for pkg in packages if pkg.get('name') == pkg_name]

def search_packages_with_binary(
        binary_name:str,
        *,
        dir_name:str='database',
        update_source:bool=False
    ) -> list[dict[str, str]]:
    """ Search packages with a binary package name and returns the upstream packages """
    packages = get_all_packages(dir_name=dir_name, update_source=update_source)
    return [pkg for pkg in packages if binary_name in pkg.get('binary', '')]

# NOTE: debian API https://sources.debian.org/doc/api/
#       Mainly search an existence of the packages
#       Seaerch popularity https://popcon.debian.org/index.html
def get_popularity(
        pkg_name:str,
        *,
        dir_name='database',
        force_reload:bool=False
    ) -> dict|None:
    """ Get the number of package downloads in debian """
    file_path = f"./{dir_name}/by_inst.json"
    if not force_reload and file_io.exists(file_path):
        # Reload if it has been downloaded for a week
        reload = file_io.elapsed_time_second(file_path) > 60*60*24*7
    else:
        reload = True

    if reload:
        url = 'https://popcon.debian.org/by_inst'
        table = file_io.download_html(url).split('\n')
        pkg_list = [l.split() for l in table if l != '' and l[0] != '#'][:-2]
        parsed = []
        for pkg in pkg_list:
            parsed_pkg = {
                'rank': int(pkg[0]),
                'name': pkg[1],
                'inst': int(pkg[2]),
                'vote': int(pkg[3]),
                'old' : int(pkg[4]),
                'recent': int(pkg[5]),
                'no-files': int(pkg[6]),
                '(maintainer)': ' '.join(pkg[7:])
            }
            parsed.append(parsed_pkg)
        jsontext = file_io.dict_to_jsontext({'data':parsed})
        file_io.save_text_file(file_path, jsontext)
    else:
        jsontext = file_io.load_text_file(file_path)
        parsed = file_io.jsontext_to_dict(jsontext)['data']

    for pkg in parsed:
        if pkg['name'] == pkg_name:
            return pkg
    return None

class PkgList:
    """ A class to get and deal with apt. """
    def __init__(self,
            *,
            distro:Literal['focal', 'jammy', 'noble']='focal',
            ubuntu_repo:Literal['security', 'archive']='security',
            dir_name:str='database',
            update_source:bool=False
        ):
        if distro not in ('focal', 'jammy', 'noble'):
            raise ValueError('`version` must be \'focal\', \'jammy\' or \'noble\'')
        if ubuntu_repo not in ('security', 'archive'):
            raise ValueError('`ubuntu_repo` must be \'security\' or \'archive\'')
        self.url = f"https://{ubuntu_repo}.ubuntu.com/ubuntu/dists/{distro}/main/source/Sources.xz"
        self.ubuntu_repo = ubuntu_repo
        self.distro = distro
        self.dir_name = dir_name
        if not file_io.exists(self.dir_name):
            file_io.make_dir(self.dir_name)
        self.file_path = file_io.join_path(
            self.dir_name,
            f"{ubuntu_repo}{distro}{self.url.split('/')[-1]}")
        self.info_acquisition_date = file_io.today_spdx_date_pattern()
        if update_source:
            file_io.delete_file(self.file_path)
        self.packages = self.parse_database()

    def parse_database(self) -> list[dict[str, str]]:
        """ Get information using `apt show [package]`."""
        def rename_key_if_exists(dictionary:dict, old_key:str, new_key:str):
            """ Rename a key if the key exists. """
            if old_key in dictionary.keys():
                dictionary[new_key] = dictionary.pop(old_key)

        if file_io.exists(self.file_path):
            xz_file = file_io.load_binary_data(self.file_path)
        else:
            xz_file  = file_io.download_binarydata(self.url)
            file_io.save_binary_data(self.file_path, xz_file)
        txt_data = file_io.extract_xzfile(xz_file)
        packages = list(txt_data.strip().split('\n\n'))
        self.packages = [file_io.parse_list_with_colon(pkg) for pkg in packages]

        for pkg in self.packages:
            for key in pkg.copy():
                if key == 'additionalInfo':
                    continue
                rename_key_if_exists(pkg, key, key.lower())
            pkg['getInformationFrom'] = 'apt'
            pkg['ubuntuRepoInfo']  = self.ubuntu_repo
            pkg['ubuntuDistroInfo']  = self.distro
            pkg['infoAcquisitionDate'] = self.info_acquisition_date
            rename_key_if_exists(pkg, 'package', 'name')
            rename_key_if_exists(pkg, 'version', 'versionInfo')
        return self.packages
