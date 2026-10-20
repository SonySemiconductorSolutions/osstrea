""" Module getting information from dpkg file. """
import pathlib

from typing import TypeAlias

from . import file_io

StrPath:TypeAlias = str|pathlib.Path

class List:
    """ A class to get and deal with dpkg list """
    def __init__(
            self,
            dpkg_path:StrPath,
            dir_name :str='database',
            file_name:str='dpkg.json'
            ):
        self.dpkg_path = dpkg_path
        self.dir = dir_name
        if not file_io.exists(self.dir):
            file_io.make_dir(self.dir)
        self.path = file_io.join_path(self.dir, file_name)

        if file_io.exists(self.path):
            text = file_io.load_text_file(self.path)
            self.info = file_io.jsontext_to_dict(text)
            self.packages = self.info['packages']
        else:
            self.packages = self.parse_dpkg(self.dpkg_path)
            self.info_acquisition_date = file_io.timestamp(self.dpkg_path)
            for pkg in self.packages:
                pkg['infoAcquisitionDate'] = self.info_acquisition_date
                pkg['getInformationFrom'] = 'dpkg'
            self.info = {'packages':self.packages}
            text = file_io.dict_to_jsontext(self.info)
            file_io.save_text_file(self.path, text)

    def parse_dpkg(self, path:StrPath) -> list:
        """ Parse a dpkg file to a dictionary. """
        def rename_key_if_exists(dictionary:dict, old_key:str, new_key:str):
            """ Rename a key if the key exists. """
            if old_key in dictionary.keys():
                dictionary[new_key] = dictionary.pop(old_key)

        text = file_io.load_text_file(path)
        packages = []
        for pkg_info in text.split('\n\n'):
            if pkg_info == '':
                continue
            pkg = file_io.parse_list_with_colon(pkg_info)
            for key in pkg.copy():
                if key == 'additionalInfo':
                    continue
                rename_key_if_exists(pkg, key, key.lower())
            rename_key_if_exists(pkg, 'package', 'name')
            rename_key_if_exists(pkg, 'version', 'versionInfo')
            packages.append(pkg)
        return packages
