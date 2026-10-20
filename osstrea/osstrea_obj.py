""" Module defining OSSTREA object properties """
import json
import importlib

# CAUTION: DO NOT IMPORT ANY MODULES FROM OSSTREA!

def typename(o:object) -> str:
    """ Return the type name of an object. The object can be a class or an instance """
    if isinstance(o, type):
        return f"{o.__module__}.{o.__qualname__}"
    else:
        return f"{o.__class__.__module__}.{o.__class__.__qualname__}"

class Obj():
    """
    Parent class for objects in osstrea.
    Inherit this class when you want to output objects in json
    """
    def to_dict(self):
        """ Convert `Obj` to `dict` for json form """
        return {'__type': typename(self), '__value':self.__dict__}

    @classmethod
    def from_dict(cls, d:dict):
        """ Convert `dict` to `Obj` from json form """
        return cls(**d)

class JSONEncoder(json.JSONEncoder):
    """ Encode Pkg to JSON """
    def default(self, o):
        if isinstance(o, Obj):
            return o.to_dict()
        else:
            return super().default(o)

class JSONDecoder(json.JSONDecoder):
    """ Decode Pkg from JSON """
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.pkg_hook, *args, **kwargs)

    def pkg_hook(self, o):
        """ Detect Pkg from JSON and decode """
        if '__type' in o and o['__type'].split('.')[0] == 'osstrea':
            python_package_name:str = '.'.join(o['__type'].split('.')[:2])
            module = importlib.import_module(python_package_name)
            cls = module
            for cls_name in o['__type'].split('.')[2:]:
                cls = getattr(cls, cls_name)
            if isinstance(cls, type) and issubclass(cls, Obj):
                return cls.from_dict(o['__value'])
            else:
                raise TypeError(f"Object {o['__type']} is not serializable. "
                                "The data structure of the input data may have changed.")
        else:
            return o
