""" Module for storing general-purpose classes """
import functools

class Singleton(type):
    """ A class that implements the Singleton design pattern. """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

def get_union_list(seq:list) -> list:
    """ Return a list without duplicate elements """
    seen = []
    return [x for x in seq if x not in seen and not seen.append(x)]

@functools.lru_cache(maxsize=2**16)
def levenshtein_distance(
        a:str,
        b:str,
        *,
        ignore_cases:bool=False,
        allow_replacement:bool=True
    ) -> int:
    """ Return the Levenshtein distance between two strings """
    options = {'ignore_cases':ignore_cases, 'allow_replacement':allow_replacement}

    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    if ignore_cases:
        return levenshtein_distance(a.lower(), b.lower(), allow_replacement=allow_replacement)

    # The Levenshtein distance when the first characters of two strings are aligned
    # is equal to the Levenshtein distance after the second character.
    if a[0] == b[0]:
        return levenshtein_distance(a[1:], b[1:], **options)

    # insert at or delete the beginning of a, b
    d1 = levenshtein_distance(a[1:], b    , **options)
    d2 = levenshtein_distance(a    , b[1:], **options)
    # replace the first character of a and b
    d3 = levenshtein_distance(a[1:], b[1:], **options) if allow_replacement else max(d1, d2)

    return 1 + min(d1, d2, d3)
