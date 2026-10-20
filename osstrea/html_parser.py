""" Module for parsing html """
import re

def cut_tag(txt:str):
    """
    Remove tags at both ends of the string.
    Note that this function doesn't see the tag correspondence.
    e.g. '<sampletag> sampletext </sampletag>' -> ' sampletext ',
        '<a> a </a> midletext <b> b </b> extratext' -> ' a </a> midletext <b> b '
    """
    return ' '.join(re.findall('(?<=>).*(?=</)', txt))

def rawdata(txt:str, tag:str, tag_cut:bool=False):
    """ Extract the part surrounded by the corresponding tag. """
    for rawtxt in re.findall('<'+tag+'.*?</'+tag+'>', txt, re.DOTALL):
        if tag_cut:
            yield cut_tag(rawtxt)
        else:
            yield rawtxt

def includes_tag(txt:str, tag:str):
    """ Take out the contents with the tag. """
    return re.search('<'+tag+'.*?</'+tag+'>', txt, re.DOTALL)

def get_attribute(txt:str, tag:str):
    """ Retrieve attributes contained in a tag. """
    attributes = {}
    for attribute in re.findall('(?<=<'+tag+').*?(?=>)', txt, re.DOTALL):
        attribute_strip = attribute.split('=')
        attribute_name = attribute_strip[0].strip()
        element = attribute_strip[1].strip()
        attributes[attribute_name] = element
    return attributes
