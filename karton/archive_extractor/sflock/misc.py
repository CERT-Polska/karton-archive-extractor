# Copyright (C) 2015-2018 Jurriaan Bremer.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import importlib
import os
import six

def import_plugins(dirpath, module_prefix, namespace, class_):
    """Import plugins of type `class` located at `dirpath` into the
    `namespace` that starts with `module_prefix`. If `dirpath` represents a
    filepath then it is converted into its containing directory."""
    if os.path.isfile(dirpath):
        dirpath = os.path.dirname(dirpath)

    for fname in os.listdir(dirpath):
        if fname.endswith(".py") and not fname.startswith("__init__"):
            module_name, _ = os.path.splitext(fname)
            importlib.import_module("%s.%s" % (module_prefix, module_name))

    plugins = {}
    for subclass in class_.__subclasses__():
        namespace[subclass.__name__] = subclass
        plugins[subclass.name.lower()] = subclass
        class_.plugins[subclass.name.lower()] = subclass
    return plugins

def data_file(*path):
    from . import data
    """Return the path for the filepath of an embedded file."""
    dirpath = data.__path__[0]
    if six.PY3:
        dirpath = dirpath.encode()
    return os.path.abspath(os.path.join(dirpath, *path))

def make_list(obj):
    if isinstance(obj, (tuple, list)):
        return list(obj)
    return [obj]
