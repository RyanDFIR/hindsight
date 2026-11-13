import importlib.util
import os
import sys

__all__ = ['chrome_extensions', 'dnr_rules', 'generic_timestamps', 'google_analytics',
           'google_searches', 'load_balancer_cookies', 'quantcast_cookies',
           'query_string_parser', 'time_discrepancy_finder']

# Custom plugins are kept in sys.modules under this prefix rather than their bare name,
# so one called json.py or utils.py is not mistaken for a module that is already loaded.
CUSTOM_MODULE_PREFIX = 'hindsight_custom_plugin_'


def custom_plugin_dirs():
    """The directories a custom plugin is loaded from, in the order they are searched.

    There are two: a "plugins" folder beside the program (the script, or the exe in a
    packaged build), and this package's own directory, for a plugin file added next to
    the built-in ones.

    Every directory on sys.path used to be searched for a "plugins" subfolder, and each
    .py file in one was imported and run. That reached site-packages, where an unrelated
    package can install a top-level "plugins" package, and everything on PYTHONPATH.
    """
    if getattr(sys, 'frozen', False):
        program_dir = os.path.dirname(sys.executable)
    else:
        program_dir = os.path.dirname(os.path.realpath(sys.argv[0]))

    dirs = []
    for candidate in (os.path.join(program_dir, 'plugins'),
                      os.path.dirname(os.path.abspath(__file__))):
        candidate = os.path.realpath(candidate)
        if os.path.isdir(candidate) and candidate not in dirs:
            dirs.append(candidate)
    return dirs


def find_custom_plugins():
    """(name, directory) for each custom plugin file, without importing any of them.

    The built-in plugins are left out, as is a name already found in an earlier directory.
    """
    found = []
    names = set(__all__)
    for directory in custom_plugin_dirs():
        try:
            file_names = sorted(os.listdir(directory))
        except OSError:
            continue
        for file_name in file_names:
            name, extension = os.path.splitext(file_name)
            if extension != '.py' or name.startswith('_') or name in names:
                continue
            names.add(name)
            found.append((name, directory))
    return found


def load_custom_plugin(name, directory):
    """Import the custom plugin `name` from the file `directory`/`name`.py."""
    module_name = CUSTOM_MODULE_PREFIX + name
    path = os.path.join(directory, name + '.py')
    module = sys.modules.get(module_name)
    if module is not None and getattr(module, '__file__', None) == path:
        return module

    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    # On the path while the plugin loads, so it can import a helper module kept beside it.
    sys.path.insert(0, directory)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(directory)
    sys.modules[module_name] = module
    return module
