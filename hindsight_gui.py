#!/usr/bin/env python3

import os
import sys
import logging
import warnings
import bottle
import importlib
import pyhindsight
import pyhindsight.plugins
from pyhindsight.analysis import AnalysisSession
from pyhindsight.utils import get_rich_banner
import rich.align
import rich.console

# This will be the main pyhindsight.AnalysisSession object that all the work will be done on
analysis_session = None
STATIC_PATH = 'static'


def get_plugins_info():

    plugin_descriptions = []
    completed_plugins = []

    # First run built-in plugins that ship with Hindsight
    # log.info(" Built-in Plugins:")
    for plugin in pyhindsight.plugins.__all__:
        # Check to see if we've already run this plugin (likely from a different path)
        if plugin in completed_plugins:
            continue

        description = {'file_name': plugin, 'friendly_name': None, 'version': None, 'error': None,
                       'error_msg': None, 'parent_path': None}

        try:
            module = importlib.import_module("pyhindsight.plugins.{}".format(plugin))
            description['friendly_name'] = module.friendlyName
            description['version'] = module.version
            try:
                module.plugin()
            except ImportError as e:
                description['error'] = 'import'
                description['error_msg'] = e
                continue

        except Exception as e:
            description['error'] = 'other'
            description['error_msg'] = e
            continue

        finally:
            plugin_descriptions.append(description)
            completed_plugins.append(plugin)

    # Useful when Hindsight is run from a different directory than where the file is located
    real_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    if real_path not in sys.path:
        sys.path.insert(0, real_path)

    # Loop through all paths, to pick up all potential locations for plugins
    for potential_path in sys.path:
        # If a subdirectory exists called 'plugins' at the current path, continue on
        potential_plugin_path = os.path.join(potential_path, 'plugins')
        if os.path.isdir(potential_plugin_path):
            try:
                # Insert the current plugin location to the system path, so we can import plugin modules by name
                sys.path.insert(0, potential_plugin_path)

                # Get list of available plugins and run them
                plugin_listing = os.listdir(potential_plugin_path)

                for plugin in plugin_listing:
                    if plugin[-3:] == ".py" and plugin[0] != '_':

                        description = {'file_name': plugin, 'friendly_name': None, 'version': None, 'error': None,
                                       'error_msg': None, 'parent_path': potential_plugin_path}
                        plugin = plugin.replace(".py", "")

                        # Check to see if we've already run this plugin (likely from a different path)
                        if plugin in completed_plugins:
                            continue

                        try:
                            module = __import__(plugin)
                            description['friendly_name'] = module.friendlyName
                            description['version'] = module.version
                            try:
                                module.plugin()
                            except ImportError as e:
                                description['error'] = 'import'
                                description['error_msg'] = e
                                continue

                        except Exception as e:
                            description['error'] = 'other'
                            description['error_msg'] = e
                            continue

                        finally:
                            plugin_descriptions.append(description)
                            completed_plugins.append(plugin)

            except Exception as e:
                # log.debug(' - Error loading plugins ({})'.format(e))
                print('  - Error loading plugins')
            finally:
                # Remove the current plugin location from the system path, so we don't loop over it again
                sys.path.remove(potential_plugin_path)
    return plugin_descriptions


# Static Routes
@bottle.get(r'/static/<filename:re:.*\.(png|css|ico|svg|json|eot|svg|ttf|woff|woff2|js)>')
def images(filename):
    return bottle.static_file(filename, root=STATIC_PATH)


@bottle.route('/')
def main_screen():

    global analysis_session
    analysis_session = AnalysisSession()
    bottle_args = analysis_session.__dict__
    analysis_session.plugin_descriptions = get_plugins_info()
    bottle_args['plugins_info'] = analysis_session.plugin_descriptions
    return bottle.template(os.path.join('templates', 'run.tpl'), bottle_args)


@bottle.route('/run', method='POST')
def do_run():
    # Get user selections from the UI
    ui_selected_decrypts = bottle.request.forms.getall('selected_decrypts')
    analysis_session.selected_plugins = bottle.request.forms.getall('selected_plugins')
    analysis_session.input_path = bottle.request.forms.get('profile_path')  # TODO: refactor bottle name
    analysis_session.cache_path = bottle.request.forms.get('cache_path')
    # Empty value = "Auto-detect" (per-profile detection); anything else forces an override.
    browser_type = bottle.request.forms.get('browser_type')
    analysis_session.browser_type = browser_type if browser_type else None
    analysis_session.timezone = bottle.request.forms.get('timezone')
    # Get base directory for resolving relative paths (exe dir for frozen apps)
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.realpath(__file__))

    log_path = bottle.request.forms.get('log_path')
    if not os.path.isabs(log_path):
        log_path = os.path.join(base_dir, log_path)
    analysis_session.log_path = log_path

    copy_before_opening = bottle.request.forms.get('copy')
    if copy_before_opening == 'copy':
        analysis_session.no_copy = False
    else:
        analysis_session.no_copy = True

    temp_dir = bottle.request.forms.get('temp_dir', 'hindsight-temp')
    if not os.path.isabs(temp_dir):
        temp_dir = os.path.join(base_dir, temp_dir)
    analysis_session.temp_dir = temp_dir

    # Set up logging
    logging.basicConfig(filename=analysis_session.log_path, level=logging.DEBUG,
                        format='%(asctime)s.%(msecs).03d | %(levelname).01s | %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger(__name__)
    # Suppress ResourceWarning spam from long-running GUI sessions.
    warnings.filterwarnings("ignore", category=ResourceWarning)

    # Hindsight version info
    log.info(
        '\n' + '#' * 80 + '\n###  Hindsight v{} (https://github.com/RyanDFIR/hindsight)  ###\n'
        .format(pyhindsight.__version__) + '#' * 80)

    if 'windows' in ui_selected_decrypts:
        analysis_session.available_decrypts['windows'] = 1
    else:
        analysis_session.available_decrypts['windows'] = 0

    if 'mac' in ui_selected_decrypts:
        analysis_session.available_decrypts['mac'] = 1
    else:
        analysis_session.available_decrypts['mac'] = 0

    if 'linux' in ui_selected_decrypts:
        analysis_session.available_decrypts['linux'] = 1
    else:
        analysis_session.available_decrypts['linux'] = 0

    run_status = analysis_session.run()
    if run_status:
        analysis_session.run_plugins()
    else:
        print("error :(")
        return bottle.redirect('/error')
    return bottle.redirect('/results')


@bottle.route('/error')
def display_error():
    return bottle.template('templates/error.tpl', analysis_session.__dict__)


@bottle.route('/results')
def display_results():
    return bottle.template('templates/results.tpl', {
        'js_installed': os.path.exists(
            os.path.join(STATIC_PATH, 'web_modules/sqlite-view.js')),
        # A method, so it isn't in __dict__; the artifacts table needs it to show
        # "failed" instead of a count of 0 for an artifact that couldn't be parsed.
        'artifact_status_summary': analysis_session.artifact_status_summary(),
        **analysis_session.__dict__
        })


@bottle.route('/sqlite')
def generate_sqlite():
    temp_output = '.tempdb'
    try:
        os.remove(temp_output)
    except:
        # temp file deletion failed
        pass

    import io
    str_io = io.BytesIO()
    analysis_session.generate_sqlite(temp_output)

    with open(temp_output, 'rb') as f:
        str_io.write(f.read())

    try:
        os.remove(temp_output)
    except:
        # temp file deletion failed
        pass

    bottle.response.headers['Content-Type'] = 'application/x-sqlite3'
    bottle.response.headers['Content-Disposition'] = 'attachment; filename={}.sqlite'.format(analysis_session.output_name)
    str_io.seek(0)
    return str_io.read()


@bottle.route('/xlsx')
def generate_xlsx():
    import io
    string_buffer = io.BytesIO()
    analysis_session.generate_excel(string_buffer)
    string_buffer.seek(0)

    bottle.response.headers['Content-Type'] = \
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; charset=UTF-8'
    bottle.response.headers['Content-Disposition'] = f'attachment; filename="{analysis_session.output_name}.xlsx"'
    return string_buffer


@bottle.route('/jsonl')
def generate_jsonl():
    # TODO: there has to be a way to do this without making a temp file...
    temp_output = '.tempjsonl'
    try:
        os.remove(temp_output)
    except:
        # temp file deletion failed
        pass

    analysis_session.generate_jsonl(temp_output)
    import io
    string_buffer = io.BytesIO()

    with open(temp_output, 'rb') as f:
        string_buffer.write(f.read())

    try:
        os.remove(temp_output)
    except:
        # temp file deletion failed
        pass

    bottle.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
    bottle.response.headers['Content-Disposition'] = f'attachment; filename={analysis_session.output_name}.jsonl'
    string_buffer.seek(0)
    return string_buffer


@bottle.route('/sqlite-view')
def sqlite_view():
    return bottle.template(
        'templates/sqlite_view.tpl', analysis_session.__dict__)


def main():
    console = rich.console.Console()
    console.print(rich.align.Align.center(get_rich_banner()))
    global STATIC_PATH

    # Get the hindsight module's path on disk to add to sys.path, so we can find templates and static files
    module_path = os.path.dirname(pyhindsight.__file__)
    sys.path.insert(0, module_path)

    # Loop through all paths in system path, to pick up all potential locations for templates and static files.
    # Paths can get weird when the program is run from a different directory, or when the packaged exe is unpacked.
    for potential_path in sys.path:
        potential_template_path = potential_path
        if os.path.isdir(potential_template_path):
            # Insert the current plugin location to the system path, so bottle can find the templates
            bottle.TEMPLATE_PATH.insert(0, potential_template_path)

        potential_static_path = os.path.join(potential_path, 'static')
        if os.path.isdir(potential_static_path):
            STATIC_PATH = potential_static_path

    # SECURITY: bind to localhost only. Hindsight is a single-operator forensic
    # tool — the profile/cache/log paths submitted via the GUI are treated as
    # trusted because the operator runs the process at their own privilege and
    # reads only files they could already access. That assumption holds ONLY
    # while the server is loopback-bound. Do NOT change host to 0.0.0.0 (or
    # otherwise expose it): combined with running at a higher privilege than the
    # requester, it turns those operator-supplied paths into a genuine
    # arbitrary-file-read (CWE-22). See dismissed code-scanning alert py/path-injection.
    bottle.run(host='localhost', port=8080, debug=True)


if __name__ == "__main__":
    main()
