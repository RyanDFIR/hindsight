#!/usr/bin/env python3

"""Hindsight - Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome data folder, runs various plugins
against the data, and then outputs the results in a spreadsheet.
"""

import argparse
import collections
import datetime
import importlib
import logging
import os
import re
import shutil
import sys
import time

import pyhindsight
import pyhindsight.plugins
from pyhindsight.analysis import AnalysisSession
from pyhindsight.utils import get_rich_banner

import rich.align
import rich.console
import rich.live
import rich.spinner
import rich.table
import rich.text

from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def get_base_dir():
    """Get base directory for resolving relative paths (exe dir for frozen apps)."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.realpath(__file__))


def parse_arguments(analysis_session):
    description = f'''
Hindsight v{pyhindsight.__version__} - Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome/Chromium data folder, runs various plugins
   against the data, and then outputs the results in a spreadsheet. '''

    epi = r'''
Example:  C:\hindsight.py -i "C:\Users\Ryan\AppData\Local\Google\Chrome\User Data\Default" -o test_case

The Chrome Profile folder default locations are:
   Vista - 11: <userdir>\AppData\Local\Google\Chrome\\User Data\Default\
        WinXP: <userdir>\Local Settings\Application Data\Google\Chrome
                \User Data\Default\        
        Linux: <userdir>/.config/google-chrome/Default/
        MacOS: <userdir>/Library/Application Support/Google/Chrome/Default/
          iOS: \Applications\com.google.chrome.ios\Library\Application Support
                \Google\Chrome\Default\
  Chromium OS: \home\user\<GUID>\
    '''

    class MyParser(argparse.ArgumentParser):
        def error(self, message):
            sys.stderr.write(f'error: {message}\n')
            self.print_help()
            sys.exit(2)

    parser = MyParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description,
        epilog=epi)

    parser.add_argument('-i', '--input', required=True,
                        help='Path to the Chrome(ium) profile directory (typically "Default"). If a higher-level '
                             'directory is specified instead, Hindsight will recursively search for profiles.', )
    parser.add_argument('-o', '--output', help='Name of the output file (without extension)')
    parser.add_argument('-b', '--browser_type',
                        help='Force a browser for every profile, overriding auto-detection '
                             '(case-insensitive: Chrome, Edge, Brave, Vivaldi, Firefox, Tor; '
                             'Chromium maps to Chrome). Omit to auto-detect each profile from its files.',
                        default=None)
    parser.add_argument('-f', '--format', choices=analysis_session.available_output_formats,
                        default=analysis_session.available_output_formats[-1], help='Output format')
    parser.add_argument('-l', '--log', help='Location Hindsight should log to (will append if exists)',
                        default=os.path.join(get_base_dir(), 'hindsight.log'))
    parser.add_argument('-t', '--timezone', help='Display timezone for the timestamps in XLSX output', default='UTC')
    parser.add_argument('-d', '--decrypt', choices=['mac', 'linux'], default=None,
                        help='Try to decrypt Chrome data from a Linux or Mac system; support for both is currently '
                             'buggy and enabling this may cause problems. Only use "--decrypt linux" on data from a '
                             'Linux system, and only use "--decrypt mac" when running Hindsight on the same Mac the '
                             'Chrome data is from.')
    parser.add_argument('-c', '--cache',
                        help='Path to the cache directory; only needed if the directory is outside the given "input" '
                             'directory. Mac systems are set up this way by default. On a Mac, the default cache '
                             'directory location for Chrome is <userdir>/Library/Caches/Google/Chrome/Default/Cache/')
    parser.add_argument('--nocopy', '--no_copy', help='Don\'t copy files before opening them; this might run faster, '
                                                      'but some locked files may be inaccessible', action='store_true')
    parser.add_argument('--temp_dir', default=os.path.join(get_base_dir(), 'hindsight-temp'),
                        help='If files are copied before being opened, use this directory as the copy destination')

    args = parser.parse_args()

    # Convert any relative paths to absolute using base directory
    base_dir = get_base_dir()
    if not os.path.isabs(args.log):
        args.log = os.path.join(base_dir, args.log)
    if not os.path.isabs(args.temp_dir):
        args.temp_dir = os.path.join(base_dir, args.temp_dir)

    if args.timezone:
        try:
            args.timezone = ZoneInfo(args.timezone)
        except ZoneInfoNotFoundError:
            print("Couldn't understand timezone; using UTC.")
            args.timezone = datetime.timezone.utc

    # Disable decryption on Linux unless explicitly enabled and supported
    if args.decrypt == 'linux' and analysis_session.available_decrypts['linux'] == 1:
        analysis_session.available_decrypts['linux'] = 1
    else:
        analysis_session.available_decrypts['linux'] = 0

    # Disable decryption on Mac unless explicitly enabled and supported
    if args.decrypt == 'mac' and analysis_session.available_decrypts['mac'] == 1:
        analysis_session.available_decrypts['mac'] = 1
    else:
        analysis_session.available_decrypts['mac'] = 0

    return args


def main():

    def write_excel(analysis_session):
        import io

        # Set up a StringIO object to save the XLSX content to before saving to disk
        string_buffer = io.BytesIO()

        # Generate the XLSX content using the function in the AnalysisSession and save it to the StringIO object
        analysis_session.generate_excel(string_buffer)

        # Go back to the beginning (be kind, rewind)
        string_buffer.seek(0)

        # Write the StringIO object to a file on disk named what the user specified
        with open(f'{analysis_session.output_name}.{analysis_session.selected_output_format}', 'wb') as file_output:
            shutil.copyfileobj(string_buffer, file_output)

    def write_sqlite(analysis_session, console):
        output_file = analysis_session.output_name + '.sqlite'

        if os.path.exists(output_file):
            if os.path.getsize(output_file) > 0:
                console.print(f'\nDatabase file "{output_file}" already exists.\n')
                user_input = console.input('Would you like to (O)verwrite it, (R)ename output file, or (E)xit? ')
                over_re = re.compile(r'(^o$|overwrite)', re.IGNORECASE)
                rename_re = re.compile(r'(^r$|rename)', re.IGNORECASE)
                exit_re = re.compile(r'(^e$|exit)', re.IGNORECASE)
                if re.search(exit_re, user_input):
                    console.print("Exiting... ")
                    sys.exit()
                elif re.search(over_re, user_input):
                    os.remove(output_file)
                    console.print(f'Deleted old "{output_file}"')
                elif re.search(rename_re, user_input):
                    output_file = f"{output_file[:-7]}_1.sqlite"
                    console.print(f"Renaming new output to {output_file}")
                else:
                    console.print("Did not understand response.  Exiting... ")
                    sys.exit()

        analysis_session.generate_sqlite(output_file)

    def write_jsonl(analysis_session):
        output_file = analysis_session.output_name + '.jsonl'
        analysis_session.generate_jsonl(output_file)

    console = rich.console.Console()
    rich_banner = get_rich_banner()
    console.print(rich.align.Align.center(rich_banner))

    # Set up the AnalysisSession object, and transfer the relevant input arguments to it
    analysis_session = AnalysisSession()

    # parse_arguments needs the analysis_session as an input to set things like available decrypts
    args = parse_arguments(analysis_session)

    if args.output:
        analysis_session.output_name = args.output

    if args.cache:
        analysis_session.cache_path = args.cache

    analysis_session.selected_output_format = args.format
    analysis_session.browser_type = args.browser_type
    analysis_session.timezone = args.timezone
    analysis_session.no_copy = args.nocopy
    analysis_session.temp_dir = args.temp_dir
    analysis_session.log_path = args.log

    # Set up logging
    logging.basicConfig(filename=analysis_session.log_path, level=logging.DEBUG,
                        format='%(asctime)s.%(msecs).03d | %(levelname).01s | %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger(__name__)

    # Hindsight version info
    log.info(
        '\n' + '#' * 80 +
        f'\n##    Hindsight v{pyhindsight.__version__} (https://github.com/RyanDFIR/hindsight)     ##\n' +
        '#' * 80)

    # Analysis start time
    start_datetime = datetime.datetime.now()
    start_time = str(start_datetime)[:-3]

    # Print input & output directories
    analysis_session.input_path = args.input
    output_name = f'{analysis_session.output_name}.{analysis_session.selected_output_format}'
    # Find browser profiles early so we can display the count
    profile_paths = analysis_session.find_browser_profiles(args.input)
    profile_count = len(profile_paths)
    console.rule("Processing", style="green")
    meta_table = rich.table.Table(show_header=False, box=None)
    meta_table.add_column("Item", style="bold", justify="right", no_wrap=True)
    meta_table.add_column("Value", overflow="fold")
    meta_table.add_row("Start time", start_time)
    meta_table.add_row("Input directory", args.input)
    meta_table.add_row("Profiles found", str(profile_count))
    if args.browser_type:
        meta_table.add_row("Browser type", f"{args.browser_type} (forced via -b)")
    else:
        families = collections.Counter(analysis_session.detected_profile_families.values())
        if families:
            detected = ", ".join(f"{count}× {family}" for family, count in sorted(families.items()))
            meta_table.add_row("Detected", detected)
    console.print(rich.align.Align.center(meta_table))
    console.print()
    run_status = analysis_session.run()
    if not run_status:
        if analysis_session.fatal_error:
            console.print(f"\n Fatal Error '{analysis_session.fatal_error}'", style="bold red")
        sys.exit(1)

    console.rule("Running Plugins", style="green")
    console.print()
    log.info("Plugins:")
    completed_plugins = []
    plugin_rows = []

    def build_plugin_table():
        table = rich.table.Table(show_header=False, box=None, expand=False)
        table.add_column(justify="right", min_width=44)
        table.add_column(justify="center", min_width=30)
        for row in plugin_rows:
            table.add_row(*row)
        return rich.align.Align.center(table)

    def update_plugin_table(live):
        if live:
            live.update(build_plugin_table())

    def format_plugin_name(name, version):
        text = rich.text.Text()
        text.append(f"{name} ")
        text.append(f"(v{version}):", style="dim")
        return text

    def format_plugin_result(items):
        text = rich.text.Text()
        text.append("- ", style="dim")
        text.append(f"{items}")
        text.append(" -", style="dim")
        return text

    def running_status():
        return rich.spinner.Spinner("dots")

    live = rich.live.Live(build_plugin_table(), console=console, refresh_per_second=6)

    # First run built-in plugins that ship with Hindsight
    log.info(" Built-in Plugins:")
    with live:
        for plugin in pyhindsight.plugins.__all__:
            # Check to see if we've already run this plugin (likely from a different path)
            if plugin in completed_plugins:
                continue

            log.debug(f" - Loading '{plugin}'")
            try:
                module = importlib.import_module(f'pyhindsight.plugins.{plugin}')
            except ImportError as e:
                log.error(f' - Error: {e}')
                plugin_rows.append((format_plugin_name(plugin, "unknown"), rich.text.Text("- import failed -", style="red")))
                update_plugin_table(live)
                continue
            except Exception as e:
                log.error(f' - Exception in {plugin} plugin: {e}')
                continue

            try:
                log.info(f" - Running '{module.friendlyName}' plugin")
                plugin_rows.append((format_plugin_name(module.friendlyName, module.version), running_status()))
                update_plugin_table(live)
                parsed_items = module.plugin(analysis_session)
                plugin_rows[-1] = (format_plugin_name(module.friendlyName, module.version), format_plugin_result(parsed_items))
                update_plugin_table(live)
                log.info(f' - Completed; {parsed_items}')
                completed_plugins.append(plugin)
            except Exception as e:
                plugin_rows[-1] = (format_plugin_name(module.friendlyName, module.version), rich.text.Text("- failed -", style="red"))
                update_plugin_table(live)
                log.info(f' - Failed; {e}')

    # Then look for any custom user-provided plugins in a 'plugins' directory
    log.info(" Custom Plugins:")

    # Useful when Hindsight is run from a different directory than where the file is located
    real_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    if real_path not in sys.path:
        sys.path.insert(0, real_path)

    # Loop through all paths, to pick up all potential locations for custom plugins
    for potential_path in sys.path:
        # If a subdirectory exists called 'plugins' or 'pyhindsight/plugins' at the current path, continue on
        for potential_plugin_path in [os.path.join(potential_path, 'plugins'),
                                      os.path.join(potential_path, 'pyhindsight', 'plugins')]:
            if os.path.isdir(potential_plugin_path):
                log.info(f" Found custom plugin directory {potential_plugin_path}:")
                try:
                    # Insert the current plugin location to the system path, so we can import plugin modules by name
                    sys.path.insert(0, potential_plugin_path)

                    # Get list of available plugins and run them
                    plugin_listing = os.listdir(potential_plugin_path)

                    log.debug(" - Contents of plugin folder: " + str(plugin_listing))
                    for plugin in plugin_listing:
                        if plugin[-3:] == ".py" and plugin[0] != '_':
                            plugin = plugin.replace(".py", "")

                            # Check to see if we've already run this plugin (likely from a different path)
                            if plugin in completed_plugins:
                                log.debug(f" - Skipping '{plugin}'; a plugin with that name has run already")
                                continue

                            log.debug(f" - Loading '{plugin}'")
                            try:
                                module = __import__(plugin)
                            except ImportError as e:
                                log.error(f' - Error: {e}')
                                plugin_rows.append((format_plugin_name(plugin, "unknown"), rich.text.Text("- import failed -", style="red")))
                                update_plugin_table(None)
                                continue
                            except Exception as e:
                                log.error(f' - Exception in {plugin} plugin: {e}')
                                continue

                            try:
                                log.info(f" - Running '{module.friendlyName}' plugin")
                                plugin_rows.append((format_plugin_name(module.friendlyName, module.version), running_status()))
                                update_plugin_table(None)
                                parsed_items = module.plugin(analysis_session)
                                plugin_rows[-1] = (format_plugin_name(module.friendlyName, module.version), format_plugin_result(parsed_items))
                                update_plugin_table(None)
                                log.info(f' - Completed; {parsed_items}')
                                completed_plugins.append(plugin)
                            except Exception as e:
                                plugin_rows[-1] = (format_plugin_name(module.friendlyName, module.version), rich.text.Text("- failed -", style="red"))
                                update_plugin_table(None)
                                log.info(f' - Failed; {e}')
                except Exception as e:
                    log.debug(f' - Error loading plugins ({e})')
                    console.print('  - Error loading plugins')
                finally:
                    # Remove the current plugin location from the system path, so we don't loop over it again
                    sys.path.remove(potential_plugin_path)

    # Check if output directory exists; attempt to create if it doesn't
    if os.path.dirname(analysis_session.output_name) != "" \
            and not os.path.exists(os.path.dirname(analysis_session.output_name)):
        os.makedirs(os.path.dirname(analysis_session.output_name))

    # Get desired output type form args.format and call the correct output creation function
    output_file = os.path.abspath(f"{analysis_session.output_name}.{analysis_session.selected_output_format}")

    console.print()
    console.rule("Writing Output", style="green")
    console.print()

    if analysis_session.selected_output_format == 'xlsx':
        log.info("Writing output; XLSX format selected")
        try:
            write_excel(analysis_session)
        except IOError:
            error_type, value, traceback = sys.exc_info()
            console.print(f"{value} - is the file open?  If so, please close it and try again.")
            log.error(f"Error writing XLSX file; type: {error_type}, value: {value}, traceback: {traceback}")

    elif args.format == 'jsonl':
        log.info("Writing output; JSONL format selected")
        write_jsonl(analysis_session)

    elif args.format == 'sqlite':
        log.info("Writing output; SQLite format selected")
        write_sqlite(analysis_session, console)

    # Display finish info
    total_items = len(analysis_session.parsed_artifacts) + len(analysis_session.parsed_storage)
    elapsed = datetime.datetime.now() - start_datetime
    elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
    finish_time = str(datetime.datetime.now())[:-3]

    output_table = rich.table.Table(show_header=False, box=None)
    output_table.add_column("Item", style="bold", justify="right", no_wrap=True)
    output_table.add_column("Value", overflow="fold")
    output_table.add_row("Output path", output_file)
    output_table.add_row("Log path", os.path.abspath(analysis_session.log_path))
    output_table.add_row("Format", analysis_session.selected_output_format.upper())
    output_table.add_row("Total items", str(total_items))
    output_table.add_row("Elapsed time", elapsed_str)
    output_table.add_row("Finish time", finish_time)
    console.print(rich.align.Align.center(output_table))
    log.info(f'Finish time: {str(datetime.datetime.now())[:-3]}\n\n')


if __name__ == "__main__":
    main()
