import logging
import os
import json
import re
from pyhindsight.browsers.chrome import Chrome
from pyhindsight.utils import to_datetime
from pyhindsight.browsers.webbrowser import timeline_sort_key

log = logging.getLogger(__name__)


class Brave(Chrome):
    def __init__(self, profile_path, timezone=None):
        Chrome.__init__(self, profile_path, browser_name=None, version=None, timezone=timezone, parsed_artifacts=None,
                        installed_extensions=None, artifacts_counts=None)
        self.browser_name = "Brave"

    def get_history(self, path, history_file, version, row_type):
        # Set up empty return array
        results = []

        log.info("History items from {}:".format(history_file))
        try:

            with open(os.path.join(path, history_file), 'rb') as history_input:
                history_raw = history_input.read()
                history_json = json.loads(history_raw)

                for version_dict in history_json['about']['brave']['versionInformation']:
                    if version_dict['name'] == 'Brave':
                        self.display_version = version_dict['version']

                for s, site in enumerate(history_json['sites']):
                    if history_json['sites'][s].get('location'):
                        last_accessed = history_json['sites'][s]['lastAccessedTime'] if history_json['sites'][s].get('lastAccessedTime') else history_json['sites'][s]['lastAccessed']

                        new_row = Brave.URLItem(s, history_json['sites'][s]['location'],
                                                history_json['sites'][s].get('title', "<No Title>"),
                                                last_accessed, last_accessed,
                                                None, None, None, None, None, None, None, None, None, )

                        # Set the row type as determined earlier
                        new_row.row_type = row_type

                        # Set the row type as determined earlier
                        new_row.timestamp = to_datetime(new_row.last_visit_time, self.timezone)

                        # Add the new row to the results array
                        results.append(new_row)

            self.artifacts_counts[history_file] = len(results)
            log.info(" - Parsed {} items".format(len(results)))
            self.parsed_artifacts.extend(results)

        except:
            log.error(" - Error opening '{}'".format(os.path.join(path, history_file)))
            self.artifacts_counts[history_file] = 'Failed'
            return

    def process(self):
        supported_databases = ['History', 'Archived History', 'Web Data', 'Cookies', 'Login Data', 'Extension Cookies']
        supported_subdirs = ['Local Storage', 'Extensions', 'Cache']
        supported_jsons = ['Bookmarks']  # , 'Preferences']
        supported_items = supported_databases + supported_subdirs + supported_jsons
        log.debug("Supported items: " + str(supported_items))
        input_listing = os.listdir(self.profile_path)

        log.info("Found the following supported files or directories:")
        for input_file in input_listing:
            if input_file in supported_items:
                log.info(" - %s" % input_file)

        # Process History files
        custom_type_re = re.compile(r'__([A-Za-z0-9\._]*)$')
        for input_file in input_listing:
            if re.search(r'session-store-', input_file):
                row_type = 'url'
                custom_type_m = re.search(custom_type_re, input_file)
                if custom_type_m:
                    row_type = 'url ({})'.format(custom_type_m.group(1))
                # self.get_history(args.input, input_file, self.version, row_type)
                self.get_history(self.profile_path, input_file, self.version, row_type)
                display_type = 'URL' if not custom_type_m else 'URL ({})'.format(custom_type_m.group(1))
                self.artifacts_display[input_file] = "{} records".format(display_type)
                print((self.format_processing_output("{} records".format(display_type),
                                                    self.artifacts_counts[input_file])))

            if input_file == 'Partitions':
                partitions = os.listdir(os.path.join(self.profile_path, input_file))
                for partition in partitions:
                    partition_path = os.path.join(self.profile_path, input_file, partition)
                    partition_listing = os.listdir(os.path.join(self.profile_path, input_file, partition))
                    if 'Cookies' in partition_listing:
                        self.get_cookies(partition_path, 'Cookies', [47])  # Parse cookies like a modern Chrome version (v47)
                        print((self.format_processing_output("Cookie records ({})".format(partition), self.artifacts_counts['Cookies'])))

                    if 'Local Storage' in partition_listing:
                        self.get_local_storage(partition_path, 'Local Storage')
                        print((self.format_processing_output("Local Storage records ({})".format(partition), self.artifacts_counts['Local Storage'])))

        # Version information is moved to after parsing history, as we read the version from the same file rather than detecting via SQLite table attributes
        print((self.format_processing_output("Detected {} version".format(self.browser_name), self.display_version)))
        log.info("Detected {} version {}".format(self.browser_name, self.display_version))

        if 'Cache' in input_listing:
            self.get_cache(self.profile_path, 'Cache', row_type='cache')
            self.artifacts_display['Cache'] = "Cache records"
            print((self.format_processing_output(self.artifacts_display['Cache'],
                                                self.artifacts_counts['Cache'])))
        if 'GPUCache' in input_listing:
            self.get_cache(self.profile_path, 'GPUCache', row_type='cache (gpu)')
            self.artifacts_display['GPUCache'] = "GPU Cache records"
            print((self.format_processing_output(self.artifacts_display['GPUCache'],
                                                self.artifacts_counts['GPUCache'])))

        if 'Cookies' in input_listing:
            self.get_cookies(self.profile_path, 'Cookies', [47])  # Parse cookies like a modern Chrome version (v47)
            self.artifacts_display['Cookies'] = "Cookie records"
            print((self.format_processing_output("Cookie records", self.artifacts_counts['Cookies'])))

        if 'Local Storage' in input_listing:
            self.get_local_storage(self.profile_path, 'Local Storage')
            self.artifacts_display['Local Storage'] = "Local Storage records"
            print((self.format_processing_output("Local Storage records", self.artifacts_counts['Local Storage'])))

        if 'Web Data' in input_listing:
            self.get_autofill(self.profile_path, 'Web Data', [47])  # Parse autofill like a modern Chrome version (v47)
            self.artifacts_display['Autofill'] = "Autofill records"
            print((self.format_processing_output(self.artifacts_display['Autofill'],
                                                self.artifacts_counts['Autofill'])))

        if 'Preferences' in input_listing:
            self.get_preferences(self.profile_path, 'Preferences')
            self.artifacts_display['Preferences'] = "Preference Items"
            print((self.format_processing_output("Preference Items", self.artifacts_counts['Preferences'])))

        if 'UserPrefs' in input_listing:
            self.get_preferences(self.profile_path, 'UserPrefs')
            self.artifacts_display['UserPrefs'] = "UserPrefs Items"
            print((self.format_processing_output("UserPrefs Items", self.artifacts_counts['UserPrefs'])))

        # Destroy the cached key so that json serialization doesn't
        # have a cardiac arrest on the non-unicode binary data.
        self.cached_key = None

        self.parsed_artifacts.sort(key=timeline_sort_key)
