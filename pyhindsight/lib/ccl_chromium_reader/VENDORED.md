# Bundled ccl_chromium_reader

This is a copy of ccl_chromium_reader, not code written for Hindsight. Do not edit it here:
tools/vendor_ccl.py replaces this directory, and its --check fails on any difference.

Source: https://github.com/hindsight-foundry/ccl_chromium_reader
Commit: `ef840de30221c4d65bc96d2f4d9057e9ef2f526d`
Upstream: https://github.com/cclgroupltd/ccl_chromium_reader

The source is Hindsight's fork. Its 'hindsight' branch is upstream plus fixes that are
waiting for upstream to merge them; compare the commit above with upstream to list them.

The only change from the source is to imports: imports of ccl_chromium_reader and
ccl_simplesnappy by their installed names are made relative, so this copy is the one
that loads. LICENSE is the source repository's license.
