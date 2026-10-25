# Bundled ccl_simplesnappy

This is a copy of ccl_simplesnappy, not code written for Hindsight. Do not edit it here:
tools/vendor_ccl.py replaces this directory, and its --check fails on any difference.

Source: https://github.com/cclgroupltd/ccl_simplesnappy
Commit: `3d085230baa8c46cf2090ebba29bf6e8eab31087`

The only change from the source is to imports: imports of ccl_chromium_reader and
ccl_simplesnappy by their installed names are made relative, so this copy is the one
that loads. LICENSE is the source repository's license.
