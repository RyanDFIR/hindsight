# Builds the Windows version resource for the PyInstaller specs from the single
# version source (pyhindsight.__version__), replacing the old hand-edited
# file_version_info_*.txt files.
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from pyhindsight import __version__


def make_version_info(original_filename):
    # The version resource is Windows-only, and PyInstaller's versioninfo
    # module can't even be imported elsewhere (pefile is a Windows-only dep).
    if sys.platform != 'win32':
        return None

    from PyInstaller.utils.win32.versioninfo import (
        VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable, StringStruct,
        VarFileInfo, VarStruct)

    parts = __version__.split('.')
    year, month = int(parts[0]), int(parts[1])
    micro = int(parts[2]) if len(parts) > 2 else 0

    return VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=(year, month, micro, 0),
            prodvers=(year, month, micro, 0),
            mask=0x0,
            flags=0x0,
            OS=0x4,
            fileType=0x1,
            subtype=0x0,
            date=(0, 0)
        ),
        kids=[
            VarFileInfo([VarStruct('Translation', [1033, 1200])]),
            StringFileInfo([
                StringTable(
                    '040904B0',
                    [StringStruct('Comments', 'Web browser forensics tool'),
                     StringStruct('CompanyName', 'Hindsight Foundry'),
                     StringStruct('FileDescription', 'Hindsight'),
                     StringStruct('LegalCopyright', f'Copyright© 2012 - {year}  Ryan Benson'),
                     StringStruct('ProductName', 'Hindsight'),
                     StringStruct('FileVersion', __version__),
                     StringStruct('ProductVersion', __version__),
                     StringStruct('InternalName', 'Hindsight'),
                     StringStruct('OriginalFilename', original_filename)])
            ])
        ]
    )
