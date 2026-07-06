__author__ = "Ryan Benson"
__version__ = "2026.06"
__email__ = "ryan@hindsig.ht"


def _derive_pypi_version(display_version):
    parts = display_version.split('.')
    year, month = int(parts[0]), int(parts[1])
    micro = int(parts[2]) if len(parts) > 2 else 0
    return f'{year}{month:02}{micro:02}'


# PyPI versions must keep the historical YYYYMMDD-style integer shape
# (e.g. 20260430): PEP 440 compares release numbers numerically, so a bare
# "2026.06" would sort *before* every already-published release and pip
# would never upgrade to it. "2026.06" -> "20260600"; "2026.06.1" -> "20260601".
__pypi_version__ = _derive_pypi_version(__version__)
