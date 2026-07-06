# -*- mode: python -*-
import sys
sys.path.insert(0, SPECPATH)
from _version_info import make_version_info

block_cipher = None


a = Analysis(['../hindsight.py'],
             pathex=['..'],
             binaries=[],
             datas=[('../pyhindsight/plugins', 'plugins'), ('../hindsight.py', 'hindsight.py')],
             hiddenimports=[
                "pycryptodome", "pyhindsight", "pyhindsight.plugins.chrome_extensions", "pyhindsight.plugins.dnr_rules",
                "pyhindsight.plugins.generic_timestamps", "pyhindsight.plugins.google_analytics",
                "pyhindsight.plugins.google_searches", "pyhindsight.plugins.load_balancer_cookies",
                "pyhindsight.plugins.quantcast_cookies", "pyhindsight.plugins.query_string_parser",
                "pyhindsight.plugins.time_discrepancy_finder",
                ],
             hookspath=[],
             runtime_hooks=[],
             excludes=['unfurl', 'pycountry', 'numpy', 'pandas', 'networkx',
                       'maxminddb', 'publicsuffix2', 'tldextract',
                       'tkinter', '_tkinter',
                       'IPython', 'pytest', 'sphinx'],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          Tree('../pyhindsight/lib', prefix='pyhindsight/lib'),
          name='hindsight',
          debug=False,
          strip=False,
          upx=True,
          console=True,
          version=make_version_info('hindsight.exe'),
          icon='../pyhindsight/static/h.ico')