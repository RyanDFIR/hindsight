from setuptools import setup, find_packages
from pyhindsight import __pypi_version__
setup(
  name='pyhindsight',
  python_requires='>=3.9',
  packages=find_packages(),
  include_package_data=True,
  scripts=['hindsight.py', 'hindsight_gui.py'],
  version=__pypi_version__,
  description='Browser forensics for Google Chrome/Chromium',
  url='https://github.com/obsidianforensics/hindsight',
  author='Ryan Benson',
  author_email='ryan@hindsig.ht',
  license='Apache-2.0',
  keywords=['chrome', 'forensics', 'dfir', 'google-chrome', 'chromium'],
  classifiers=[
    'Development Status :: 5 - Production/Stable',
    'Topic :: Security',
    'Topic :: System :: Recovery Tools',
  ],
  install_requires=[
    'bottle>=0.12.18',
    'keyring>=21.2.1',
    'pycryptodomex>=3.9.7',
    'pywin32>=306; sys_platform == "win32"',
    'xlsxwriter>=3.1',
    'puremagic>=1.11',
    'protobuf>=4.23',
    'rich>=13.0',
    'tzdata>=2024.1'
    # 'ccl_chromium_reader @ git+https://github.com/cclgroupltd/ccl_chromium_reader.git'
  ]
)
