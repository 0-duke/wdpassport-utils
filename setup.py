
from setuptools import setup

setup(name='wdpassport_utils',
      version='0.2',
      description='WD My Passport Drive Hardware Encryption Utility for Linux',
      url='https://github.com/JoshData/wdpassport-utils',
      author='0-duke, crypto-universe, JoshData',
      author_email='jt@occams.info',
      license='GPLv2',
      install_requires=[
        'pyudev',
        'py_sg @ git+https://github.com/crypto-universe/py_sg',
      ],
      scripts=['wdpassport-utils.py'],
      )