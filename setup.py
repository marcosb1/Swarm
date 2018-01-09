from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='Swarm',

    version='0.0.1',

    description='Part of the H.I.V.E suite, Swarm provides an restful api for applications'
                'digest message stored in a relational database',

    url='https://github.com/Dr-Crow/swarm',

    author='James Crowley',

    license='Apache',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: H.I.V.E Suite',
        'License :: OSI Approved :: Apache License',
        'Programming Language :: Python :: 3.5',
    ],

    py_modules=['swarm'],

    install_requires=['psycopg2', 'pyyaml'],

    include_package_data=True,
)
