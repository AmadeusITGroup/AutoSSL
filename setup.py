import os
from pkg_resources import parse_version
from sys import version_info as py_version

from setuptools import setup, find_packages
from setuptools import __version__ as setuptools_version

HERE = os.path.abspath(os.path.dirname(__file__))

# retrieve package information
about = {}
with open(os.path.join(HERE, 'autossl', '__version__.py'), 'rb') as f:
    exec(f.read().decode('utf-8'), about)

with open(os.path.join(HERE, 'README.rst'), 'rb') as readme_file:
    readme = readme_file.read().decode('utf-8')

install_requires = [
    'six',
    'cryptography',
    'pyyaml',
    'requests',
]

extras_require = {
    # acme
    'acme': ['acme'],
    # servers
    # tracking
    # storage
    'git': ['GitPython'],
}
# ability to install automatically all dependencies
extras_require['all'] = list(set(value for sublist in extras_require.values() for value in sublist))


def has_environment_marker_range_operators_support():
    """Code extracted from 'pytest/setup.py'
    https://github.com/pytest-dev/pytest/blob/7538680c/setup.py#L31

    The first known release to support environment marker with range operators
    it is 17.1, see: https://setuptools.readthedocs.io/en/latest/history.html#id113
    """
    return parse_version(setuptools_version) >= parse_version('17.1')


# Compatibility with old version of setuptools
if has_environment_marker_range_operators_support():
    extras_require[':python_version<"3.4"'] = ['enum34', 'pathlib2']
elif py_version < (3, 4):
    install_requires.extend(['enum34', 'pathlib2'])


setup(
    name=about['__title__'],
    version=about['__version__'],

    author=about['__author__'],
    author_email=about['__author_email__'],

    description=about['__description__'],
    long_description=readme,
    long_description_content_type='text/markdown',
    url=about['__url__'],
    license=about['__license__'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',

        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Operating System :: MacOS',

        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],

    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'autossl = autossl.__main__:main'
        ]
    },
    platforms='Unix; MacOS X',

    install_requires=install_requires,
    extras_require=extras_require,
)
