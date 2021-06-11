# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
import sphinx_rtd_theme
from sphinx.ext.autodoc import between
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(0, os.path.abspath('..'))

# -- Project information -----------------------------------------------------

project = 'oidcat'
copyright = '2021, Bea Steers'
author = 'Bea Steers'

# The full version, including alpha/beta/rc tags
import imp
imported_version = imp.load_source('{}.__version__'.format(project), os.path.join(os.path.dirname(__file__),  '..', project, '__version__.py'))
version = imported_version.__version__
# release = '0.0.6'

# -- Mock dependencies
from unittest.mock import MagicMock

class Mock(MagicMock):
    @classmethod
    def getattr(cls, name):
        return MagicMock()

MOCK_MODULES = ['requests']


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    # 'sphinx.ext.doctest',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    # 'sphinx.ext.coverage',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    # 'sphinx_execute_code',
    # 'numpydoc',
    # 'sphinx_issues',
    # "sphinx.ext.intersphinx",  # cross-linkage
    # "sphinx.ext.mathjax",
    # "sphinx_gallery.gen_gallery",  # advanced examples
    # "matplotlib.sphinxext.plot_directive",  # docstring examples
    # "sphinxcontrib.inkscapeconverter",  # used for badge / logo conversion in tex 
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'manni'  # 'arduino', 'material', 'inkpot'

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
import sphinx_rtd_theme
html_theme = 'sphinx_rtd_theme'
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
# html_theme = 'alabaster'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']


autodoc_member_order = 'bysource'


from pprint import pformat
from sphinx.util import inspect
def object_description(obj):
    return pformat(obj, indent=4)
inspect.object_description = object_description