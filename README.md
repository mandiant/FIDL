[![GitHub](https://img.shields.io/github/license/fireeye/FIDL)](https://en.wikipedia.org/wiki/MIT_License)
![PyPI - Status](https://img.shields.io/pypi/status/FIDL)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/fireeye/FIDL)](https://github.com/fireeye/FIDL/releases)
[![PyPI](https://img.shields.io/pypi/v/FIDL.svg)](https://pypi.org/project/FIDL)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/fidl)](https://pypi.org/project/FIDL)
[![Documentation Status](https://readthedocs.org/projects/fidl/badge/?version=latest)](https://fidl.readthedocs.io/en/latest/?badge=latest)


<pre>
███████╗██╗██████╗ ██╗     
██╔════╝██║██╔══██╗██║     
█████╗  ██║██║  ██║██║     
██╔══╝  ██║██║  ██║██║     
██║     ██║██████╔╝███████╗
╚═╝     ╚═╝╚═════╝ ╚══════╝
</pre>


# FLARE IDA Decompiler Library

_FIDLing with the decompiler API_


This is a set of utilities wrapping the decompiler API into something sane. This code focus on vulnerability research and bug hunting, however most of the functionality is generic enough to be used for broader reverse engineering purposes.


# Installation

The recommended way to install this is to use python's `pip`. Keep in mind that you have to use the `pip` corresponding to the Python installation IDA is using.
In case you have more than one installation (for example 32 and 64 bits), you can find which one IDA uses by typing this into the console:

```python
import sys
sys.version
```

`cd` to the directory containing `setup.py`

__Release mode:__ `pip install .`

__Development (editable) mode:__ `pip install -e .[dev]`

In _development mode_, `pip` will install `pytest` and some linters helpful while developing, as well as creating symbolic links under python's packages directory instead of copying FIDL to it. This allows you to modify your `.py` files and test on the fly, without needing to reinstall every time you make a change :)


# Documentation

You can find up to date **documentation online** [here](https://fidl.readthedocs.io/en/latest/)

The source distribution has built-in documentation [here](./FIDL/docs/_build/html/index.html)
