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


# Running tests

Load the test IDB `putty.i64` (under tests/data) in IDA.
Now simply execute the `pytest_fidl.py` script (under tests) from within IDA (Alt + F7)


# NOTE

To import _FIDL_ into your own programs, use the uppercase form of the name, that is:

`import FIDL` or `import FIDL.decompiler_utils as du` will work but

`import fidl` will result in an import error


# Documentation

There is built-in documentation [here](./FIDL/docs/_build/html/index.html)



