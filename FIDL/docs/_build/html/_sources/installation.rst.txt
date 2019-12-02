.. _installation_label::

Installation
============

FIDL is just another Python package living within your local Python installation. There are two ways to install it:


Install from source
-------------------

1. cd to the repository's directory containing setup.py
2. Use your installation's Pip:

    - ``pip install .`` (for *Release* mode)
    - ``pip install -e .[dev]`` (for *Development/Editable* mode)

In *development mode*, Pip will install Pytest and some linters helpful while developing, and create symbolic links under Python's packages directory instead of copying *FIDL* to it. This allows you to modify your ``.py`` files and test on the fly, without need to reinstall every time you make a change.


Install from PyPi
-----------------

FIDL is in PyPi. If you are able to reach PyPi, installing is as easy as:

    ``pip install FIDL``


Running tests
-------------

Load the test IDB ``putty.i64`` (under *tests/data*) in IDA.

Now simply execute the ``pytest_fidl.py`` script (under *tests*) from within IDA (``Alt + F7``)

.. warning::

    There is an issue related to testing with Pytest in Python3.
    Tests are not working for IDA with Python3 at the moment.
