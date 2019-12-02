"""Pytest based tests for FIDL

The tests can be run within IDA :)
See Daniel's blog: https://pnx-tf.blogspot.com/2012/11/tdd-idapython.html
"""

import os
import sys
from datetime import datetime
import pytest


# -----------------------------------------------------------------------------
# Auxiliary
# -----------------------------------------------------------------------------
def snow():
    """Readable now"""
    return datetime.now().strftime("%d %B %Y %H:%M:%S")


def main():
    print("-" * 60)
    print("Started tests at @ {}".format(snow()))

    pytest.main(['--capture=sys', os.path.dirname(__file__)])

    print("Finished tests at @ {}".format(snow()))


if __name__ == "__main__":
    main()
