# =====================================================
# Functional Tests
#
# These are intended to run within IDA, acting on a
# known binary
# =====================================================

from collections import Counter

from idc import *
from idaapi import *
from idautils import *

import ida_hexrays

from dc_fixtures import calls_in_putty, locals_in_putty
from FIDL import decompiler_utils as du


def test_file_loaded():
    """We test on a known PuTTY IDB file"""
    md5_hex = GetInputFileMD5()
    assert md5_hex == '227DEFDC09BF329D4ADF7CAB6E7CAD74'


def test_calls(calls_in_putty):
    """Checks the `calls` in a `controlFlowinator` object"""

    for f_ea, f_call_info in calls_in_putty.items():
        c = du.controlFlowinator(ea=f_ea, fast=False)
        if not c:
            continue

        # ------------------------------------------------------
        # Extract hard-coded information and compare with the
        # result of `controlFlowinator.calls`
        # ------------------------------------------------------

        # Function names within this call
        names = [co.name for co in c.calls]
        namez = [x['name'] for x in f_call_info.values()]

        assert Counter(names) == Counter(namez)

        # Location of function calls
        locs = [co.call_ea for co in c.calls]
        locz = [i['call_ea'] for i in f_call_info.values()]

        assert Counter(locs) == Counter(locz)


def test_locals(locals_in_putty):
    """Checks the `lvars` in a `controlFlowinator` object"""

    for f_ea, locals_info in locals_in_putty.items():
        c = du.controlFlowinator(ea=f_ea, fast=False)
        if not c:
            continue

        # ------------------------------------------------------
        # Extract hard-coded locals information and compare with
        # the result of `controlFlowinator.calls`
        # ------------------------------------------------------

        for i, lv in c.lvars.items():
            # Local variable names
            name = lv.name  # calculated at run-time
            namez = locals_info[i]['name']  # stored

            assert name == namez

            # Local variable sizes
            size = lv.size
            sizez = locals_info[i]['size']

            assert size == sizez

            # Local variable types
            calc_type = lv.type_name
            must_type = locals_info[i]['type_name']

            assert Counter(calc_type) == Counter(must_type)
