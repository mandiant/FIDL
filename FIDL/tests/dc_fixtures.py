# =====================================================
# FIDL test fixtures
# =====================================================

import pytest

from idc import *
from idaapi import *
from idautils import *


@pytest.fixture
def calls_in_putty():
    """Simple hardcoded information regarding function
    calls about selected functions
    """

    calls_d = {
        # co (from c.calls)
        # k: co.ea
        # v: dict of 'call_ea' and 'name'
        0x1400880D8: {
            0x140088143: {'call_ea': 0x140080630, 'name': 'sub_140080630'},
            0x140088194: {'call_ea': 0x14008D7F8, 'name': 'sub_14008D7F8'},
            0x140088117: {'call_ea': 0x140080750, 'name': 'sub_140080750'},
            0x140088169: {'call_ea': 0x14007B2FC, 'name': 'sub_14007B2FC'},
            0x14008819D: {'call_ea': 0x140080750, 'name': 'sub_140080750'},
            0x1400880FC: {'call_ea': 0x140072C98, 'name': 'sub_140072C98'},
            0x140088138: {'call_ea': 0x140080750, 'name': 'sub_140080750'},
            0x140088122: {'call_ea': 0x140080630, 'name': 'sub_140080630'},
        },
        0x140055674: {
            0x1400556BE: {'call_ea': 0x1400905D0, 'name': 'GetProcAddress'},
            0x14005570A: {'call_ea': 0x1400905D0, 'name': 'GetProcAddress'},
            0x140055726: {'call_ea': 0x1400C0DD0, 'name': 'qword_1400C0DD0'},
            0x140055698: {'call_ea': 0x1400905D0, 'name': 'GetProcAddress'},
            0x1400556E4: {'call_ea': 0x1400905D0, 'name': 'GetProcAddress'},
            0x140055681: {'call_ea': 0x140065B68, 'name': 'sub_140065B68'},
        },
        # NOTE:
        # Insert additional functions here
    }

    return calls_d


@pytest.fixture
def locals_in_putty():
    """Hard-coded information regarding local variables
    """

    locals_d = {
        # k: index
        # v: dict of local properties
        0x14007DA84: {
            6: {'name': 'v6', 'size': 8, 'type_name': '__int64'},
            7: {'name': 'v7', 'size': 8, 'type_name': '__int64'},
            8: {'name': 'v8', 'size': 8, 'type_name': '__int64'},
            9: {'name': 'v9', 'size': 8, 'type_name': '__int64'},
            11: {'name': 'v11', 'size': 8, 'type_name': '__int64'},
            12: {'name': 'v12', 'size': 16, 'type_name': '__int128'},
            13: {'name': 'v13', 'size': 8, 'type_name': '__int64'},
            14: {'name': 'v14', 'size': 8, 'type_name': '__int64'},
            15: {'name': 'v15', 'size': 1, 'type_name': 'char'},
            16: {'name': 'v16', 'size': 1, 'type_name': 'char'},
            17: {'name': 'v17', 'size': 8, 'type_name': '__int64'},
            18: {'name': 'v18', 'size': 16, 'type_name': '__int128'},
            19: {'name': 'v19', 'size': 8, 'type_name': '__int64'},
            20: {'name': 'v20', 'size': 8, 'type_name': '__int64'},
            21: {'name': 'v21', 'size': 8, 'type_name': '__int64'},
            22: {'name': 'v22', 'size': 4, 'type_name': 'int'},
            23: {'name': 'v23', 'size': 4, 'type_name': 'int'},
            24: {'name': 'v24', 'size': 2, 'type_name': '__int16'},
            25: {'name': 'v25', 'size': 1, 'type_name': 'char'},
            26: {'name': 'v26', 'size': 8, 'type_name': '__int64'},
            27: {'name': 'v27', 'size': 4, 'type_name': 'int'},
            28: {'name': 'v28', 'size': 1, 'type_name': 'char'},
            29: {'name': 'v29', 'size': 4, 'type_name': 'int'},
            30: {'name': 'v30', 'size': 4, 'type_name': 'int'},
            31: {'name': 'v31', 'size': 8, 'type_name': 'char *'},
            32: {'name': 'v32', 'size': 8, 'type_name': '__int64'},
            33: {'name': 'v33', 'size': 8, 'type_name': '__int64'},
            34: {'name': 'v34', 'size': 8, 'type_name': '__int64'},
            35: {'name': 'v35', 'size': 8, 'type_name': '__int64'}
        },
        # NOTE:
        # Insert additional functions here
    }

    return locals_d
