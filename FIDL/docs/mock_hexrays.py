# -------------------------------------------------------------------------
# Mock ida_hexrays to use sphinx's autodoc
#
# This creates a Python file containing the definitions of all
# `cit_*` and `cot_*` constants
# These are needed in Sphinx's `conf.py` (See `Mocking Hex-Rays` there)
#
# These constant definitions should not change, since this would break
# most HexRays scripts, but one never knows...
# Should this happen, use this script to recreate the definitions.
# -------------------------------------------------------------------------

import ida_hexrays as ih


def main():
    # All method's __names__
    m = dir(ih)

    # Name filtering
    ci = [x for x in m if x.startswith('cit_')]
    co = [x for x in m if x.startswith('cot_')]

    m_consts = ci + co

    with open("mock_hexrays_consts.py", "w") as f:
        f.write("import mock\n")
        f.write("\n\nm=mock.Mock()\n")
        for name in m_consts:
            value = getattr(ih, name)
            f.write("m.{} = {}\n".format(name, value))

    print("Done.")


if __name__ == '__main__':
    main()
