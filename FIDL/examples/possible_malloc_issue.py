# ---------------------------------------------------------------
# Example from @fabs0x0 presentation about Joern
# https://fabs.codeminers.org/talks/2019-joern.pdf
#
# Note: this example is deliberately verbose.
# There are cleaner, leaner ways to implement this idea
# but the objective here is to  showcase the API.
# ---------------------------------------------------------------

from ida_hexrays import cot_add
import FIDL.decompiler_utils as du


def find_possible_malloc_issues(c=None):
    """Searches for instances where malloc argument may wrap around
    and there's a dangerous use of it in a memory write operation.

    :param c: a :class:`controlFlowinator` object
    :type c: :class:`controlFlowinator`
    :return: a list of dict containing free-form information
    :rtype: list
    """

    results = []
    suspicious_lens = []

    mallocz = du.find_all_calls_to_within('malloc', c.ea)
    memcpyz = du.find_all_calls_to_within('memcpy', c.ea)

    if not mallocz or not memcpyz:
        return []

    # Check whether the ``malloc`` call contains an arithmetic
    # expression as function argument. We are only looking
    # for additions in this case
    for co in mallocz:
        m_arg = co.args[0]
        if m_arg.type != 'unk':
            continue

        is_ari = du.is_arithmetic_expression(
            m_arg.val,
            only_these=[cot_add])

        if is_ari:
            # Now, there are many ways to skin a cat...
            # we'll use the following on this example.
            # Assuming ``len + <number>`` -> ``len``
            lhs = m_arg.val.x  # looking for var_ref_t
            rhs = m_arg.val.y  # looking for an immediate

            if du.is_var(lhs) and du.is_number(rhs):
                real_var = du.ref2var(ref=lhs, c=c)

                # This is not strictly necessary but it is
                # recommended to use ``my_var_t`` objects if
                # possible, since they contain a lot of useful
                # properties/methods
                my_var = du.my_var_t(real_var)

                suspicious_lens.append(my_var)

    # Are there any of these "suspicious" length variables
    # being used in a memcpy?
    for lv in suspicious_lens:
        for co in memcpyz:
            # memcpy(src, dst, size)  // size: 3rd arg
            sv = co.args[2]

            # Checking whether the `size` parameter is a variable,
            # it could be a constant as well...
            if sv.type == 'var':
                v_name = sv.val.name
                # Checking whether two local variables are the same
                # is better done by comparing their names.
                if lv.name == v_name:
                    res = {
                            'ea': c.ea,
                            'msg': "Check use of {} at {:X}".format(
                                lv.name,
                                co.ea,
                                )}
                    results.append(res)

    return results


def main():
    results = du.do_for_all_funcs(
        find_possible_malloc_issues,
        min_size=0,
        fast=False)

    print("=" * 80)
    print(results)


if __name__ == '__main__':
    main()
