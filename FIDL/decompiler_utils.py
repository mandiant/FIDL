# -*- coding: utf-8 -*-

# ===========================================================================
# Decompiler utils
#
# This is a set of utilities wrapping the decompiler API into something
# sane. This code focus on vulnerability research and bug hunting,
# however most of the functionality is generic enough to be used for
# broader reverse engineering purposes.
#
# Carlos Garcia Prado
# <carlos.garcia@fireeye.com>
# ===========================================================================

__version__ = '1.2'

from idc import *
from idaapi import *
from idautils import *

import ida_hexrays

from FIDL.compiler_consts import expr_condition
from FIDL.compiler_consts import expr_ctype  # To pretty print debug messages
from FIDL.compiler_consts import expr_final, expr_assignments, insn_conditions

import os
import random
import traceback
import networkx as nx
from collections import namedtuple, defaultdict, OrderedDict
from six.moves import xrange

DEBUG = False


# ===========================================================
# Auxiliary functions
# ===========================================================
def dprint(s=""):
    """This will print a debug message only if debugging is active

    :param s: The debug message
    :type s: str, optional
    """
    if DEBUG:
        print(s)


# networkx expects nodes to be hashable. We monkey patch some of IDA's type to
# implement the __hash__ method so they can be used as nodes.
_hash_from_obj_id = lambda self: hash(self.obj_id)
ida_hexrays.cexpr_t.__hash__ = _hash_from_obj_id
ida_hexrays.cinsn_t.__hash__ = _hash_from_obj_id
ida_hexrays.carg_t.__hash__ = _hash_from_obj_id


def debug_get_break_statements(c):
    for n in c.g.nodes():
        if n.op == cit_if:
            cex = n.cif.expr
        elif n.op == cit_return:
            cex = n.creturn.expr
        elif n.op == cit_for:
            cex = n.cfor.expr
        elif n.op == cit_while:
            cex = n.cwhile.expr
        elif n.op == cit_do:
            cex = n.cdo.expr
        else:
            cex = n
        if cex.op == cit_break:
            return [c.ea]
        operands = blowup_expression(cex)
        for operand in operands:
            if operand.op == cit_break:
                return [c.ea]
    return [0]


def debug_stahp():
    """Toggles ``DEBUG`` value, useful for testing
    """
    global DEBUG

    DEBUG = not DEBUG


def NonLibFunctions(start_ea=None, min_size=0):
    """Generator yielding only non-lib functions

    :param start_ea: Address to start looking for non-library functions.
    :type start_ea: int, optional
    :param min_size: Minimum function size. Useful to filter small, \
    uninteresting functions.
    :type min_size: int, optional
    """

    for f_ea in Functions(start=start_ea):
        flags = get_func_attr(f_ea, FUNCATTR_FLAGS)
        if flags & FUNC_LIB or flags & FUNC_THUNK:
            continue

        # Min size check
        f = get_func(f_ea)
        if f.size() < min_size:
            continue

        yield f_ea


def do_for_all_funcs(func, fast=True, start_ea=None, blacklist=None,
                     min_size=100, **kwargs):
    """This is a generic wrapper for all kinds of logic that we want to apply \
    to all the functions in the binary.

    :param func: function "pointer" performing the analysis. \
    Its only mandatory argument is a :class:`controlFlowinator` object.
    :type func: function
    :param fast: parameter fast for the :class:`controlFlowinator` object.
    :type fast: boolean, optional
    :param start_ea: Address to start looking for non-library functions.
    :type start_ea: int, optional
    :param blacklist: a function determining whether to process a function.\
    Implemented via dependency injection.
    :type blacklist: function, optional
    :return: A list of JSON-like messages (individual function results)
    :rtype: list
    """

    results = []

    for f_ea in NonLibFunctions(start_ea=start_ea, min_size=min_size):

        # Since this is pretty CPU intensive, the following
        # offers a mechanism for skipping some functions
        def nope(x): return False
        is_blacklisted = blacklist or nope
        if is_blacklisted(f_ea):
            continue

        try:
            c = controlFlowinator(ea=f_ea, fast=fast)  # CFG
        except Exception as e:
            print(e)
            continue

        res = func(c, **kwargs)

        # Functions return a __list__ of JSON-like messages
        # Consolidate all lists into one by using the
        # overloaded addition operator
        if res:
            results += res

    return results


def my_get_func_name(ea):
    """Wrapper for :class:`get_func_name` handling some corner cases.

    :param ea: Address of the function to resolve its name
    :type ea: int
    """

    f_name = get_func_name(ea)

    if not f_name:
        # This could be a function pointer
        # stored in a global variable
        f_name = get_name(ea)

    if not f_name:
        # Maybe an import?
        # TODO: some kind of caching or memoization
        imp = cImporter()
        import_dict = imp.get_imports_info()

        f_name = import_dict.get(ea, "")

    return f_name


class cImporter:
    """Collect import information

    This is mainly to work around the fact that :func:``get_func_name`` does \
    not resolve imports...
    """

    def __init__(self):
        self.import_dict = {}

    def _imp_cb(self, ea, name, ord):
        if name:
            self.import_dict[ea] = name
        else:
            print("Could not resolve import name!")

        return True

    def _find_imports_info(self):
        nimps = get_import_module_qty()

        for i in xrange(0, nimps):
            name = get_import_module_name(i)
            if not name:
                continue

            enum_import_names(i, self._imp_cb)

    def get_imports_info(self):
        self._find_imports_info()
        return self.import_dict


class BBGraph(object):
    """Representation of the assembly CFG for a function
    """

    def __init__(self, f_ea):
        self.f_ea = f_ea
        self.f = FlowChart(get_func(f_ea), None, FC_PREDS)
        self.bb_list = self._get_basic_blocks()

    def _get_basic_blocks(self):
        """List of tuples containing basic blocks limits"""
        return [(bb.startEA, bb.endEA) for bb in self.f]

    def _get_function_graph(self):
        """It creates a graph of basic blocks and their children.

        returns: dict { block_ea: [branch1_ea, branch2_ea], ... }
        """

        bb_dict = defaultdict(set)  # Dict of BasicBlock objects

        for bb in self.f:
            for child in bb.succs():
                bb_dict[bb.startEA].add(child.startEA)

        return bb_dict

    def _graph_to_networkx(self):
        """Gets a bb_dict (see _get_function_graph) and converts \
        this to a NetworkX format
        """

        bb_dict = self._get_function_graph()

        if not bb_dict:
            return None

        try:
            dg = nx.DiGraph()
        except NameError as e:
            # NetworkX is not installed
            return None

        for node, children in bb_dict.items():
            for child in children:
                dg.add_edge(node, child)

        return dg

    def _get_block_from_ea(self, ea):
        """It returns the _BasicBlock_ containing ``ea`` or None
        """

        for bb in self.f:
            # Remember that bb.endEA is bb.startEA of the next one!
            if ea >= bb.startEA and ea < bb.endEA:
                return bb

        return None

    def get_node(self, addr):
        """Given a function's address, returns the basic block (address) that \
        contains it (or None)

        :param addr: address within a function
        :type addr: int
        :return: Address of the node containing the input address
        :rtype: int
        """

        node_addr = None

        for start, end in self.bb_list:
            if addr >= start and addr < end:
                # The address is within this basic block
                node_addr = start
                break

        return node_addr

    def find_connected_paths(self, bb_start, bb_end, co=10):
        """Leverages NetworkX to find all connected paths

        :param bb_start: Initial basic block
        :type bb_start: Basic block
        :param bb_end: Final basic block
        :type bb_end: Basic block
        :param co: Cutoff parameter
        :type co: int, optional

        NOTE: the cutoff parameter in :class:`nx.all_simple_paths` serves \
        two purposes:

        - reduce the chances of CPU melting (algo is O(n!))
        - nobody will inspect (manually) monstruous paths

        :returns: generator of lists or None
        """

        g = self._graph_to_networkx()
        if not g:
            return None

        # Sanity check.
        # Basic blocks within current function?
        bbl = [bb.startEA for bb in self.f]

        # bbl contains startEA's. However, we may have clicked
        # *somewhere* within the basic block
        _bb_start = self._get_block_from_ea(bb_start).startEA
        _bb_end = self._get_block_from_ea(bb_end).startEA

        if _bb_start in bbl and _bb_end in bbl:
            paths = nx.all_simple_paths(
                g,
                source=_bb_start,
                target=_bb_end,
                cutoff=co)
            return paths
        else:
            print('[!] find_connected_paths: check bb_start, bb_end parameters')
            return None


# ===========================================================
# Lighthouse utilities
# (from: https://github.com/gaasedelen/lighthouse)
# These help processing the displayed decompiled code
# For example: painting specific lines of code
# ===========================================================
def map_line2citem(decompilation_text):
    """Part of `Lighthouse plugin <https://github.com/gaasedelen/lighthouse>`_

    Map decompilation line numbers to citems.
    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.
    """

    line2citem = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    for line_number in xrange(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = lex_citem_indexes(line_text)

    return line2citem


def map_line2node(cfunc, line2citem):
    """Part of `Lighthouse plugin <https://github.com/gaasedelen/lighthouse>`_

    Map decompilation line numbers to node (basic blocks) addresses.
    This function allows us to build a relationship between graph nodes
    (basic blocks) and specific lines in the hexrays decompilation text.
    """

    line2node = {}
    treeitems = cfunc.treeitems
    function_address = cfunc.entry_ea
    bb_graph = BBGraph(function_address)

    #
    # prior to this function, a line2citem map was built to tell us which
    # citems reside on any given line of text in the decompilation output.
    #
    # now, we walk through this line2citem map one 'line_number' at a time in
    # an effort to resolve the set of graph nodes associated with its citems.
    #

    for line_number, citem_indexes in line2citem.items():
        nodes = set()

        #
        # we are at the level of a single line (line_number). we now consume
        # its set of citems (citem_indexes) and attempt to identify the explict
        # graph nodes they claim to be sourced from (by their reported EA)
        #

        for index in citem_indexes:

            # get the code address of the given citem
            try:
                item = treeitems[index]
                address = item.ea

            # apparently this is a thing on IDA 6.95
            except IndexError as e:
                continue

            # find the graph node (eg, basic block) that generated this citem
            node_addr = bb_graph.get_node(address)

            # address not mapped to a node... weird. continue to the next citem
            if not node_addr:
                continue

            #
            # we made it this far, so we must have found a node that contains
            # this citem. save the computed node_id to the list of of known
            # nodes we have associated with this line of text
            #

            nodes.add(node_addr)

        #
        # finally, save the completed list of node ids as identified for this
        # line of decompilation text to the line2node map that we are building
        #

        line2node[line_number] = nodes

    # all done, return the computed map
    return line2node


def lex_citem_indexes(line):
    """Part of `Lighthouse plugin <https://github.com/gaasedelen/lighthouse>`_

    Lex all ctree item indexes from a given line of text.
    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.
    """

    i = 0
    indexes = set([])
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                citem_index = int(line[i:i + COLOR_ADDR_SIZE], 16)
                i += COLOR_ADDR_SIZE

                # SANITY CHECK
                # NOTE: this value is arbitrary (although reasonable)
                # FIX: get this from cfunc.treeitems.size()
                if citem_index < 0x1000:
                    # save the extracted citem index
                    indexes.add(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes


def map_node2lines(line2node):
    """Part of `Lighthouse plugin <https://github.com/gaasedelen/lighthouse>`_

    Creates a mapping of nodes to lines of code
    """

    node2lines = defaultdict(set)

    for line, node_set in line2node.items():
        for node_addr in node_set:
            node2lines[node_addr].add(line)

    return node2lines


def map_citem2line(line2citem):
    """Part of `Lighthouse plugin <https://github.com/gaasedelen/lighthouse>`_

    Creates a mapping of citem indexes to lines of code
    """

    citem2line = {}

    for line, citem_l in line2citem.items():
        for citem_idx in citem_l:
            citem2line[citem_idx] = line

    return citem2line


def citem2higher(citem):
    """This gets the higher representation of a given :class:``citem``, \
    that is, a :class:``cinsn_t`` or :class:``cexpr_t``

    :param citem: a :class:``citem`` object
    :type citem: :class:``citem``
    """

    if citem.is_expr():
        return citem.cexpr

    return citem.cinsn


# ===========================================================
# Hex-rays hacks :)
# ===========================================================
class my_var_t:
    """This wraps the :class:`lvar_t` nicely into a more usable data structure.

    It aggregates several interesting pieces of information in one place. \
    eg. ``is_arg``, ``is_constrained``, ``is_initialized``, etc.

    The most commonly used attributes for this class are:

    - name
    - type_name
    - size
    - is_arg
    - is_pointer
    - is_array
    - is_signed

    :param var: an object representing a local variable or function argument
    :type var: :class:`lvar_t`
    """

    def __init__(self, var):
        self.var = var
        self.name = self.var.name
        self.type_name = ''
        self.size = 0
        self.ti = None
        self.is_signed = False
        self.is_array = False
        self.array_type = None
        self.element_size = 0
        self.array_len = 0
        self.complex_type = None
        self.is_pointer = False
        self.pointed_type = None

        # Convenience
        self.is_arg = self.var.is_arg_var

        # Shit gets real here
        self.is_tainted = False
        self.is_constrained = False
        self.is_initialized = False

        # Auxiliary for taint/constraint tracking
        # A specific variable might be a function
        # of others, ex: v1 = v2 * v3 + 1
        # is_a_function_of -> [v2, v3]
        self.is_a_function_of = []

        self._get_var_type()

    def _get_var_type(self):
        """Variable type information"""

        tif = self.var.type()  # tinfo_t

        # This is useful to call its `is_int`
        # and similar functions
        # Ex. `my_var_t.ti.is_int()`
        self.ti = tif

        # Interesting for integer types
        self.is_signed = tif.is_signed()
        # Something like `__int64`
        self.type_name = str(tif)

        # For an array this is the number of elements
        # Ex: char arr[1234] -> 1234
        self.size = tif.get_size()

        # This adds the type of the array
        # Ex: __int16 arr[123] -> __int16
        if tif.is_array():
            self.is_array = True
            self.array_type = tif.get_array_element()
            self.element_size = self.array_type.get_size()
            if self.element_size:
                self.array_len = self.size / self.element_size

        # Ex: char *str -> char (None if the type is not a pointer)
        if tif.is_ptr():
            self.is_pointer = True
            self.pointed_type = tif.get_pointed_object() or None

        # Ex: struct _SYSTEMTIME st -> _SYSTEMTIME
        if self.is_pointer:
            _tif = self.pointed_type
        else:
            _tif = tif

        self.complex_type = _tif.get_type_name() or ""

    def __repr__(self):
        print("Name: {}".format(self.name))
        print("  Type name: {}".format(self.type_name))
        print("  Size: {}".format(self.size))

        # Optional stuff (not all vars have this)
        if self.array_type:
            print("  Array type: {}".format(self.array_type))
            print("  Array element size: {}".format(self.element_size))
            print("  Array length: {}".format(self.array_len))

        if self.complex_type:
            print("  Complex type: {}".format(self.complex_type))

        # At a first glance, this may seem odd. It is correct.
        pointed_type_s = "{}".format(self.pointed_type)
        if len(pointed_type_s) and pointed_type_s != 'None':
            print("  Pointed object: {}".format(pointed_type_s))

        return ""


def get_return_type(cf=None):
    """Hack to get the return value of a function.

    :param cf: the result of ``decompile()``
    :type cf: :class:`ida_hexrays.cfuncptr_t`
    :return: Type information for the return value
    :rtype: :class:`tinfo_t`
    """

    if not cf:
        raise ValueError

    ty = cf.type  # tinfo_t (entire prototype)
    ti = ty.get_rettype()  # tinfo_t (return value)

    return ti


# ===========================================================
# Convenience functions
# ===========================================================
class pseudoViewer:
    """This wraps the :class:`pseudoViewer` API neatly.

    We need it because some things don't work unless \
    you previously visited (or are currently visiting) \
    the function whose decompiled form you want to analyze. \
    Thus, we are forced to "Hack like in the movies"

    TODO: probably deprecate this after IDA 7.5 changes
    NOTE: the performance penalty is negligible
    """

    silent_flags = ida_hexrays.OPF_REUSE | ida_hexrays.OPF_NO_WAIT

    def __init__(self):
        self.vdui = None
        self.p_twidget = None

    def show(self, ea=0, flags=silent_flags):
        """Displays the pseudoviewer widget

        :param ea: adress of the function to display
        :type ea: int, optional
        :param flags: how to flags an existing pseudocode display, if any
        :type flags: int, optional
        """

        try:
            self.vdui = open_pseudocode(ea, flags)
            if self.vdui:
                self.p_twidget = self.vdui.ct
        except Exception as e:
            print("ERROR (pseudoViewer.show) @ {:#08x}".format(ea))
            print(e)

    def close(self):
        """Closes the pseudoviewer widget
        """

        close_pseudocode(self.p_twidget)


def get_function_vars(c=None, ea=0, only_args=False, only_locals=False):
    """Populates a dict of :class:`my_var_t` for the function
    containing the specified ``ea``

    :param c: a :class:`controlFlowinator` object, optional
    :type c: :class:`controlFlowinator`
    :param ea: the function address
    :type ea: int
    :param only_args: extract only function arguments
    :type only_args: bool, optional
    :param only_locals: extract only local variables
    :type only_locals: bool, optional
    :return: A dictionary of :class:`my_var_t`, indexed by their index
    """

    if not c:
        try:
            cf = my_decompile(ea=ea)
        except DecompilationFailure as e:
            print("ERROR (get_function_vars)")
            print(repr(str(e)))
            return {}
    else:
        cf = c.cf

    # Successful decompilation at `ea` point
    # `cf.lvars` is an array of `lvars_t`
    # `idx` is the index into this array to be used later
    #
    # I need to re-order the list of arguments.
    # No idea why, but IDA does not spit the arguments in order.
    # It keeps however a list of how the indexes are messed up in ``c.cf.argidx``
    ordered_vars = [None] * len(cf.lvars)

    for i, v in enumerate(cf.lvars):
        if v.is_arg_var:
            # Need to fix order
            idx = cf.argidx[i]
        else:
            # Local vars seem to be fine
            idx = i

        ordered_vars[idx] = v

    if only_args:
        return OrderedDict({idx: my_var_t(v) for idx, v in enumerate(ordered_vars)
                            if v.is_arg_var and v.name})
    elif only_locals:
        return OrderedDict({idx: my_var_t(v) for idx, v in enumerate(ordered_vars)
                            if not v.is_arg_var and v.name})
    else:
        return OrderedDict({idx: my_var_t(v) for idx, v in enumerate(ordered_vars)})


def ref2var(ref, c=None, cf=None):
    """Convenient wrapper to streamline the conversions
    between ``var_ref_t`` and ``lvar_t``

    :param c: a :class:`controlFlowinator` object, optional
    :type c: :class:`controlFlowinator`
    :param cf: a decompilation object (usually the result of ``decompile``), optional
    :type cf: a :class:`cfunc_t` object
    :param ref: a reference to a variable in the pseudocode
    :type ref: :class:`var_ref_t`
    :return: a :class:`lvar_t` object
    :rtype: :class:`lvar_t`
    """

    if not c and not cf:
        raise RuntimeError('Need c or cf parameters. None was passed to ref2var')

    if not cf and c:
        cf = c.cf

    return cf.lvars[ref.v.idx]


def is_arithmetic_expression(cex, only_these=[]):
    """Checks whether this is an arithmetic expression.

    :param cex: expression, usually this is a *node*.
    :type cex: :class:`cexpr_t`
    :param only_these: a list of arithmetic expressions to look for. \
    These are defined in :mod:`ida_hexrays`
    :type only_these: a list of ``cot_*`` constants, eg. ``cot_add``.
    :return: True or False
    :rtype: bool
    """

    arith_ops = [cot_add, cot_mul, cot_sub]

    interesting_ops = only_these or arith_ops

    if cex.op in interesting_ops:
        return True

    # Let's go down only a level since most common expressions
    # are something like "v4 + 1", "v3 * 2 + 1", etc.
    _x = cex.x
    _y = cex.y

    for e in (_x, _y):
        # e: left / right hand side of the comparison
        if e and e.op in interesting_ops:
            return True

    return False


def is_binary_truncation(cex):
    """Looking for expressions truncating a number

    These expressions are of the form ``v1 & 0xFFFF`` or alike

    :param cex: an expression
    :type cex: :class:cexpr_t
    :return: True or False
    :rtype: bool
    """

    res = find_elements_of_type(cex, element_type=cot_band)
    if not res:
        return False

    for band_e in res:
        rhs = band_e.y
        if is_number(rhs):
            return True

    return False


# ============================================================
# The following wrappers are not rocket science
# but the code resulting from using them
# is __way__ more legible...
# ============================================================
def is_array_indexing(ins):
    if ins.op == cot_idx:
        return True

    return False


def is_cast(ins):
    if ins.op == cot_cast:
        return True

    return False


def decast(ins):
    """Remove the ``cast``, returning the casted element
    """

    if is_cast(ins):
        ins = ins.x

    return ins


def is_asg(ins):
    if ins.op in expr_assignments.keys():
        return True

    return False


def is_call(ins):
    if ins.op == cot_call:
        return True

    return False


def is_ref(ins):
    if ins.op == cot_ref:
        return True

    return False


def ref_to(ins):
    if ins.op == cot_ref:
        ins = ins.x

    return ins


def is_ptr(ins):
    if ins.op == cot_ptr:
        return True

    return False


def points_to(ins):
    if ins.op == cot_ptr:
        ins = ins.x

    return ins


def is_number(ins):
    """Convenience wrapper"""
    if ins.op == cot_num:
        return True

    return False


def num_value(ins):
    """Returns the numerical value of ``ins``

    :param ins: :class:`cexpr_t` or :class:`insn_t`
    """

    if not is_number(ins):
        raise TypeError

    return ins.n.value(ins.type)


def is_string(ins):
    """Convenience wrapper"""
    if ins.is_cstr():
        return True

    return False


def string_value(ins):
    """Gets the string corresponding to ``ins``

    Works with *C-str* and *Unicode*

    :param ins: :class:`cexpr_t` or :class:`insn_t`
    :return: string for this ``ins``
    :rtype: string
    """

    if not is_string(ins):
        raise TypeError

    str_ea = ins.obj_ea
    str_type = get_str_type(str_ea) & 0xF

    # Python 3: get_strlit_contents returns bytes now
    str_b = get_strlit_contents(str_ea, -1, str_type)
    return str_b.decode('utf-8')


def is_var(ins):
    """Whether this ``ins`` corresponds to a variable

    Remember that if this evaluates to True, we are dealing
    with an object of type ``var_ref_t`` which are pretty much
    useless. We may want to convert this to a ``lvar_t`` and
    even better to a :class:`my_var_t` afterwards.

    :func:`ref2var` is a simple wrapper to perform the conversion
    between reference and variable
    """

    if ins.op == cot_var:
        return True

    return False


def is_global_var(ins):
    """Tells whether ``ins`` is a global variable

    TODO: enhance this heuristic

    :param ins: :class:`cexpr_t` or :class:`insn_t`
    :return: True or False
    :rtype: bool
    """

    if ins.op == cot_obj:
        if not ins.is_cstr():
            if ins.obj_ea > 0:
                return True

    return False


def value_of_global(ins):
    """Returns the value of a global variable
    """

    if not is_global_var(ins):
        raise TypeError

    return ins.obj_ea


def is_if(ins):
    if ins.op == cit_if:
        return True

    return False


# ===========================================================
# Auxiliary
# ===========================================================
def my_decompile(ea=None):
    """This sets flags necessary to use this programmatically.

    :param ea: Address within the function to decompile
    :type ea: int
    :return: decompilation object
    :rtype: a :class:`cfunc_t`
    """

    if not ea:
        print("Please specify an address (ea)")
        return None

    try:
        cf = decompile(
                       ea=ea,
                       flags=ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_NO_CACHE
                       )
        cf.refresh_func_ctext()
    except ida_hexrays.DecompilationFailure as e:
        print("Failed to decompile @ {:X}".format(ea))
        cf = None

    return cf


def dump_pseudocode(ea=0):
    """Debugging helper.
    """

    print("~~~~ Dumping pseudocode ~~~~")

    cf = my_decompile(ea=ea)
    if not cf:
        print("Failed to decompile @ {:X}".format(ea))
        return None

    ps = cf.pseudocode
    for idx, sline in enumerate(ps):
        print("[{}] {}".format(idx, tag_remove(sline.line)))


def dump_lvars(ea=0):
    """Debugging helper.
    """

    print("~~~~ Dumping local variables ~~~~")

    try:
        cf = controlFlowinator(ea=ea)
    except Exception as e:
        print("Failed to decompile {:X}".format(ea))
        return None

    print()
    print(c.lvars)


def lines_and_code(cf=None, ea=0):
    """Mapping of line numbers and code

    :param cf: a decompilation object
    :type cf: an :class:`cfunc_t` object, optional
    :param ea: Address within the function to decompile, if no `cf` is provided
    :type ea: int, optional
    :return: a dictionary of lines of code, indexed by line number
    :rtype: dict
    """

    code = {}

    if not cf:
        cf = my_decompile(ea=ea)

    if cf:
        # Decompilation successful
        ps = cf.pseudocode

        for idx, sline in enumerate(ps):
            # Lines of code start at 1
            code[idx + 1] = tag_remove(sline.line)

    return code


def all_paths_between(c, start_node=None, end_node=None, co=40):
    """Calculates all paths between ``start_node`` and ``end_node``

    Calculating paths is one of these things that \
    is better done with the paralell index graph (``c.i_cfg``) \
    It haywires when done with complex elements.

    FIXME: the co (cutoff) param is necessary to avoid complexity
    explosion. However, there is a problem if it's reached...

    :param c: a :class:`controlFlowinator` object
    :type c: :class:`controlFlowinator`
    :param start_node: a :class:`controlFlowinator` node
    :type start_node: :class:`cexpr_t`
    :param start_node: a :class:`controlFlowinator` node
    :type start_node: :class:`cexpr_t`
    :param co: the *cutoff* value controls the maximum path length.
    :type co: int, optional
    :return: it **yields** a list of nodes for each path
    :rtype: list
    """

    if not start_node:
        start_index = min(c.i_cfg.nodes)
    else:
        start_index = c.node2index[start_node]

    # Use the node with the highest index
    # as default value
    if not end_node:
        node_indexes = [n.index for n in c.g.nodes()]
        # higher value is usually
        # the last return node
        if node_indexes:
            end_index = max(node_indexes)
        else:
            end_index = start_index
    else:
        end_index = c.node2index[end_node]

    # Find all *simple* paths
    # These paths are lists of citem indexes
    try:
        all_paths_i = nx.all_simple_paths(
            c.i_cfg,
            source=start_index,
            target=end_index,
            cutoff=co)
    except nx.NodeNotFound as e:
        # TODO: this problem is related to
        # the cutoff. Figure out what happens...
        traceback.print_exc()
        all_paths_i = []

    # ------------------------------------------------
    # Translate the indexes to cinsn_t, cexpr_t nodes
    # before yielding back to the caller
    # ------------------------------------------------
    for p_i in all_paths_i:
        p_nodes = [c.index2node[x] for x in p_i]
        yield p_nodes


def display_node(c=None, node=None, color=None):
    """Displays a given node in the ``pseudoviewer``

    :param c: a :class:`controlFlowinator` object
    :type c: :class:`controlFlowinator`
    :param node: a :class:`controlFlowinator` node
    :type node: :class:`cexpr_t`
    :param color: color to mark the line of code corresponding to `node`
    :type color: int, optional
    """

    cf = c.cf
    pseudo = cf.pseudocode
    line2citem = map_line2citem(pseudo)
    citem2line = map_citem2line(line2citem)
    code = lines_and_code(cf=cf)

    if not code:
        print("Mapping between lines and code not available!")
        return

    if not color:
        color = random.randint(0x202020, 0x808080)

    try:
        line = citem2line[node.index]
    except KeyError as e:
        print("display_node :: Error @ citem2line")

    print("{}: {}".format(line + 1, code[line + 1]))

    # Paint it!
    pseudo[line].bgcolor = color

    refresh_idaview_anyway()


def display_path(cf=None, path=None, color=None):
    """Shows a path's code and colors its lines.

    :param cf: a decompilation object
    :type cf: an :class:`cfunc_t` object, optional
    :param path: a list of ::class:`controlFlowinator` nodes
    :type path: list
    :param color: color to mark the lines of code corresponding to `path`
    :type color: int, optional
    :return: a list of function lines (path nodes)
    :rtype: list
    """

    path_lines = []

    if not cf:
        cf = my_decompile(ea=ea)

    pseudo = cf.pseudocode
    line2citem = map_line2citem(pseudo)
    citem2line = map_citem2line(line2citem)
    code = lines_and_code(cf=cf)

    if not code:
        print("Mapping between lines and code not available!")
        return []

    if not color:
        color = random.randint(0x202020, 0x808080)

    for node in path:
        try:
            line = citem2line[node.index]
        except KeyError as e:
            continue

        print("{}: {}".format(line + 1, code[line + 1]))
        path_lines.append(line + 1)

        # Paint it!
        pseudo[line].bgcolor = color

    refresh_idaview_anyway()

    return path_lines


def display_line_at(ea, silent=False):
    """Displays the line of pseudocode corresponding to ``ea``

    This is useful to quickly answer questions like:

        - "Is this function always called with its first parameter being a constant?"
        - "I want to see all the error messages displayed by this function"
        - etc.

    :param ea: address of an element contained within the line to display
    :type ea: int
    :param silent: flag controlling verbose output
    :type silent: bool
    """

    err_fmt = "{:X} FAIL: {}"

    try:
        c = controlFlowinator(ea=ea)
    except Exception as e:
        err = "Failed to decompile"
        return err_fmt.format(ea, err)

    pseudo = c.cf.pseudocode
    line2citem = map_line2citem(pseudo)
    citem2line = map_citem2line(line2citem)
    code = lines_and_code(cf=c.cf)

    if not code:
        print("Mapping between lines and code not available!")

    found = None
    for item in c.cf.treeitems:
        # `node` is a `cexpr_t` that may contain the call within
        # a more complex expression. Need to peek inside
        if item.ea == ea:
            found = True
            break

    if not found:
        err = "Could find that address"
        return err_fmt.format(ea, err)

    try:
        line = citem2line[item.index]
        line_info = "{:X} {}: {}".format(ea, line + 1, code[line + 1])
        if not silent:
            print(line_info)

        return line_info
    except KeyError as e:
        err = "KeyError:", e
        return err_fmt.format(ea, err)


def display_all_calls_to(func_name):
    """Wrapping :func:`display_line_at` since this is the most common use of this API

    :param func_name: name of the function to search references
    :type func_name: string
    """

    f_ea = get_name_ea_simple(func_name)
    if f_ea == BADADDR:
        print("Can not find {}".format(func_name))
        return None

    # We'll save the results and display all at the end,
    # otherwise the output gets clobbered with IDA's logging
    lines = []
    for ref in XrefsTo(f_ea, True):
        if not ref.iscode:
            continue

        lines.append(display_line_at(ref.frm, silent=True))

    print("==================================================")
    print("= All calls to {}".format(func_name))
    print("==================================================")
    for line in lines:
        print("- {}".format(line))


# ===========================================================
# CFG reconstruction
# ===========================================================
class controlFlowinator:
    """This is the main object of FIDL's API.

    It finds all decompiled code "blocks" and recreates a CFG based
    on this information.

    This gives us the best of both worlds: the possibility to
    analyze a graph (like in disassembly mode) and the power
    of :class:``citem`` based analysis.

    Some analysis is performed *after* the CFG has been
    constructed. These are rather cost intensive, so they are
    turned off by default. Use ``fast=False`` to apply these
    and get a better CFG.

    :param ea: address of the function to analyze
    :type ea: int
    :param fast: Set to ``False`` for an object with richer information
    :type fast: bool
    """

    def __init__(self, ea=None, fast=True):
        self.cf = my_decompile(ea=ea)

        if not self.cf:
            raise RuntimeError("controlFlowinator: failed to decompile")

        self.ea = self.cf.entry_ea
        self.fast = fast
        self.g = None

        # Information about local variables within this function
        # This is a dict of `my_var_t` objects
        self.lvars = None

        # Information about _this_ function arguments
        # This is a dict of `my_var_t` objects
        self.args = None

        # The return type of this function
        self.ret_type = None

        # A map of graph nodes and their indexes
        self.index2node = {}

        # Convenient to ve the reverse mapping
        self.node2index = {}

        # Superblock is the root
        superblock = self.cf.body.cblock
        self.i_cfg = self._get_root_cfg(superblock)
        blocks = self._get_blocks_to_expand(superblock)

        # Interim CFG of citem_t indexes
        # It is easier to create the initial graph
        # using indexes as nodes but convoluted to use
        self._generate_i_cfg(blocks_to_expand=blocks)

        # A `nx.Digraph` of `cinsn_t` or `cexpr_t`
        # It is easier to operate on this one,
        # it reduces API complexity
        self._generate_better_cfg()

        # =============================================================
        # The hybrid-CFG is ready now. We add some (optional) features
        # to this object, since they're useful in most cases
        # =============================================================

        # Information about calls within this function
        # This is a list of `callObj` objects
        self.calls = []

        # Retrieves a list of `callObj's`
        self._get_all_function_calls()

        if not fast:
            self.lvars = get_function_vars(c=self, only_locals=True)
            self.args = get_function_vars(c=self, only_args=True)
            self.ret_type = get_return_type(cf=self.cf)

    def _e(self, index):
        """Syntactic sugar"""

        try:
            return self.cf.treeitems[index]
        except Exception as e:
            print(e)

    def _stitch_together(self, nodes):
        """Stitches the cinsn_t in a block together

           This is an auxiliary function since the
           operation appears so commonly

           (A, B, C, ..., X) => A->B->C->...->X

           Returns a list of edges: [(A, B), (B, C), ...]
        """

        edges = []
        list_indexes = [x.index for x in nodes]

        if len(list_indexes) < 2:
            return []

        for idx in xrange(len(list_indexes) - 1):
            u = list_indexes[idx]
            v = list_indexes[idx + 1]
            edges.append((u, v))

        return edges

    def _get_root_cfg(self, super_block):
        """Creates the initial graph from the super_block
           It contains all blocks at recursion level 0

           Returns a `nx.Digraph`
        """

        root_edges = self._stitch_together(super_block)

        root = nx.DiGraph()

        if root_edges:
            root.add_edges_from(root_edges)
        else:
            # The function contains a single call
            root_index = self.cf.body.index + 1
            root.add_node(root_index)

        return root

    def _get_blocks_to_expand(self, node_list, succ=None):
        """Finds collapsed blocks to be expanded.

           Returns a list of cinsn_t
        """

        to_expand = []

        complex_blocks = (cit_if, cit_do, cit_while,
                          cit_switch, cit_for, cit_goto)

        for n in node_list:
            if n.op in complex_blocks:
                n.succ = succ
                to_expand.append(n)

        return to_expand

    def _get_block_successor(self, block):
        """Gets the successor for a given block

           FIXME: This has a problem with "void" function prototypes.
           The lack of _return_ node results in an absence of an implicit
           _ielse_ for the switch statements.

           Maybe introduce a dummy "ret" node in the CF?
        """

        succs = None

        try:
            succs = list(self.i_cfg.successors(block.index))
            if len(succs) > 1:
                print("More than one successor!")
                print("Check this out")

            if succs:
                succ = succs[0]
            else:
                succ = None
        except nx.NetworkXError as e:
            print("_get_block_successor: {}".format(e))
            succ = None

        if not succ:
            print("Block: {:#08x}".format(block.ea))
            print(" succs: {}".format(succs))
            print(" No successor! Take a look into this!")

        return succ

    def _expand_if_block(self, block):
        """Expands a given `if` block"""

        new_blocks = []

        iblock = {'ithen': block.cif.ithen}
        ielse = block.cif.ielse
        if ielse:
            iblock['ielse'] = ielse

        # 1. Find and save the original successor
        # NOTE: There may not be a successor?
        # ex: leaf branch
        succ = self._get_block_successor(block)

        # 2. If we have an ielse block, remove
        # the implicit ielse (the existing edge)
        if 'ielse' in iblock and succ:
            try:
                self.i_cfg.remove_edge(block.index, succ)
            except nx.NetworkXError as e:
                print(e)

        # 3. Add the edges to this node
        # (ithen and maybe ielse)
        for what, bl in iblock.items():
            branch = bl.cblock

            # Calculate new blocks to expand
            new_blocks += self._get_blocks_to_expand(branch, block.succ)

            # Stitch the instructions together
            if_edges = self._stitch_together(branch)
            if if_edges:
                self.i_cfg.add_edges_from(if_edges)

            # The cblock has one ins at least
            branch_ins = list(branch)
            if block.succ:
                for node in branch_ins:
                    if node.op == cit_break:
                        self.i_cfg.add_edge(node.index, block.succ)
            first = branch_ins[0]
            last = branch_ins[-1]

            # Add the edge between the if ins and
            # the first cblock element
            self.i_cfg.add_edge(block.index, first.index)

            # Connect to the orphaned successor
            # Unless it is a return, etc.
            if succ:
                if last.op not in (cit_return, cit_break):
                    self.i_cfg.add_edge(last.index, succ)

        return new_blocks

    def _expand_switch_block(self, block):
        """Expands a given `switch` block"""

        # 1. Find and save the original successor
        # NOTE: There may not be a successor?
        # ex: leaf branch

        new_blocks = []

        succ = self._get_block_successor(block)

        # Remove the original edge
        if succ:
            self.i_cfg.remove_edge(block.index, succ)

        switch = block.cswitch

        for case in switch.cases:
            case_block = case.cblock

            u = block
            case_ins = [i for i in case_block]

            new_blocks += self._get_blocks_to_expand(case_ins)

            for v in case_ins:
                self.i_cfg.add_edge(u.index, v.index)
                u = v

            # If the last element is a 'break' we can throw
            # this out and connect the last meaningful
            # citem to the end of the switch
            if v.op == cit_break:
                self.i_cfg.remove_node(v.index)

                if succ:
                    # u -> break => u -> succ
                    self.i_cfg.add_edge(case_ins[-2].index, succ)

        return new_blocks

    def _expand_do_block(self, block):
        """Expand a given `do` block"""

        succ = self._get_block_successor(block)

        # Remove the original edge
        if succ:
            self.i_cfg.remove_edge(block.index, succ)

        do_body = block.cdo.body
        do_block = do_body.cblock

        # Calculate new blocks to expand
        new_blocks = self._get_blocks_to_expand(do_block, succ)

        # Stitch the instructions together
        do_edges = self._stitch_together(do_block)
        if do_edges:
            self.i_cfg.add_edges_from(do_edges)

        # The cblock has one ins at least
        block_ins = list(do_block)
        if succ:
            for node in block_ins:
                if node.op == cit_break:
                    self.i_cfg.add_edge(node.index, succ)
        first = block_ins[0]
        last = block_ins[-1]

        # Add the edge between the do ins and
        # the first cblock element
        self.i_cfg.add_edge(block.index, first.index)

        # Add the edge to the original successor
        if succ:
            self.i_cfg.add_edge(last.index, succ)

        # Optional: Add a reference to show the looping structure
        self.i_cfg.add_edge(last.index, block.index)

        return new_blocks

    def _expand_while_block(self, block):
        """Expand a given `while` block"""

        succ = self._get_block_successor(block)

        # Remove the original edge
        if succ:
            self.i_cfg.remove_edge(block.index, succ)

        while_body = block.cwhile.body
        while_block = while_body.cblock

        # Calculate new blocks to expand
        new_blocks = self._get_blocks_to_expand(while_block, succ)

        # Stitch the instructions together
        while_edges = self._stitch_together(while_block)
        if while_edges:
            self.i_cfg.add_edges_from(while_edges)

        # The cblock has one ins at least
        block_ins = list(while_block)
        if succ:
            for node in block_ins:
                if node.op == cit_break:
                    self.i_cfg.add_edge(node.index, succ)
        first = block_ins[0]
        last = block_ins[-1]

        # Add the edge between the while ins and
        # the first cblock element
        self.i_cfg.add_edge(block.index, first.index)

        # Add the edge to the original successor
        if succ:
            self.i_cfg.add_edge(last.index, succ)

        # Optional: Add a reference to show the looping structure
        self.i_cfg.add_edge(last.index, block.index)

        return new_blocks

    def _expand_for_block(self, block):
        """Expand a given `for` block"""

        succ = self._get_block_successor(block)

        # Remove the original edge
        if succ:
            self.i_cfg.remove_edge(block.index, succ)

        for_body = block.cfor.body
        for_block = for_body.cblock

        # Calculate new blocks to expand
        new_blocks = self._get_blocks_to_expand(for_block, succ)

        # Stitch the instructions together
        for_edges = self._stitch_together(for_block)

        if for_edges:
            self.i_cfg.add_edges_from(for_edges)

        # The cblock has one ins at least
        block_ins = list(for_block)
        if succ:
            for node in block_ins:
                if node.op == cit_break:
                    self.i_cfg.add_edge(node.index, succ)
        first = block_ins[0]
        last = block_ins[-1]

        # Add the edge between the for ins and
        # the first cblock element
        self.i_cfg.add_edge(block.index, first.index)

        # Add the edge to the original successor
        if succ:
            self.i_cfg.add_edge(last.index, succ)

        # Optional: Add a reference to show the looping structure
        self.i_cfg.add_edge(last.index, block.index)

        return new_blocks

    def _expand_goto_block(self, block):
        """Expands a given `goto` block"""

        # Remove the current's `goto` successor
        # pointing to the next instruction
        succ = self._get_block_successor(block)

        if succ:
            self.i_cfg.remove_edge(block.index, succ)

        # Target is identified by its label number
        # NOTE: All citem_t has a label_number
        target_label = block.cgoto.label_num

        # Find the citem corresponding to that label
        target_citem = self.cf.find_label(target_label)
        target_idx = target_citem.index

        if target_idx:
            # goto -> target
            self.i_cfg.add_edge(block.index, target_idx)

        # This operation does not add new blocks
        return []

    def _generate_i_cfg(self, blocks_to_expand=[]):
        """This expands interesting blocks creating an
           increasingly complex graph.
           Each one of the methods `_expand_xxx_block`
           modify the `self.i_cfg` Digraph

           This works recursively until there are no blocks
           left to expand
        """

        if not blocks_to_expand:
            return

        for block in blocks_to_expand:
            new_blocks = []

            # Remove this block from the list
            blocks_to_expand.remove(block)

            # Modify CFG
            if block.op == cit_if:
                dprint()
                dprint(">> IF block @ {:#08x}...".format(block.ea))
                new_blocks = self._expand_if_block(block)
            elif block.op == cit_do:
                dprint()
                dprint(">> DO block @ {:#08x}...".format(block.ea))
                new_blocks = self._expand_do_block(block)
            elif block.op == cit_while:
                dprint()
                dprint(">> WHILE block @ {:#08x}...".format(block.ea))
                new_blocks = self._expand_while_block(block)
            elif block.op == cit_switch:
                dprint()
                dprint(">> SWITCH block @ {:#08x}...".format(block.ea))
                new_blocks = self._expand_switch_block(block)
            elif block.op == cit_for:
                dprint()
                dprint(">> FOR block @ {:#08x}...".format(block.ea))
                new_blocks = self._expand_for_block(block)
            elif block.op == cit_goto:
                dprint()
                dprint(">> GOTO block @ {:#08x}...".format(block.ea))
                new_blocks = self._expand_goto_block(block)

            # Add new found blocks to the list
            blocks_to_expand += new_blocks

            self._generate_i_cfg(blocks_to_expand=blocks_to_expand)

    def _generate_better_cfg(self):
        """Create a better representation of the interim CFG

           This one has {cinsn_t, cexpr_t} as nodes, instead of indexes
        """

        _lifted = {}
        self.g = nx.DiGraph()

        # ==================================================
        # Mapping between nodes {cinsn_t, cexpr_t}
        # and their indexes (from the computed i_cfg)
        # ==================================================
        _nodez = {}
        j = 0
        sind = 0  # single node index

        for i in self.i_cfg.nodes():
            obj = self._e(i)

            hi = citem2higher(obj)  # cinsn_t
            if hi.op == cit_expr:
                hi = hi.cexpr
                j = hi.index
                # i -> j
                _lifted[i] = j
                i = j
            else:
                _lifted[i] = i

            sind = i
            _nodez[i] = hi  # cinsn_t or cexpr_t

        # Replicate the interim graph's edges
        # with {cinsn_t, cexpr_t} objects as nodes
        # Update the `i_cfg` with the lifted node indexes
        i_edges = list(self.i_cfg.edges())

        if not i_edges and len(self.i_cfg.nodes()) == 1:
            # Corner case:
            # Only one node and no edges
            self.g.add_node(_nodez[sind])
        else:
            # We have more than one node
            # and edges between them
            self.i_cfg = nx.DiGraph()

            for u, v in i_edges:
                # i -> j
                u = _lifted.get(u, None) or u
                v = _lifted.get(v, None) or v
                self.g.add_edge(_nodez[u], _nodez[v])
                self.i_cfg.add_edge(u, v)

        # Save these mappings for later
        self.index2node = _nodez
        self.node2index = {v: k for k, v in _nodez.items()}

    def _get_all_function_calls(self):
        """It does exactly what the name says

           This is needed because calls don't always appear
           in their own nodes (that'd be a `sub_xxx();`) but
           may be 'embedded' in other expressions.
           Ex: `v1 = sub_xxx();` (asg)

           Returns: None (it sets self.calls)
        """
        for n in self.g.nodes():
            # Which nodes are prone to contain function calls?
            if n.op == cit_if:
                # if(sub_xxx() != v1)
                cex = n.cif.expr
            elif n.op == cit_return:
                # return sub_yyy()
                cex = n.creturn.expr
            elif n.op == cit_for:
                cex = n.cfor.expr
            elif n.op == cit_while:
                cex = n.cwhile.expr
            elif n.op == cit_do:
                cex = n.cdo.expr
            else:
                # asg, call, etc.
                cex = n

            # This catches nodes that are pure calls
            # ex: sub_xxx(1, 2);
            if cex.op == cot_call:
                name = my_get_func_name(cex.x.obj_ea) or 'sub_unknown'
                co = callObj(c=self, name=name, node=n, expr=cex)
                self.calls.append(co)

            # This recurses into more complex expressions
            # looking for calls. A very simple example
            # would be to check both sides of an assignment
            operands = blowup_expression(cex)
            for operand in operands:
                if operand.op == cot_call:
                    # The node in our CFG is the expression
                    # containing the function call
                    name = my_get_func_name(operand.x.obj_ea) or 'sub_unknown'

                    co = callObj(c=self, name=name, node=n, expr=operand)
                    self.calls.append(co)

    # ================================================================================
    # Debugging utilities
    # ================================================================================
    def dump_i_cfg(self):
        """Dump interim CFG for debugging purposes
        """

        print("[DEBUG] Dumping CFG")
        for u, v in self.i_cfg.edges():
            print("{} -> {}".format(u, v))

        print("[DEBUG] Writing GraphML...")
        # Labeling the nodes
        for node in self.i_cfg.nodes():
            self.i_cfg.node[node]['label'] = "{}".format(node)

        nx.write_graphml(self.i_cfg, r"D:\graphs\di.graphml")

    def dump_cfg(self, out_dir):
        """Dump the CFG for debugging purposes

        This dumps a representation of the CFG in DOT format.
        To generate an image:

        ``dot.exe -Tpng decompiled.dot -o decompiled.png``
        """

        dot = "digraph D {\n"
        dot += "node [shape=record style=rounded fontname=\"Sans serif\" fontsize=\"8\"];\n"

        # Labeling the nodes
        for node in self.g.nodes():
            node_fmt = "node_{} [label=\"{} ({}) ({:X})\"];\n"

            # We can set different node attributes for specific opcodes
            if node.opname == 'call':
                node_fmt = "node_{} [fillcolor=lightblue style=\"rounded, filled\" label=\"{} ({}) ({:X})\"];\n"
            elif node.opname.startswith('asg'):
                node_fmt = "node_{} [fillcolor=green style=\"rounded, filled\" label=\"{} ({}) ({:X})\"];\n"
            elif node.opname == 'if':
                node_fmt = "node_{} [shape=diamond fillcolor=yellow style=filled label=\"{} ({}) ({:X})\"];\n"
            elif node.opname == 'return':
                node_fmt = "node_{} [shape=box fillcolor=red style=filled label=\"{} ({}) ({:X})\"];\n"

            dot += node_fmt.format(
                node.index,
                node.opname,
                node.index,
                node.ea)

        # Adding edges
        for u, v in self.g.edges():
            dot += "node_{} -> node_{};\n".format(
                u.index,
                v.index)

        dot += "}\n"

        print("[DEBUG] Writing DOT file...")
        od = os.path.join(out_dir, "decompiled.dot")
        with open(od, 'wb') as f:
            f.write(bytes(bytearray(dot, "utf-8")))

        print("[DEBUG] Done.")


def get_cfg_for_ea(ea, dot_exe, out_dir):
    """Debugging helper.

    Uses ``DOT`` to create a ``.PNG`` graphic of the
    :class:`ControlFlowinator` CFG and displays it.

    :param ea: address of the function to analyze
    :type ea: int
    :param dot_exe: path to the ``DOT`` binary
    :type dot_exe: string
    :param out_dir: directory to write the ``.DOT`` file
    :type out_dir: string
    """

    try:
        c = controlFlowinator(ea=ea)
    except Exception as e:
        print(e)
        return

    c.dump_cfg(out_dir)

    cmd = "{dot_exe} -Tpng -o '{png_file}' '{dot_file}'".format(
        dot_exe=dot_exe,
        dot_file=os.path.join(out_dir, "decompiled.dot"),
        png_file=os.path.join(out_dir, "decompiled.png"))
    cmd2 = os.path.join(out_dir, "decompiled.png")

    print("Trying to run: {}...".format(cmd))
    os.system(cmd)
    print("Trying to run: {}...".format(cmd2))
    os.system(cmd2)


def debug_blownup_expressions(c=None):
    """ Debugging helper.

    Show all blown up expressions for this function.

    :param c: a :class:`controlFlowinator` object
    :type c: :class:`controlFlowinator`
    """

    if not c:
        print("I need a controlFlowinator object")
        return

    for node in c.g.nodes:
        ea = node.ea
        if type(node) == cinsn_t:
            node = get_cond_from_statement(node)
            if not node:
                print("{:X} ???".format(ea))
                continue

        elems = blowup_expression(node)
        s_elems = ",".join([expr_ctype[e.op] for e in elems])

        print("{:X} {}".format(ea, s_elems))


def create_comment(c=None, ea=0, comment=""):
    """Displays a comment at the line corresponding to ``ea``

    TODO: avoid creating orphan comment in case the mapping
    from ``ea`` to decompiled code fails

    :param c: a :class:`controlFlowinator` object
    :type c: :class:`controlFlowinator`
    :param ea: address for the comment
    :type ea: int
    :param comment: the comment to add
    :type comment: string
    """

    if not c:
        # No `controlFlowinator` object supplied
        # We have to decompile manually
        if ea:
            cf = my_decompile(ea=ea)
        else:
            raise ValueError
    else:
        cf = c.cf

    tl = treeloc_t()
    tl.ea = ea
    tl.itp = ITP_SEMI
    cf.set_user_cmt(tl, comment)
    cf.save_user_cmts()


# ===========================================================
# Processing the CFG
# Convenience functions for cexpr_t elements
# ===========================================================
class callObj:
    """Auxiliary object for code clarity.

    It represents the occurrence of a ``call`` expression.

    :param name: name of the function called
    :type name: string, optional
    :param node: a :class:`controlFlowinator` node containing the call expression
    :type node: :class:`controlFlowinator`
    :param expr: the ``call`` expression element
    :type expr: :class:`cexpr_t`
    """

    def __init__(self, c=None, name="", node=None, expr=None):
        self.c = c
        self.name = name
        self.ida_args = []
        self.args = {}
        self.ea = None
        self.call_ea = None
        self.ret_type = None

        # Node in our CFG containing the call expr
        self.node = node
        # The call expr itself (cot_call)
        self.expr = expr

        if self.expr:
            # This is the Ea of the function
            # being called at location `self.ea`
            self.call_ea = self.expr.x.obj_ea

            # This is the Ea of the `call` instruction
            # and obviously of the decompiled function call
            self.ea = self.expr.ea

        self._populate_args()
        self._populate_return_type()

    def _populate_args(self):
        """Performs some arguments preprocessing"""

        self.ida_args = list(self.expr.a)
        self.args = {}

        Rep = namedtuple('Rep', 'type val')

        for i, raw_arg in enumerate(self.ida_args):
            # To be sure. Idempotent.
            arg = decast(raw_arg)

            if is_number(arg):
                rep = Rep(type='number', val=num_value(arg))
            elif is_string(arg):
                rep = Rep(type='string', val=string_value(arg))
            elif is_var(arg):
                # :class:`var_ref_t` -> :class:`lvar_t` -> :class:`my_var_t`
                lv = ref2var(arg, c=self.c)
                rep = Rep(type='var', val=my_var_t(lv))
            elif is_global_var(arg):
                rep = Rep(type='global', val=value_of_global(arg))
            elif is_ref(arg):
                # &v1
                rep = Rep(type='ref', val=ref_to(arg))
            elif is_ptr(arg):
                # *v1
                rep = Rep(type='ptr', val=points_to(arg))
            else:
                rep = Rep(type='unk', val=arg)

            self.args[i] = rep

    def _populate_return_type(self):
        """Finds the return type for the function being called
        """

        tif = tinfo_t()
        get_tinfo(tif, self.call_ea) or guess_tinfo(tif, self.call_ea)
        self.ret_type = tif.get_rettype()

    def __repr__(self):
        """Display a pretty representation for print"""

        print("--------------------------------------")
        print("Ea: {:X}".format(self.ea))
        print("Target's Name: {}".format(self.name))
        print("Target's Ea: {:X}".format(self.call_ea))
        print("Target's ret: {}".format(self.ret_type))
        print("Args:")
        for i, arg in self.args.items():
            print(" - {}: {}".format(i, arg))

        return ""


def blowup_expression(cex, final_operands=None):
    """Extracts all elements of an expression

    Ex: ``x + 1 < y`` -> ``{x, 1, y}``

    :param cex: a :class:`cexpr_t` object
    :type cex: :class:`cexpr_t`
    :return: a *set* of elements (the *final_operands*)
    :rtype: set
    """

    # Recursion and default values in Python...
    if final_operands is None:
        final_operands = set([])

    operands = {}

    # Quick and dirty operand extraction
    # ----------------------------------
    # NOTE: for now this does not look inside member offsets ('m')
    op_names = ('x', 'y', 'z')
    for name in op_names:
        if hasattr(cex, name):
            attr = getattr(cex, name)
            if attr:
                operands[name] = attr

    # Special code to handle call arguments
    if hasattr(cex, 'a') and cex.a:
        for arg in cex.a:
            arg_name = "a{}".format(arg.index)
            operands[arg_name] = arg

    # Corner case: this expression is a variable
    if hasattr(cex, 'v') and cex.v:
        v_name = "v{}".format(cex.v.idx)
        operands[v_name] = cex

    for op_name, operand in operands.items():
        if is_final_expr(cex):
            # If the expression itself is a final one
            final_operands.add(cex)
        elif not is_final_expr(operand):
            # if visited_operands != None:
            #    visited_operands.append(operand)
            if is_call(operand):
                final_operands.add(operand)
            blowup_expression(operand, final_operands)
        else:
            final_operands.add(operand)
            dprint("> final: {} {:#08x}".format(
                expr_ctype[operand.op], operand.ea))

    return final_operands


def get_all_vars_in_node(cex):
    """Extracts all variables involved in an expression.

    :param cex: typically a :class:`controlFlowinator` node
    :type cex: :class:`cexpr_t`
    :return: list of ``var_t`` indexes (to ``cf.lvars``)
    :rtype: list
    """

    set_elem = blowup_expression(cex)
    var_indexes = [x.v.idx for x in set_elem if is_var(x)]

    return var_indexes


def find_all_calls_to_within(f_name, ea):
    """Finds all calls to a function with the given name \
    within the function containing the ``ea`` address.

    Note that the string comparison is relaxed to find variants of it, that is,
    searching for ``malloc`` will match as well ``_malloc``, ``malloc_0``, etc.

    :param f_name: the function name to search for
    :type f_name: string
    :param ea: any address within the function that may contain the calls
    :type ea: int
    :return: a list of :class:`callObj`
    :rtype: list
    """

    call_objs = []
    try:
        c = controlFlowinator(ea=ea, fast=False)
    except Exception as e:
        print("Failed to find_all_calls_to_within {}".format(f_name))
        print(e)
        return []

    for node in c.g.nodes:
        kalls = find_elements_of_type(node, cot_call)
        for kall in kalls:
            got_name = my_get_func_name(kall.x.obj_ea)
            if f_name.lower() in got_name.lower(): 
                co = callObj(
                    c=c,
                    name=f_name,
                    node=node,
                    expr=kall)
                call_objs.append(co)
                break

    return call_objs


def find_all_calls_to(f_name):
    """Finds all calls to a function with the given name

    Note that the string comparison is relaxed to find variants of it, that is,
    searching for ``malloc`` will match as well ``_malloc``, ``malloc_0``, etc.

    :param f_name: the function name to search for
    :type f_name: string
    :return: a list of :class:`callObj`
    :rtype: list
    """

    f_ea = get_name_ea_simple(f_name)
    if f_ea == BADADDR:
        print("Failed to resolve address for {}".format(f_name))
        return []

    callz = []
    callers = set()
    
    for ref in XrefsTo(f_ea, True):
        if not ref.iscode:
            continue

        # Get a set of unique *function* callers
        f = get_func(ref.frm)
        if f is None:
            continue
            
        f_ea = f.start_ea
        callers.add(f_ea)

    for caller_ea in callers:
        c = find_all_calls_to_within(f_name, caller_ea)
        callz += c

    return callz


def find_elements_of_type(cex, element_type, elements=None):
    """Recursively extracts expression elements until \
    a :class:`cexpr_t` from a specific group is found

    :param cex: a :class:`cexpr_t` object
    :type cex: :class:`cexpr_t`
    :param element_type: the type of element we are looking for \
    (as a ``cot_xxx`` value, see ``compiler_consts.py``)
    :type element_type: a ``cot_xxx`` value (eg. ``cot_add``)
    :return: a set of :class:`cexpr_t` of the specified type
    :rtype: set
    """

    if elements is None:
        elements = set([])

    operands = {}

    # ===========================================
    # This covers the case cex is itself of
    # the type currently searched for :)
    # ===========================================
    if cex.op == element_type:
        elements.add(cex)

    # Quick and dirty operand extraction
    # ----------------------------------
    # TODO: for now this does not look inside member offsets ('m')
    op_names = ('x', 'y', 'z')
    for name in op_names:
        if hasattr(cex, name):
            attr = getattr(cex, name)
            if attr:
                operands[name] = attr

    # Special code to handle call arguments
    if hasattr(cex, 'a') and cex.a:
        for arg in cex.a:
            arg_name = "a{}".format(arg.index)
            operands[arg_name] = arg

    # Corner case: this expression is a variable
    if hasattr(cex, 'v') and cex.v:
        v_name = "v{}".format(cex.v.idx)
        operands[v_name] = cex

    for op_name, operand in operands.items():
        if operand.op == element_type:
            # If the expression itself is a sought one
            elements.add(operand)
        elif not is_final_expr(operand):
            find_elements_of_type(operand, element_type, elements)

    return elements


def is_final_expr(cex):
    """Helper for internal functions.

    A final expression will be defined as one that \
    can not be further decomposed, eg. number, var, string, etc.

    Normally, you should not need to use this.

    :param cex: a :class:`cexpr_t` object
    :type cex: :class:`cexpr_t`
    :return: True or False
    :rtype: bool
    """

    if cex.op in expr_final:
        return True
    else:
        return False


def get_cond_from_statement(ins):
    """Given a ``cinsn_t`` representing a control flow structure \
    (do, while, for, etc.), it returns the corresponding ``cexpr_t`` \
    representing the condition/argument for that code construct.

    This is useful since we usually want to peek into \
    conditional statements...

    :param ins: the :class:`cinsn_t` associated with a control flow structure
    :type ins: :class:`cinsn_t`
    :return: the condition or argument within that control flow structure
    :rtype: :class:`cexpr_t`
    """

    if ins.op == cit_while:
        res = ins.cwhile.expr
    elif ins.op == cit_do:
        res = ins.cdo.expr
    elif ins.op == cit_for:
        res = ins.cfor.expr
    elif ins.op == cit_if:
        res = ins.cif.expr
    elif ins.op == cit_return:
        res = ins.creturn.expr
    elif ins.op == cit_switch:
        res = ins.cswitch.expr
    else:
        res = None

    return res


def assigns_to_var(cex):
    """Does this :class:``cexpr_t`` assign a value to any variable?

    TODO: this is limited for now to expressions of the type:

        ``v1 = something something``

    :param cex: a :class:`cexpr_t` object
    :type cex: :class:`cexpr_t`
    :return: the assigned var index (to ``cf.lvars`` array) or -1 if the \
    :class:`cexpr_t` does not assign to any variable
    :rtype: int
    """

    v = None
    lvar_idx = -1

    if not is_asg(cex):
        # Currently assignments only
        return -1
    else:
        # left hand side
        _x = cex.x

    # Get the lhs variable
    if is_var(_x):
        # v1 = ...
        v = _x
    elif is_ptr(_x):
        # *v1 = ...
        # *v1 -> v1
        __x = _x.x
        if is_var(__x):
            v = __x

    if v:
        lvar_idx = v.v.idx

    return lvar_idx


def does_constrain(node):
    """This tries to answer the question: "Does this ``node`` constrains variables in any way?"

    Essentially it is looking for the occurrence of variables within known \
    *constrainer constructs*, eg. inside an ``if`` condition.

    TODO: many more heuristics can be included here

    :param node: typically a :class:`controlFlowinator` node
    :type node: :class:`cinsn_t` or :class:`cexpr_t`
    :return: a set of variable indexes (to ``cf.lvars`` array)
    :rtype: set
    """

    constrained_var_idxs = set([])

    # ===========================
    # Something simple as v1 = 0
    # or v1 = sub_xxx(y)
    # ===========================
    if is_asg(node):
        lhs = node.x
        rhs = node.y

        if is_var(lhs) and not is_var(rhs):
            v_idx = lhs.v.idx
            constrained_var_idxs.add(v_idx)

            return constrained_var_idxs

    # ===================================
    # Statements containing a condition
    # ex: if(v < MAX),
    # for(i=0; i<10; i++), etc.
    # ===================================
    insn_cond = insn_conditions.keys()

    if node.op in insn_cond:
        # Unwrap real condition (ex. x < y)
        cond = get_cond_from_statement(node)
        if not cond:
            return constrained_var_idxs

        constrainers = expr_condition.keys()

        if cond.op in constrainers:
            # We are mostly interested in the left
            # hand side (x) of the expression
            lhs = cond.x
            lhs_vars = find_elements_of_type(lhs, cot_var)

            for e in lhs_vars:
                v_idx = e.v.idx
                constrained_var_idxs.add(v_idx)
                dprint("Constraint found @ {:#08x}: {}".format(
                    node.ea, expr_ctype[cond.op]))

        return constrained_var_idxs

    # =================================
    # Binary truncation
    # ex: v1 = v4 & 0xFFFF
    # =================================
    if is_asg(node):
        rhs = node.y
        lhs = node.x
        if is_binary_truncation(rhs):
            var_indexes = get_all_vars_in_node(lhs)
            # TODO: Refine this algorithm
            v_idx = var_indexes[0]

            return set([v_idx])

    # TODO: More constraining cases here

    return set([])


def get_interesting_calls(c, user_defined=[]):
    """Not all functions are created equal.
    We are interested in functions with certain names or substrings in it.

    :param c: a :class:`controlFlowinator` object
    :type c: :class:`controlFlowinator`
    :param user_defined: a list of names (or substrings), if not supplied a \
    hard-coded default list will be used.
    :type user_defined: list, optional
    :return: a list of :class:`callObj`
    :rtype: list
    """

    default_list = ['check', 'log', 'assert', 'cpy',
                    'copy', 'alloc', 'move', 'memset']

    interesting_calls = user_defined or default_list

    result = []

    for co in c.calls:
        # Check against a number of interesting function names
        for f_name in interesting_calls:
            if f_name in co.name.lower():
                result.append(co)

    return result


def is_write(node):
    """Try to find write primitives.

    Looking for things like::

        *(_DWORD *)(something) = v38
        arr[i] = v21

    TODO: Rather rough, it is a first version...

    :param node: a :class:`controlFlowinator` node
    :type node: :class:`cinsn_t` or :class:`cexpr_t`
    :return: True or False
    :rtype: bool
    """

    if not is_asg(node):
        return False

    lhs = node.x

    if is_ptr(lhs):
        # *something
        return True

    if is_array_indexing(lhs):
        # arr[i]
        return True

    return False


def is_read(ins):
    """Try to find read primitives.

    Looking for things like::

        v3 = *(_DWORD *)(v5 + 784)

    NOTE: this will find expressions that are read && write,
    since they are not mutually exclusive

    TODO: Rather rough, it is a first version...

    :param node: a :class:`controlFlowinator` node
    :type node: :class:`cinsn_t` or :class:`cexpr_t`
    :return: True or False
    :rtype: bool
    """

    if not is_asg(ins):
        return False

    rhs = ins.y

    if is_ptr(rhs):
        # *something
        return True

    return False


# ===========================================================
def main():
    if not init_hexrays_plugin():
        print("No decompiler found! :(")
        return

    # Ascii banner :)
    print(r"""
███████╗██╗██████╗ ██╗     
██╔════╝██║██╔══██╗██║     
█████╗  ██║██║  ██║██║     
██╔══╝  ██║██║  ██║██║     
██║     ██║██████╔╝███████╗
╚═╝     ╚═╝╚═════╝ ╚══════╝
                     """)

    print("Hex-rays version {} detected".format(get_hexrays_version()))
    print("FIDL v.{} (\"{}\") loaded...".format(__version__, __codename__))
    print("")


if __name__ == '__main__':
    main()
