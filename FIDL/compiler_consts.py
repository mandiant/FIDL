# -*- coding: utf-8 -*-

# ==============================================
# List of expression ctype_t's
# ==============================================

from ida_hexrays import *


expr_taint_propagation = {
    # These operations propagate tainting, that is
    # if y is tainted -> x is now tainted too
    cot_asg:      '{x} = {y}',
    cot_asgbor:  '{x} |= {y}',
    cot_asgxor:  '{x} ^= {y}',
    cot_asgband:  '{x} &= {y}',
    cot_asgadd:  '{x} += {y}',
    cot_asgsub:  '{x} -= {y}',
    cot_asgmul:  '{x} *= {y}',
    cot_asgsshr:  '{x} >>= {y}',
    cot_asgushr:  '{x} >>= {y}',
    cot_asgshl:  '{x} <<= {y}',
    cot_asgsdiv:  '{x} /= {y}',
    cot_asgudiv:  '{x} /= {y}',
    cot_asgsmod:  '{x} %= {y}',
    cot_asgumod:  '{x} %= {y}',
    cot_add:      '{x} + {y}',
    cot_sub:      '{x} - {y}',
    cot_mul:      '{x} * {y}',
    cot_sdiv:   '{x} / {y}',
    cot_udiv:   '{x} / {y}',
    cot_smod:   '{x} % {y}',
    cot_umod:   '{x} % {y}',
    cot_fadd:   '{x} + {y}',
    cot_fsub:   '{x} - {y}',
    cot_fmul:   '{x} * {y}',
    cot_fdiv:   '{x} / {y}',
    cot_sshr:   '{x} >> {y}',
    cot_ushr:   '{x} >> {y}',
    cot_shl:      '{x} << {y}',
    cot_idx:      '{x}[{y}]',
    # Some other forms of control
    #cot_call:   '{x}({y})',
    cot_cast:   '({x}){y}',
    cot_ref:      '&{x}',
}

expr_condition = {
    cot_eq:   '{x} == {y}',
    cot_ne:   '{x} != {y}',
    cot_sge:      '{x} >= {y}',
    cot_uge:      '{x} >= {y}',
    cot_sle:      '{x} <= {y}',
    cot_ule:      '{x} <= {y}',
    cot_sgt:      '{x} >  {y}',
    cot_ugt:      '{x} >  {y}',
    cot_slt:      '{x} <  {y}',
    cot_ult:      '{x} <  {y}',
    # cot_lnot:   '!{x}',
}

expr_unsigned_cmp = {
    cot_uge:      '{x} >= {y}',
    cot_ule:      '{x} <= {y}',
    cot_ugt:      '{x} >  {y}',
    cot_ult:      '{x} <  {y}',
}

expr_signed_cmp = {
    cot_sge:      '{x} >= {y}',
    cot_sle:      '{x} <= {y}',
    cot_sgt:      '{x} >  {y}',
    cot_slt:      '{x} <  {y}',
}

expr_all_cmp = {
    # unsigned
    cot_uge:      '{x} >= {y}',
    cot_ule:      '{x} <= {y}',
    cot_ugt:      '{x} >  {y}',
    cot_ult:      '{x} <  {y}',
    # signed
    cot_sge:      '{x} >= {y}',
    cot_sle:      '{x} <= {y}',
    cot_sgt:      '{x} >  {y}',
    cot_slt:      '{x} <  {y}',
}

expr_assignments = {
    cot_asg:      '{x} = {y}',
    cot_asgbor:  '{x} |= {y}',
    cot_asgxor:  '{x} ^= {y}',
    cot_asgband:  '{x} &= {y}',
    cot_asgadd:  '{x} += {y}',
    cot_asgsub:  '{x} -= {y}',
    cot_asgmul:  '{x} *= {y}',
    cot_asgsshr:  '{x} >>= {y}',
    cot_asgushr:  '{x} >>= {y}',
    cot_asgshl:  '{x} <<= {y}',
    cot_asgsdiv:  '{x} /= {y}',
    cot_asgudiv:  '{x} /= {y}',
    cot_asgsmod:  '{x} %= {y}',
    cot_asgumod:  '{x} %= {y}',
}

expr_final = {
    cot_num:      '{n}',
    cot_fnum:   '{fpc}',
    cot_str:      '{string}',
    cot_var:      '{x}',
    cot_helper:  '{helper}',
    cot_obj:   '{obj_ea}',
    #cot_call:   '{x}({y})',
}

# =================================
# Expressions
# cexpr_t
# =================================
expr_ctype = {
    cot_comma:  '{x}, {y}',
    cot_asg:      '{x} = {y}',
    cot_asgbor:  '{x} |= {y}',
    cot_asgxor:  '{x} ^= {y}',
    cot_asgband:  '{x} &= {y}',
    cot_asgadd:  '{x} += {y}',
    cot_asgsub:  '{x} -= {y}',
    cot_asgmul:  '{x} *= {y}',
    cot_asgsshr:  '{x} >>= {y}',
    cot_asgushr:  '{x} >>= {y}',
    cot_asgshl:  '{x} <<= {y}',
    cot_asgsdiv:  '{x} /= {y}',
    cot_asgudiv:  '{x} /= {y}',
    cot_asgsmod:  '{x} %= {y}',
    cot_asgumod:  '{x} %= {y}',
    cot_tern:   '{x} ? {y} : {z}',
    cot_lor:      '{x} || {y}',
    cot_land:   '{x} && {y}',
    cot_bor:      '{x} | {y}',
    cot_xor:      '{x} ^ {y}',
    cot_band:   '{x} & {y}',
    cot_eq:   '{x} == {y}',
    cot_ne:   '{x} != {y}',
    cot_sge:      '{x} >= {y}',
    cot_uge:      '{x} >= {y}',
    cot_sle:      '{x} <= {y}',
    cot_ule:      '{x} <= {y}',
    cot_sgt:      '{x} >  {y}',
    cot_ugt:      '{x} >  {y}',
    cot_slt:      '{x} <  {y}',
    cot_ult:      '{x} <  {y}',
    cot_sshr:   '{x} >> {y}',
    cot_ushr:   '{x} >> {y}',
    cot_shl:      '{x} << {y}',
    cot_add:      '{x} + {y}',
    cot_sub:      '{x} - {y}',
    cot_mul:      '{x} * {y}',
    cot_sdiv:   '{x} / {y}',
    cot_udiv:   '{x} / {y}',
    cot_smod:   '{x} % {y}',
    cot_umod:   '{x} % {y}',
    cot_fadd:   '{x} + {y}',
    cot_fsub:   '{x} - {y}',
    cot_fmul:   '{x} * {y}',
    cot_fdiv:   '{x} / {y}',
    cot_fneg:   '-{x}',
    cot_neg:      '-{x}',
    cot_lnot:   '!{x}',
    cot_bnot:   '~{x}',
    cot_ptr:      '*{x}',
    cot_ref:      '&{x}',
    cot_postinc:  '{x}++',
    cot_postdec:  '{x}--',
    cot_preinc:  '++{x}',
    cot_predec:  '--{x}',
    cot_call:   '{x}({y})',
    cot_idx:      '{x}[{y}]',
    cot_num:      '{n}',
    cot_fnum:   '{fpc}',
    cot_str:      '{string}',
    cot_var:      '{x}',
    cot_sizeof:  'sizeof({x})',
    cot_helper:  '{helper}',
    cot_cast:   '({x})',
    cot_memref:  '{x}.{m}',
    cot_memptr:  '{x}->{m}',
    cot_obj:   '{obj_ea}',

    # =============================
    # Adding statements too
    # cinsn_t
    # =============================
    cit_asm: 'asm',
    cit_block: 'block',
    cit_break: 'break',
    cit_continue: 'continue',
    cit_do: 'do',
    cit_empty: 'empty',
    cit_end: 'end',
    cit_expr: 'expr',
    cit_for: 'for',
    cit_goto: 'goto',
    cit_if: 'if',
    cit_return: 'return',
    cit_switch: 'switch',
    cit_while: 'while',
}

# ======================================
# Statements containing a condition
# ======================================
insn_conditions = {
    cit_do: 'do',
    cit_for: 'for',
    cit_if: 'if',
    cit_while: 'while',
}
