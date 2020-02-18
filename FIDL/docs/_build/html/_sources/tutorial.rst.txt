.. _tutorial_label:

Getting started
===============

.. versionadded:: 1.0

This section will introduce the basics of the FIDL API as well as examples for the most common tasks.


.. _controlFlowinator_label:

The ControlFlowinator
---------------------

The main object for the FIDL API is a data structure representing individual functions. This data structure is a mix between the assembly-level control flow graph (*CFG*) and the decompilation output in IDA. It has been conveniently named ``controlFlowinator``.

To understand it better, picture yourself a *CFG* where every node is a high level code construct, e.g.,

    - if
    - assignment
    - function call
    - return
    - etc.

In a ``controlFlowinator`` object, every node of the *CFG* translates roughly to a line of decompiled code. 

Below you can find a visualization of the ``controlFlowinator`` object for an example function, next to the *classical* IDA function views (assembly *CFG* and decompilation). Essentially, FIDL adds a new abstract representation of a function.

.. image:: img/representations.png
    :width: 800px
    :align: center
    :alt: controlFlowinator as a new abstract representation of a function

Creating a ``controlFlowinator`` object scales well when dealing with large functions:

.. image:: img/controlflowinator_scales.png
    :width: 800px
    :align: center
    :alt: controlFlowinator creation scales well


Batteries included
------------------

The ``controlFlowinator`` object contains by default a lot of interesting information about the function it represents, e.g.,

    - local variables
    - arguments
    - function calls
    - return type

This information is easily accessible as attributes. Let's use the following function (from ``putty.exe``) as an example:

.. code-block:: C
    :linenos:

    BOOL __fastcall complex_75_sub_140062678(__int64 a1, const WCHAR *a2, __int64 a3, int a4)
    {
      __int64 v4; // rdi
      const __m128i *v5; // rbx
      int v6; // eax
      SIZE_T v7; // r15
      _DWORD *v8; // rax
      void *v9; // r14
      HGLOBAL v10; // rax
      void *v11; // r13
      __m128i *v12; // r12
      int v13; // esi
      <snip...>

This is a fairly complex function with four arguments and many local variables.

Function arguments
^^^^^^^^^^^^^^^^^^

Extract information from a function arguments is easy. We will start by importing the module and creating a ``controlFlowinator`` object.

.. code-block:: python
    :linenos:

    Python>import FIDL.decompiler_utils as du
    Python>c = du.controlFlowinator(ea=here(), fast=False)
    Python>c
    <FIDL.decompiler_utils.controlFlowinator instance at 0x00000176B566BE48>

We can now access this function arguments via the ``args`` attribute. Note that arguments are pretty printed by default.

.. code-block:: python
    :linenos:

    Python>c.args
    Name: a1
      Type name: __int64
      Size: 8
    Name: a2
      Type name: const WCHAR *
      Size: 8
    Complex type: WCHAR
    Pointed object: const WCHAR
    Name: a3
      Type name: __int64
      Size: 8
    Name: a4
      Type name: int
      Size: 4
    {0x0: , 0x1: , 0x2: , 0x3: }


``c.args`` is a dict indexed by a numerical index. Its individual arguments are of type ``my_var_t``. Please refer to :ref:`api_label` for more information about this class.

We can now easily extract information from individual arguments. As an example we'll query properties from the first two arguments of this function.

Remember the prototype is: ``BOOL __fastcall complex_75_sub_140062678(__int64 a1, const WCHAR *a2, __int64 a3, int a4)``

.. code-block:: python
    :linenos:

    Python>first = c.args[0]
    Python>dir(first)
    ['__doc__', '__init__', '__module__', '__repr__', '_get_var_type', 'array_type', 'complex_type', 'is_a_function_of', 'is_arg', 'is_array', 'is_constrained', 'is_initialized', 'is_pointer', 'is_signed', 'is_tainted', 'name', 'pointed_type', 'size', 'ti', 'type_name', 'var']
    Python>first.name
    'a1'
    Python>first.type_name
    '__int64'
    Python>first.pointed_type
    Python>first.is_signed
    True
    Python>first.is_pointer
    False
    Python>first.is_array
    False

    Python>second = c.args[1]
    Python>second.name
    'a2'
    Python>second.is_pointer
    True
    Python>second.pointed_type
    const WCHAR
    Python>second.type_name
    'const WCHAR *'

See :ref:`api_label` for more information about working with arguments.

.. _local_variables_label:

Local variables
^^^^^^^^^^^^^^^

Working with a function's local variables is very similar to working with arguments (under the hood, both are of the same type in *Hex-Rays*). In *FIDL*, local variables share type with function arguments as well (``my_var_t``).

Let's start as usual by importing the module and constructing a ``controlFlowinator`` object:

.. code-block:: python
    :linenos:

    Python>import FIDL.decompiler_utils as du
    Python>c = du.controlFlowinator(ea=here(), fast=False)
    Python>c
    <FIDL.decompiler_utils.controlFlowinator instance at 0x000001D756DB21C8>

Accessing the local variables using the ``lvars`` attribute, a dictionary of ``my_var_t`` objects:

.. code-block:: python
    :linenos:

    Python>c.lvars
    Name: v4
      Type name: __int64
      Size: 8
    Name: v5
      Type name: const __m128i *
      Size: 8
    Complex type: __m128i
    Pointed object: const __m128i
    <snip...>
    Name: WideCharStr
      Type name: __int16[256]
      Size: 512
    Array type: __int16
    Name: v86
      Type name: __int64
      Size: 8
    Name: vars30
      Type name: int
      Size: 4
    <snip...>

Let's inspect an interesting one. That array of "words" for example. We happen to know the index (dict key) but we could search for the name as well by iterating the *dict* and accessing the ``name`` attribute. This is an straightforward exercise left to the reader ;)

.. code-block:: python
    :linenos:

    Python>lv = c.lvars[0x55]
    Python>lv.is_array
    True

    Python>lv
    Name: WideCharStr
      Type name: __int16[256]
      Size: 512
    Array type: __int16
    Array element size: 2
    Array length: 256

    Python>lv.array_len
    0x100L

As we can see we have easy access to all array properties (type, length, etc.)

See :ref:`api_label` for more information about working with local variables.


Function calls
^^^^^^^^^^^^^^

Another very important piece of information is which functions are being called by the function we are currently analyzing, as well as their arguments and return types.

For this example let's analyze another function. The function shown below displays *PuTTY*'s license:

.. code-block:: C
    :linenos:

    INT_PTR __fastcall DialogFunc(HWND a1, int a2, unsigned __int16 a3)
    {
      HWND v3; // rdi
      int v4; // edx
      int v5; // edx
      CHAR *v7; // rbx

      v3 = a1;
      v4 = a2 - 16;
      if ( !v4 )
        goto LABEL_11;
      v5 = v4 - 256;
      if ( !v5 )
      {
        v7 = sub_14000F698("%s Licence", "PuTTY");
        SetWindowTextA(v3, v7);
        sub_14000FCFC(v7);
        SetDlgItemTextA(
          v3,
          1002,
          "PuTTY is copyright 1997-2017 Simon Tatham.\r\n"
          "\r\n"
          "Portions copyright Robert de Bath, Joris van Rantwijk, Delian Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong"
          ", Nicolas Barry, Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus Kuhn, Colin Watson, Christopher"
          " Staite, and CORE SDI S.A.\r\n"
          "\r\n"
          "Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated docum"
          "entation files (the \"Software\"), to deal in the Software without restriction, including without limitation the r"
          "ights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to per"
          "mit persons to whom the Software is furnished to do so, subject to the following conditions:\r\n"
          "\r\n"
          "The above copyright notice and this permission notice shall be included in all copies or substantial portions of t"
          "he Software.\r\n"
          "\r\n"
          "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO"
          " THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE C"
          "OPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OT"
          "HERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.");
        return 1i64;
      }
      if ( v5 == 1 && a3 - 1 <= 1 )
    LABEL_11:
        EndDialog(a1, 1i64);
      return 0i64;
    }


To illustrate how to work with function calls, let's get the *license string*, that is, the third argument of the ``SetDlgItemTextA`` function.

We will start, as usual, by creating a ``controlFlowinator`` object and inspecting its attributes, in this case ``calls``:

.. code-block:: python
    :linenos:

    Python>import FIDL.decompiler_utils as du
    Python>c = du.controlFlowinator(ea=here(), fast=False)
    Python>c
    <FIDL.decompiler_utils.controlFlowinator instance at 0x000002A0B67F5B08>

Accessing the ``calls`` attribute we can quickly preview the information it contains, since it is pretty printed by default:

.. code-block:: python
    :linenos:

    Python>c.calls
    --------------------------------------
    Ea: 14005892E
    Target's Name: sub_14000FCFC
    Target's Ea: 14000FCFC
    Target's ret: __int64
    Args:
    Name: v7
      Type name: CHAR *
      Size: 8
      Complex type: CHAR
      Pointed object: CHAR
     - 0: Rep(type='var', val=)
    --------------------------------------
    Ea: 140058917
    Target's Name: sub_14000F698
    Target's Ea: 14000F698
    Target's ret: __int64
    Args:
    --------------------------------------
    Ea: 1400588F6
    Target's Name: EndDialog
    Target's Ea: 140090898
    Target's ret: BOOL
    Args:
    Name: a1
      Type name: HWND
      Size: 8
      Complex type: HWND__
      Pointed object: HWND__
     - 0: Rep(type='var', val=)
     - 1: Rep(type='number', val=1L)
    --------------------------------------
    Ea: 140058925
    Target's Name: SetWindowTextA
    Target's Ea: 1400909A8
    Target's ret: BOOL
    Args:
    Name: v3
      Type name: HWND
      Size: 8
      Complex type: HWND__
      Pointed object: HWND__
     - 0: Rep(type='var', val=)
    Name: v7
      Type name: CHAR *
      Size: 8
      Complex type: CHAR
      Pointed object: CHAR
     - 1: Rep(type='var', val=)
    --------------------------------------
    Ea: 140058942
    Target's Name: SetDlgItemTextA
    Target's Ea: 140090948
    Target's ret: BOOL
    Args:
    Name: v3
      Type name: HWND
      Size: 8
      Complex type: HWND__
      Pointed object: HWND__
     - 0: Rep(type='var', val=)
     - 1: Rep(type='number', val=1002L)
     - 2: Rep(type='string', val='PuTTY is copyright 1997-2017 Simon Tatham.\r\n\r\nPortions copyright Robert de Bath, Joris van Rantwijk, Delian Delchev, Andreas Schultz, <snip...>')
    [, , , , ]

As we can see, the long string containing *PuTTY*'s license is indeed recognized as the third argument of that Windows API. Notice how the function arguments are represented by a ``named tuple`` with elements ``type`` and ``val``. We'll now programatically search the function call matching that API name:

.. code-block:: python
    :linenos:

    Python>for k in c.calls:
    Python>   if k.name == 'SetDlgItemTextA':
    Python>      break
    Python>
    Python>k
    --------------------------------------
    Ea: 140058942
    Target's Name: SetDlgItemTextA
    Target's Ea: 140090948
    Target's ret: BOOL
    Args:
    Name: v3
      Type name: HWND
      Size: 8
      Complex type: HWND__
      Pointed object: HWND__
     - 0: Rep(type='var', val=)
     - 1: Rep(type='number', val=1002L)
     - 2: Rep(type='string', val='PuTTY is copyright 1997-2017 Simon Tatham.\r\n\r\nPortions copyright Robert de Bath, Joris van Rantwijk <snip...>')


Finally, let's locate its third argument and extract its value:

.. code-block:: python
    :linenos:

    Python>k.args
    {0x0: ('var', 0x3), 0x1: ('number', 0x3eaL), 0x2: ('string', 'PuTTY is copyright 1997-2017 Simon Tatham.<snip...>')}
    Python>lic = k.args[2]
    Python>lic.type
    'string'
    Python>s = lic.val
    Python>s
    'PuTTY is copyright 1997-2017 Simon Tatham.\r\n\r\nPortions copyright Robert de Bath, Joris van Rantwijk, Delian Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas Barry, Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus Kuhn, Colin Watson, Christopher Staite, and CORE SDI S.A.\r\n\r\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\r\n\r\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\r\n\r\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'

.. note::

    The function arguments of a ``controlFlowinator``, representing a function, and the function arguments of a specific occurrence of a function call are not of the same type.

    A **function call** can have explicitly defined constants or strings as arguments, eg. ``sub_140021F58("my_string", 1337, v8)`` accessed via a *named tuple* as shown in the code snippet above. 

    The function arguments of a ``controlFlowinator`` instance, representing the function itself, eg. ``sub_140021F58(char *a1, int a2, __int64 a3)`` are of type ``my_var_t``

    However, if the function call has an argument of type *var*, its *val* (ue) will be an instance of ``my_var_t``


A little example
^^^^^^^^^^^^^^^^

No reversing automation project is complete without an example involving ``GetProcAddress``. Let's consider the following *PuTTY* function, resolving dynamically some APIs.

You can find this function at address 0x140055674 within the provided ``putty.i64`` IDB file (under *tests*)

.. code-block:: C
    :linenos:

    __int64 cgp_sneaky_direct_asg()
    {
      HMODULE v0; // rax
      HMODULE v1; // rbx

      v0 = sub_140065B68("comctl32.dll");
      v1 = v0;
      if ( v0 )
        qword_1400C0DD0 = GetProcAddress(v0, "InitCommonControls");
      else
        qword_1400C0DD0 = 0i64;
      if ( v1 )
        qword_1400C0DD8 = GetProcAddress(v1, "MakeDragList");
      else
        qword_1400C0DD8 = 0i64;
      if ( v1 )
        qword_1400C0DE0 = GetProcAddress(v1, "LBItemFromPt");
      else
        qword_1400C0DE0 = 0i64;
      if ( v1 )
        qword_1400C0DE8 = GetProcAddress(v1, "DrawInsert");
      else
        qword_1400C0DE8 = 0i64;
      return qword_1400C0DD0();
    }

As we can see, some functions belonging to *comctl32.dll* are being resolved at runtime and pointers to them are stored in global variables. Since we will be seeing these global variables somewhere else in the binary, it would be good to rename them in a way that references the API they are pointing to. 

The following script implements this:

.. code-block:: python
    :linenos:

    import FIDL.decompiler_utils as du


    callz = du.find_all_calls_to_within(f_name='GetProcAddress', ea=here())
    for co in callz:
        # The *second* argument of ``GetProcAddress`` is the API name
        api_name = co.args[1].val

        # double check :)
        if not du.is_asg(co.node):
            continue

        lhs = co.node.x
        if du.is_global_var(lhs):
            g_addr = du.value_of_global(lhs)
            new_name = "g_ptr_{}".format(api_name)
            MakeName(g_addr, new_name)

The script assumes that the GUI cursor is within the function we are modifying.

First we get a list of :class:`callObj` objects representing all occurrences of a call to ``GetProcAddress`` (line 4). At line 7 we extract the value of their second arguments, that is, the string containing the API names. After checking that we are indeed dealing with an assignment (something of the form ``global_var = call_to_func(x, y)``), we take the left hand side of the expression (line 13). If this is indeed a global variable, we rename it to match the API it is pointing to (lines 14-17).

After executing the script the function will now look like this:

.. code-block:: C
    :linenos:

    __int64 cgp_sneaky_direct_asg()
    {
      HMODULE v0; // rax
      HMODULE v1; // rbx

      v0 = sub_140065B68("comctl32.dll");
      v1 = v0;
      if ( v0 )
        g_ptr_InitCommonControls = GetProcAddress(v0, "InitCommonControls");
      else
        g_ptr_InitCommonControls = 0i64;
      if ( v1 )
        g_ptr_MakeDragList = GetProcAddress(v1, "MakeDragList");
      else
        g_ptr_MakeDragList = 0i64;
      if ( v1 )
        g_ptr_LBItemFromPt = GetProcAddress(v1, "LBItemFromPt");
      else
        g_ptr_LBItemFromPt = 0i64;
      if ( v1 )
        g_ptr_DrawInsert = GetProcAddress(v1, "DrawInsert");
      else
        g_ptr_DrawInsert = 0i64;
      return g_ptr_InitCommonControls();
    }

You can find this script under *examples/getprocaddr_renaming_globals.py* in the source code distribution.


A more complete example
^^^^^^^^^^^^^^^^^^^^^^^

Let's take a look at a contrived example to showcase a typical use of the FIDL API. The example has been taken from @fabs0x0 presentation about Joern (a source code static analysis tool).

The problem we are trying to solve is the following: find all the functions allocating memory using ``malloc`` in a way that its size can overflow, that is, of the form ``len + imm``. Afterwards, find occurrences of ``memcpy`` where the same variable ``len`` is used as a *size* parameter.

The example script can be found on the **examples** directory of the source code distribution, along with the *IDB* file of a simple program implementing this potentially vulnerable code pattern. The same script is displayed below:

.. code-block:: python
    :linenos:

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

        print "=" * 80
        print results


    if __name__ == '__main__':
        main()


As we can see, :ref:`controlFlowinator_label` object is indeed the central piece of this API. It is the only argument of the function ``find_possible_malloc_issues`` at line 14. The convenience function ``do_for_all_funcs`` (line 89) is used to iterate over all functions on a binary, calculate their ``controlFlowinator`` and call a function with it as parameter (see line 90) and the API documentation for more information about this wrapper.

At lines 27, 28 all occurrences of calls to ``malloc`` and ``memcpy`` are calculated. The result of ``find_all_calls_to_within`` are so called ``callObj``, a complex data structure containing a lot of information about the *call* (name, arguments, location, etc.)

The argument of ``malloc`` is used as a parameter of ``is_arithmetic_expression`` (line 41), an auxiliary function returning a *boolean*, indicating whether the expression is arithmetic (that is, addition, substraction, multiplication, etc. or a combination of them). In this specific case we specify a second parameter to restrict the search to additions only.

If an expression representing an addition (a + b) is found we extract their operands {a, b} (lines 49, 50). Afterwards, we check whether the operands are of the *type* we are looking for, that is, a variable and a number (line 52). If this is true, we have found one of these ``len`` variables of interest, so we create ``my_var_t`` object and save it in a list for later usage (lines 59, 61). For more information on ``my_var_t`` objects please refer to the :ref:`local_variables_label` section.

Now that we have a list of *suspicious* ``len`` variables in this function is time to go over all calls to ``memcpy``, get their third arguments (line 68) and get their names (line 73). This is done only in the case that the *size* parameter is a variable (line 72), since it could be a constant value as well.

Finally, we compare the names of the two variables (line 76) and save the results in a JSON-like format to be returned at the end of the script's execution.

Running this over the example *IDB* provided, produces the expected result (line 6):


.. code-block:: text
    :linenos:

    40118A: variable 'v17' is possibly undefined
    <snip...>
    401C88: positive sp value 18 has been found
    401CBA: could not find valid save-restore pair for ebx
    ================================================================================
    [{'msg': 'Check use of len at 401030', 'ea': 4198400L}]
