'''
        PsychoTea's script updated for ida 7.5
        https://twitter.com/iBSparkes/status/1321196435413602304:
        "use IDA? want 36,000 symbols for free?
        iometa -M ios14_beta_research_kernel > sym_map.txt
        iometa -R target_kernel sym_map.txt > r2_map.txt
        then in IDA; import this script: https://gist.github.com/PsychoTea/253497050ff39ea10e248e9e593d1271
        and run: `importr2file("/path/to/r2_map.txt")`"

        Another change is that it only changes the default names.
        This way you can use it after diaphora for example.
        Rerun until 0 symbols are defined.

        CMP_REPS and is_auto_generated are taken from joxeankoret's diaphora
        https://github.com/joxeankoret/diaphora
'''

import idc
import ida_funcs

CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
            "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
            "stru_", "dbl_", "locret_"]


def is_auto_generated(name):
    for rep in CMP_REPS:
        if name.startswith(rep):
            return True
    return False


def define_func(addr, name):
    cur_name = idc.get_name(addr)

    if is_auto_generated(cur_name):
        idc.create_insn(addr)
        ida_funcs.add_func(addr)

        ret = idc.set_name(addr, name)
        if ret == 0:
            # The name was already (wrongfully) asigned
            name_addr = get_name_ea_simple(name)
            idc.set_name(name_addr, "")
            # Rerun script
            return False
        print("%s @ %s" % (name, hex(addr)))
        return True
    return False


def importr2file(path):
    content = ""

    with open(path, "r") as f:
        content = f.readlines()

    sym_count = 0
    defined = 0

    for line in content:
        if not line.startswith("f sym."):
            continue

        line = line.strip("\n")
        split_line_arr = line.split(' ')

        sym_name = split_line_arr[1][4:]
        sym_addr = split_line_arr[3]
        sym_addr_int = int(sym_addr, 16)

        ret = define_func(sym_addr_int, sym_name)
        if ret:
            defined += 1
        sym_count += 1

    print("defined %s syms out of %s total" %
          (str(defined), str(sym_count)))
