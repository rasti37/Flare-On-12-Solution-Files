indirect_jmp = 0x14000ca5a
imgbase = idaapi.get_imagebase()

switch_info = ida_nalt.get_switch_info(indirect_jmp)
jtable_start = switch_info.jumps

ncases = 90780
curr_case = 0
curr_off = jtable_start

cases = []
while len(cases) < ncases:
    idx = len(cases)
    jtable_case_idx = jtable_start + idx*4
    case_rel_offset = int.from_bytes(idaapi.get_bytes(jtable_case_idx, 4), 'little')
    cases.append(imgbase + case_rel_offset)

open('cases.txt', 'w').write(str(cases))