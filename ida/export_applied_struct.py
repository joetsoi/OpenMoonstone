import idaapi
import sark
import idautils


def applied_structs():
    dataseg = sark.Segment(name='seg004')

    for line in dataseg.lines:
        ti = idaapi.opinfo_t()
        f = idaapi.getFlags(line.ea)
        if idaapi.get_opinfo(line.ea, 0, f, ti):
            struct_name = idaapi.get_struc_name(ti.tid)
            if struct_name:
                print (line.ea - dataseg.ea, struct_name)
                yield line.ea - dataseg.ea, struct_name

with open('c:/Users/Joe/applied_structs.csv', 'w') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(applied_structs())