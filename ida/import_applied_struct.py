import sark
import idautils
import idaapi
import csv


dataseg = sark.Segment(name="dataseg")
with open('c:/Users/Joe/applied_structs.csv', 'r') as csvfile:
    for row in csv.reader(csvfile):

        struct_id = idaapi.get_struc_id(row[1])
        size = idaapi.get_struc_size(struct_id)
        idaapi.doStruct(int(row[0]) + dataseg.ea,size, struct_id)