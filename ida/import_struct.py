import sark
import idautils
import idaapi
import csv


with open('c:/Users/Joe/struct.csv', 'r') as csvfile:
    for row in csv.reader(csvfile):
        print row
        try:
            struct_id = sark.structure.create_struct(row[0])
        except sark.exceptions.SarkStructAlreadyExists:
            struct_id = idaapi.get_struc_id(row[0])
        print struct_id
        sark.structure.add_struct_member(struct_id, row[2], int(row[1]), int(row[3]))