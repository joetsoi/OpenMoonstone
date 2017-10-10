import sark
import idautils
import idaapi
import csv

def all_struct_members():
    for struct in idautils.Structs():
        print struct
        members = idautils.StructMembers(struct[1])
        for member in members:
            yield struct[2], member[0], member[1], member[2]


with open('c:/Users/Joe/struct.csv', 'w') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(all_struct_members())