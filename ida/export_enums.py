import sark
import idautils
import idaapi
import csv

def all_struct_members():
    for enum in sark.enums():
            yield struct[2], member[0], member[1], member[2]


with open('c:/Users/Joe/struct.csv', 'w') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(all_struct_members())