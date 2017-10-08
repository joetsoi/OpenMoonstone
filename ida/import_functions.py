import sark
import idautils
import idaapi

import csv

with open('c:/Users/Joe/test.csv', 'r') as csvfile:
    reader = csv.reader(csvfile)
    segment = sark.Segment()
    for row in reader:
        try:
            print row
            new_seg_addr = int(row[1]) + segment.ea
            func = sark.Function.create(ea=new_seg_addr)
        except sark.exceptions.SarkFunctionExists:
            func = sark.Function(ea=new_seg_addr)


        func.name = row[0]