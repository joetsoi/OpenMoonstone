import sark
import idautils
import idaapi

import csv

with open('c:/Users/Joe/test.csv', 'w') as csvfile:
    writer = csv.writer(csvfile)
    segment = sark.Segment()
    for function in segment.functions:
        writer.writerow([function.name, function.ea - segment.ea])