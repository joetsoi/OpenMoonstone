import sark
import idautils
import csv



def in_segment(address, segment):
    return address >= segment.startEA and address <= segment.endEA


codeseg = sark.Segment(name='dataseg')
names = [i for i in idautils.Names() if in_segment(i[0], codeseg)]
names = [(i[0] - codeseg.startEA, i[1]) for i in names]
with open('c:/Users/Joe/dataseg.csv', 'r') as csvfile:
    for row in csv.reader(csvfile):
        try:
            sark.set_name(address=codeseg.ea + int(row[0]), name=row[1])
        except:
            pass