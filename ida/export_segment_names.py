import sark
import idautils


def in_segment(address, segment):
    return address >= segment.startEA and address <= segment.endEA


codeseg = sark.Segment(name='seg004')
names = [i for i in idautils.Names() if in_segment(i[0], codeseg)]
names = [(i[0] - codeseg.startEA, i[1]) for i in names]
with open('c:/Users/Joe/dataseg.csv', 'w') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(names)