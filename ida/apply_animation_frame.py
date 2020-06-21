import sark
import idaapi
import idautils


anim = sark.structure.get_struct('TroggSpearImage')
end_of_frame = sark.structure.get_struct("EndOfAnimFrame")
dataseg =  sark.Segment(name='dataseg').ea
# anim_offset = idaapi.get_word(sark.Line(ea=dataseg + idautils.cpu.di + 2).ea)
current_position = sark.Line().ea
# current_byte = idaapi.get_byte(current_position)

done = False

while not done:
    current_byte = idaapi.get_byte(current_position)
    if current_byte == 0xff:
        print("applying EndOfAnimFrame")
        idaapi.doStruct(current_position, 2, end_of_frame)
        next_byte = idaapi.get_byte(current_position + 1)
        if next_byte == 0xff:
            done = True
        current_position += 2
    elif current_byte < 0x80:
        # print(current_byte)
        print("applying AnimationFrame")
        test = idaapi.doStruct(current_position, 6, anim)
        # print(test)
        current_position += 6
        # print(hex(current_position-dataseg))
    else:
        done = True
