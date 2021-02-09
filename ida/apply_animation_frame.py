import sark
import idaapi
import idautils


# anim = sark.structure.get_struct('BalokImage')
anim = sark.structure.get_struct('AnimationFrame')
end_of_frame = sark.structure.get_struct("EndOfAnimFrame")
play_sound = sark.structure.get_struct("PartialFuncPlaySound")
func_with_count = sark.structure.get_struct("PartialFuncWithCount")
partial_func_param1 = sark.structure.get_struct("PartialFuncParam1Func")
set_image_width = sark.structure.get_struct("PartialFuncSetImageWidth")
dataseg =  sark.Segment(name='dataseg').ea
# anim_offset = idaapi.get_word(sark.Line(ea=dataseg + idautils.cpu.di + 2).ea)
current_position = sark.Line().ea
# current_byte = idaapi.get_byte(current_position)

done = False

print("running")
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
    elif current_byte == 0x92:
        print("applying Play sound")
        idaapi.doStruct(current_position, 2, play_sound)
        current_position += 2
    elif current_byte == 0x84 or current_byte == 0x9e:
        print("applying function with count")
        idaapi.doStruct(current_position, 2, func_with_count)
        current_position += 2
    elif current_byte == 0x98:
        print("applying function call")
        idaapi.doStruct(current_position, 4, partial_func_param1)
        current_position += 4
    elif current_byte == 0x96:
        print("applying function set image width")
        idaapi.doStruct(current_position, 4, set_image_width)
        current_position += 4

    else:
        done = True
