import sark
import idaapi
import idautils

anim = sark.structure.get_struct('AnimationFrame')
while idaapi.is_debugger_on():

    dataseg =  sark.Segment(name='dataseg').ea
    anim_offset = idaapi.get_word(sark.Line(ea=dataseg + idautils.cpu.di + 2).ea)
    anim_addr = dataseg + anim_offset
    idaapi.doStruct(anim_addr, 6, anim)
    idaapi.jumpto(sark.Segment(name='dataseg').ea + anim_offset)
    idaapi.continue_process()
    idaapi.wait_for_next_event(2, 10000)
