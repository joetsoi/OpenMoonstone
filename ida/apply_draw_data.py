import sark
import idaapi
import idautils

anim = sark.structure.get_struct('DrawData')
while idaapi.is_debugger_on():
    dataseg = sark.Segment(name='dataseg').ea
    anim_offset = sark.Line(ea=dataseg + idautils.cpu.di).ea
    anim_addr = dataseg + anim_offset
    idaapi.doStruct(anim_offset, 0x24, anim)
    idaapi.jumpto(anim_offset)
    idaapi.continue_process()
    idaapi.wait_for_next_event(2, 10000)
