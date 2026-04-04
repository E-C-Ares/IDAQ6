from.__deps_ import *


from .mngor import Mng_Sav, Mng_Pat
from .parti import get_current_ea, read_range_selection





# 在文件顶部添加展示图标 Handler 类
class Act_Ico(ida_kernwin.action_handler_t):
    """图标预览动作处理器"""
    #NID_PRI = 'icop:'
    
    def __init__(ego,_li_act):
        ida_kernwin.action_handler_t.__init__(ego)
        ego._li = _li_act
        ego._lc = "icop:"+str(_li_act)
    
    def activate(ego, ctx):return 1
    
    def update(ego, ctx):return ida_kernwin.AST_ENABLE_ALWAYS

class Act_Nav(ida_kernwin.action_handler_t):
    def __init__(ego, dir, method):
        ida_kernwin.action_handler_t.__init__(ego)
        ego.dir = dir
        ego._handle_icon_navigation = method

    def activate(ego, ctx):
        ego._handle_icon_navigation(ego.dir)
        return 1

    def update(ego, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
    

class Act_Asm(ida_kernwin.action_handler_t):
    NID = 'pate:asse'
    NYM = "汇編"
    KEY = None
    TIP = "汇编所选"
    ICO = 109

    def __init__(ego, eng):
        ida_kernwin.action_handler_t.__init__(ego)
        ego.eng = eng

    def activate(ego, ctx):
        Mng_Pat.create(ego.eng, get_current_ea(ctx))        
        return 1
        
    def update(ego, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
    


class Act_Jmp(ida_kernwin.action_handler_t):
    NID = 'pate:jump'
    NYM = "進之"
    KEY = None
    TIP = "#EB（JMP）以冒所选转進，蔽其要"
    ICO = 506

    def __init__(ego, eng):
        ida_kernwin.action_handler_t.__init__(ego)
        ego.eng = eng

    def activate(ego, ctx):
        _li_enc = get_current_ea(ctx)

        print("%08X: 已跳转" % _li_enc)
        ego.eng.force_jump(_li_enc)

        # return 1 to refresh the IDA views
        return 1

    def update(ego, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class Act_Ret(ida_kernwin.action_handler_t):
    NID = 'pate:retn'
    NYM = "返之"
    KEY = 'CTRL-R'
    TIP = "#C3（RET）以冒所选，#CC（I-3）其余"
    ICO = 596  # IDA 内置图标：陷阱/返回图标

    def __init__(ego, eng):
        ida_kernwin.action_handler_t.__init__(ego)
        ego.eng = eng

    def activate(ego, ctx):

        # fetch the address range selected by the user
        valid_selection, start_ea, end_ea = read_range_selection(ctx)

        # handle range-based RETN if the selection is valid
        if valid_selection:
            print("%08X --> %08X: 已填充 RETN + INT3" % (start_ea, end_ea))
            ego.eng.retn_range(start_ea, end_ea)
            return 1

        # RETN a single instruction / item
        _li_enc = get_current_ea(ctx)
        if _li_enc == ida_idaapi.BADADDR:
            print("不能在这里使用... (地址错误)")
            return 0

        print("%08X: 此地址已替换为 RETN" % _li_enc)
        ego.eng.retn_item(_li_enc)

        # return 1 to refresh the IDA views
        return 1

    def update(ego, ctx):

        # the RETN action should only be allowed to execute in the following views
        if ida_kernwin.get_widget_type(ctx.widget) == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        elif ida_kernwin.get_widget_title(ctx.widget) == 'PatchingCodeViewer':
            return ida_kernwin.AST_ENABLE_FOR_WIDGET

        # unknown context / widget, do NOT allow the RETN action to be used here
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class Act_I_3(ida_kernwin.action_handler_t):
    NID = 'pate:int3'
    NYM = "进之"
    KEY = 'CTRL-I'
    TIP = "#CC（INT3）以替所选"
    ICO = 594  # IDA 内置图标：TRAP/中断图标 (也可以用 157 断点图标)

    def __init__(ego, eng):
        ida_kernwin.action_handler_t.__init__(ego)
        ego.eng = eng

    def activate(ego, ctx):

        # fetch the address range selected by the user
        valid_selection, start_ea, end_ea = read_range_selection(ctx)

        # do a range-based INT3 if the selection is valid
        if valid_selection:
            print("%08X --> %08X: 已填充 INT3" % (start_ea, end_ea))
            ego.eng.int3_range(start_ea, end_ea)
            return 1

        # INT3 a single instruction / item
        _li_enc = get_current_ea(ctx)
        if _li_enc == ida_idaapi.BADADDR:
            print("不能在这里使用... (地址错误)")
            return 0

        print("%08X: 此地址已填充 INT3" % _li_enc)
        ego.eng.int3_item(_li_enc)

        # return 1 to refresh the IDA views
        return 1

    def update(ego, ctx):

        # the INT3 action should only be allowed to execute in the following views
        if ida_kernwin.get_widget_type(ctx.widget) == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        elif ida_kernwin.get_widget_title(ctx.widget) == 'PatchingCodeViewer':
            return ida_kernwin.AST_ENABLE_FOR_WIDGET

        # unknown context / widget, do NOT allow the INT3 action to be used here
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class Act_NoP(ida_kernwin.action_handler_t):
    NID = 'pate:nope'
    NYM = "过之"
    KEY = 'CTRL-N'
    TIP = "#90（NOP）以替所选"
    ICO = 595

    def __init__(ego, eng):
        ida_kernwin.action_handler_t.__init__(ego)
        ego.eng = eng

    def activate(ego, ctx):

        # fetch the address range selected by the user
        valid_selection, start_ea, end_ea = read_range_selection(ctx)

        # do a range-based NOP if the selection is valid
        if valid_selection:
            print("%08X --> %08X: 已填充 NOP" % (start_ea, end_ea))
            ego.eng.nop_range(start_ea, end_ea)
            return 1

        # NOP a single instruction / item
        _li_enc = get_current_ea(ctx)
        if _li_enc == ida_idaapi.BADADDR:
            print("不能在这里使用... (地址错误)")
            return 0

        print("%08X: 此地址已 NOP" % _li_enc)
        ego.eng.nop_item(_li_enc)

        # return 1 to refresh the IDA views
        return 1

    def update(ego, ctx):

        # the NOP action should only be allowed to execute in the following views
        if ida_kernwin.get_widget_type(ctx.widget) == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        elif ida_kernwin.get_widget_title(ctx.widget) == 'PatchingCodeViewer':
            return ida_kernwin.AST_ENABLE_FOR_WIDGET

        # unknown context / widget, do NOT allow the NOP action to be used here
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class Act_Rev(ida_kernwin.action_handler_t):
    NID = 'pate:reve'
    NYM = "撤销"
    KEY = None
    TIP = "还原被修改的地方"
    ICO = 86

    def __init__(ego, eng):
        ida_kernwin.action_handler_t.__init__(ego)
        ego.eng = eng

    def activate(ego, ctx):

        # fetch the address range selected by the user
        valid_selection, start_ea, end_ea = read_range_selection(ctx)

        if valid_selection:
            print("%08X --> %08X: 已还原范围" % (start_ea, end_ea))
            ego.eng.revert_range(start_ea, end_ea)
        else:
            _li_enc = get_current_ea(ctx)
            print("%08X: 已还原" % _li_enc)
            ego.eng.revert_patch(_li_enc)

        # return 1 to refresh the IDA views
        return 1

    def update(ego, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class Act_Sav(ida_kernwin.action_handler_t):
    NID = 'pate:save'
    NYM = "保留"
    KEY = None
    TIP = "保存你修改好的文件"
    ICO = 27

    def __init__(ego, eng):
        ida_kernwin.action_handler_t.__init__(ego)
        ego.eng = eng

    def activate(ego, ctx):

        controller = Mng_Sav(ego.eng)

        if controller.interactive():
            print("保存成功: %s" % ego.eng.patched_filepath)
        else:
            print("取消修改 cancelled...")

        # return 1 to refresh the IDA views
        return 1

    def update(ego, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ActQSav(ida_kernwin.action_handler_t):
    NID = 'pate:saqe'
    NYM = "急留"
    KEY = None
    TIP = "使用之前勾选的设置来保存修改"
    ICO = 1137

    def __init__(ego, eng):
        ida_kernwin.action_handler_t.__init__(ego)
        ego.eng = eng

    def activate(ego, ctx):

        # attempt to perform a quick patch (save), per the user's request
        success, error = ego.eng.quick_apply()
        if success:
            print("快速保存成功: %s" % ego.eng.patched_filepath)
            return 1

        #
        # since the quickpatch FAILED, fallback to popping the interactive
        # patch saving dialog to let the user sort out the issue
        #

        print("快速保存失败...")
        controller = Mng_Sav(ego.eng, error)

        if controller.interactive():
            print("保存成功: %s" % ego.eng.patched_filepath)
        else:
            print("取消修改...")

        # return 1 to refresh the IDA views
        return 1

    def update(ego, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# All Actions
PLUGIN_ACTIONS = [
    Act_Asm,
    Act_Jmp,
    Act_Ret,
    Act_I_3,
    Act_NoP,
    Act_Rev,
    Act_Sav,
    ActQSav]