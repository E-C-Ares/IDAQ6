from.__deps_ import*


class Eng(object): pass

class Png(object): pass

class Mng(object):
    def __init__(ego):pass
    

# IDA Plugin Actions

class Act(ida_kernwin.action_handler_t):
    def __init__(ego, *c,**g):
        ida_kernwin.action_handler_t.__init__(ego)
    def activate(ego, ctx):pass
    def update(ego, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS