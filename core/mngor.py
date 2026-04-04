# -*- coding: utf-8 -*-
"""
汇编补丁控制器模块

本模块实现了汇编补丁功能的核心业务逻辑（MVC 模式中的 Model/Controller）：
- PatchingController: 管理补丁编辑器的数据和状态
- InstructionLine: 表示单条指令的显示信息
"""

from .__deps_ import *

from .utils.qt import QT_AVAILABLE
from .parti import parse_disassembly_components, scrape_symbols
from .basic import Mng

from .part3 import hexdump, trim_trailing_zeros
from .error import *
import hashlib

if QT_AVAILABLE:
    from .frmor import Frm_Pat
    from .save_ui import SaveDialog

LAST_LINE_IDX = -1  # 特殊标记，表示使用指令的最后一行


# ============================================================================
# 核心业务逻辑
# ============================================================================


class Mng_Sav(Mng):
    """
    The backing logic & model (data) for the patch saving UI.
    """
    WINDOW_TITLE = "保存修改..."

    def __init__(ego, core, error=None):
        ego.core = core
        ego.view = None

        # init fields
        ego._init_settings()

        # init error (if there was one that caused the dialog to pop)
        ego.attempts = 1 if error else 0
        ego._set_error(error)

        # only create the UI for the save dialog as needed
        if QT_AVAILABLE:
            ego.view = SaveDialog(ego)

    def _init_settings(ego):
        """
        Initialize dialog settings from the plugin core / IDA state.
        """

        # inherit certain settings from the plugin core
        ego.patch_cleanly = ego.core.prefer_patch_cleanly
        ego.quick_apply = ego.core.prefer_quick_apply

        # the target file to patch / apply patches to
        ego.target_filepath = ego.core.patched_filepath
        if not ego.target_filepath:
            ego.target_filepath = ida_nalt.get_input_file_path()

    def _set_error(ego, exception):
        """
        Set the save dialog error text based on the given exception.
        """

        # no error given, reset message text / color fields
        if exception is None:
            ego.status_message = ''
            ego.status_color = ''
            return

        #
        # something went wrong trying to ensure a usable backup / clean
        # executable was available for the patching operation. this should
        # only ever occur when the user is attempting to 'patch cleanly'
        #
        # this is most likely because the plugin could not locate a clean
        # version of the executable on disk. if the user would like to try
        # yolo-patching the target file, they can un-check 'Patch cleanly'
        #

        if isinstance(exception, PatchBackupError):
            ego.status_message = str(exception) + "\nDisable 'Patch cleanly' to try patching anyway (att #%u)" % ego.attempts
            ego.status_color = 'red'

        #
        # something went wrong explicitly trying to modify the target / output
        # file for the patching operation.
        #
        # this is most likely because the file is locked, but the target file
        # could also be missing (among other reasons)
        #

        elif isinstance(exception, PatchTargetError) or isinstance(exception, PatchApplicationError):
            ego.status_message = str(exception) + "\nIs the filepath above locked? or missing? (att #%u)" % ego.attempts
            ego.status_color = 'red'

        # unknown / unhandled error?
        else:
            ego.status_message = "Unknown error? (att #%u)\n%s" % (ego.attempts, str(exception))
            ego.status_color = 'red'

    
    # Actions
    

    def interactive(ego):
        """
        Spawn an interactive user dialog and wait for it to close.
        """
        if not ego.view:
            return False
        return ego.view.exec_()

    def attempt_patch(ego, target_filepath, clean):
        """
        Attempt to patch the target binary.
        """

        #
        # increment the 'patch attempt' count over the lifetime of this
        # dialog. the purpose of this counter is simple: it is a visual
        # cue to users who will continue to mash the 'Apply Patches'
        # button even in the face of a big red error message.
        #
        # the idea is that (hopefully) they will see this 'attempt count'
        # updating in the otherwise static error message text to indicate
        # that 'yes, the file is still locked/unavailabe/missing' until
        # they go rectify the issue
        #

        ego.attempts += 1

        #
        # attempt to apply patches to the target file on behalf of the
        # interactive dialog / user request
        #

        try:
            ego.core.apply_patches(target_filepath, clean)
        except Exception as e:
            ego._set_error(e)
            return False

        #
        # if we made it this far, patching must have succeeded, save patch
        # settings to the core plugin
        #

        ego.status_message = ''
        ego.core.prefer_patch_cleanly = ego.patch_cleanly
        ego.core.prefer_quick_apply = ego.quick_apply

        # return success
        return True

    def update_target(ego, target_filepath):
        """
        Update the targeted filepath.
        """
        ego.target_filepath = target_filepath
        if ego.patch_cleanly:
            return

        #
        # if the UI setting for 'Patch cleanly' is explicitly unchecked but
        # the user *just* updated the target filepath via file dialog, we
        # will quickly try to check if the selected file appears to be
        # a good candidate for making a copy (backup) of during the likely
        # imminent patch save / application operation
        #

        try:
            disk_md5 = hashlib.md5(open(target_filepath, 'rb').read()).digest()
        except Exception:
            return

        # the MD5 hash of the file (executable) used to generate this IDB
        input_md5 = ida_nalt.retrieve_input_file_md5()
        if input_md5 != disk_md5:
            return

        #
        # at this point, the user has explicitly selected a patch target that
        # appears to be clean, yet they have 'Patch cleanly' disabled, so we
        # should provide them with a 'soft' hint / warning that it would be
        # best for them to turn 'Patch cleanly' back on...
        #

        ego.status_message = "The patch target appears to be a clean executable,\nit is recommended you turn on 'Patch cleanly'"
        ego.status_color = 'orange'




class Mng_Pat(Mng):
    """
    补丁管
    
    负责管理汇编补丁窗口的所有数据和业务逻辑：
    - 维护当前编辑的地址和指令列表
    - 处理用户的汇编输入并尝试汇编
    - 管理补丁的应用和撤销
    - 与 UI 层通信，更新显示内容
    
    属性:
        core: 插件引擎实例，提供汇编器、补丁管理等
        view: UI 视图实例（PatchingDockable）
        address: 当前选中的地址
        assembly_text: 用户输入的汇编文本
        assembly_bytes: 汇编后的机器码
        instructions: 当前显示的指令列表
        status_message: 状态消息（错误提示等）
    """
    WINDOW_TITLE = "汇編"  # 窗口标题

    __a = None
    @staticmethod
    def create(core, ea=ida_idaapi.BADADDR):
        if Mng_Pat.__a is None:
            Mng_Pat.__a = Mng_Pat(core, ea=ea)
        else:
            Mng_Pat.__a.switch_to(core, ea=ea)
        return Mng_Pat.__a
    
    def switch_to(ego, core, ea=ida_idaapi.BADADDR):
        ego.core = core
        # 如果未提供地址，使用 IDA 当前光标位置
        if ea == ida_idaapi.BADADDR:
            ea = ida_kernwin.get_screen_ea()
        # 初始化地址相关属性
        ego._address_origin = ida_bytes.get_item_head(ea)
        ego.address = ego._address_origin
        ego.address_idx = LAST_LINE_IDX
        
        # 重置状态变量
        ego.assembly_text = ''
        ego.assembly_bytes = b''
        ego.status_message = ''
        
        # 首次刷新：加载指令数据
        ego.refresh()
        
        # 连接信号：当其他地方的补丁改变时，自动刷新
        ego.core.patches_changed(ego.refresh)
        
        # 如果有 UI，刷新显示
        if ego.view:
            print(ego.view)
            ego.view.refresh_fields()
            ego.view.refresh_code()
        else:
            ego.view = Frm_Pat(ego)
            ego.view.Show()
        # TODO

    def __init__(ego, core, ea=ida_idaapi.BADADDR):
        """
        初始化补丁控制器
        
        执行流程:
        1. 保存插件引擎引用
        2. 初始化地址和状态变量
        3. 首次刷新，加载指令数据
        4. 创建并显示 UI 窗口
        
        参数:
            core: 插件引擎实例
            ea: 初始地址（默认为当前光标位置）
        """
        ego.core = core
        ego.view = None

        # 如果未提供地址，使用 IDA 当前光标位置
        if ea == ida_idaapi.BADADDR:
            ea = ida_kernwin.get_screen_ea()

        ego._address_origin = ida_bytes.get_item_head(ea)

        # 公共属性
        ego.address = ego._address_origin      # 当前地址
        ego.address_idx = LAST_LINE_IDX         # 当前指令的行索引
        ego.assembly_text = ''                  # 汇编文本
        ego.assembly_bytes = b''                # 汇编字节
        ego.status_message = ''                 # 状态消息

        # 首次刷新：加载指令数据
        ego.refresh()

        # 连接信号：当其他地方的补丁改变时，自动刷新
        ego.core.patches_changed(ego.refresh)

        # 创建并显示 UI 窗口
        if QT_AVAILABLE:
            ego.view = Frm_Pat(ego)
            ego.view.Show()

    #-------------------------------------------------------------------------
    # 工具方法
    #-------------------------------------------------------------------------

    @staticmethod
    def find_data_block_range(buffer, start_offset=0, max_size=64):
        """
        在缓冲区中查找数据块的起止位置
        
        从 start_offset 开始，跳过前导 00，找到第一个非 00 字节，
        然后以连续 00 00 或 max_size 为界确定块的结束位置。
        
        参数:
            buffer: 字节缓冲区
            start_offset: 起始偏移量
            max_size: 最大块大小
        
        返回值:
            (block_start, block_end) 元组，如果未找到有效块则返回 (None, None)
        """
        if not buffer or start_offset >= len(buffer):
            return (None, None)
        
        # 找到第一个非 00 字节
        first_non_zero = len(buffer)
        for i in range(start_offset, len(buffer)):
            if buffer[i] != 0x00:
                first_non_zero = i
                break
        
        # 如果剩余部分全是 00，返回 None
        if first_non_zero >= len(buffer):
            return (None, None)
        
        # 寻找块的结束位置
        current_offset = first_non_zero
        block_end = current_offset
        consecutive_zeros = 0
        max_offset = min(current_offset + max_size, len(buffer))
        
        for i in range(current_offset, max_offset):
            if buffer[i] == 0x00:
                consecutive_zeros += 1
                if consecutive_zeros >= 2:
                    # 找到连续 00 00，块结束于第二个 00 之前
                    block_end = i - 1
                    break
            else:
                consecutive_zeros = 0
                block_end = i
        else:
            # 达到 max_size 上限或未找到连续 00 00
            block_end = max_offset - 1
        
        return (first_non_zero, block_end)

    @staticmethod
    def detect_utf16_encoding(buffer, offset, length):
        if length < 2 or offset + length > len(buffer): return False
        check_len = min(16, length)        
        zero_count = sum(1 for i in range(1, check_len, 2) if buffer[offset + i] == 0x00)
        zero_ratio = zero_count / (check_len // 2)
        return zero_ratio > 0.36788

    #-------------------------------------------------------------------------
    # 动作方法 - 处理用户操作
    #-------------------------------------------------------------------------

    def select_address(ego, ea, idx=LAST_LINE_IDX):
        """
        选择并定位到指定地址
        
        当用户在代码视图中点击某条指令时调用，执行以下操作：
        1. 查找该地址对应的指令对象
        2. 清除之前的冲突高亮
        3. 更新当前地址和行索引
        4. 加载该指令的汇编文本
        5. 刷新 UI 显示
        
        参数:
            ea: 目标地址
            idx: 指令内的行索引（多行指令时使用）
        
        返回值:
            无
        """
        # 查找地址对应的指令
        insn, lineno = ego.get_insn_lineno(ea)

        # 处理指令未找到的情况
        if insn is None:
            ego.status_message = "Cannot find instruction at address 0x%08X" % ea
            print("Warning: %s" % ego.status_message)
            if ego.view:
                ego.view.refresh_fields()
            return

        # 如果目标指令不存在，使用最后一行
        if insn.address != ea:
            idx = LAST_LINE_IDX

        # 如果光标移动到新行，清除所有冲突高亮
        if insn.address != ego.address or ego.address_idx != idx:
            for insn_cur in ego.instructions:
                insn_cur.clobbered = False

        # 更新当前地址和索引
        ego.address = insn.address
        ego.address_idx = idx

        # 加载该指令的汇编文本
        ego._update_assembly_text(ego.core.assembler.format_assembly(insn.address))

        # 刷新 UI
        if ego.view:
            ego.view.refresh_fields()
            ego.view.refresh_cursor()

    def switch_address(ego, new_ea):
        """
        切换到新地址并刷新内容（用于复用现有窗口）
        
        当窗口已存在时，用户右键点击新地址调用此方法：
        1. 更新内部地址指针
        2. 重新加载指令数据
        3. 刷新 UI 显示
        4. 将窗口带到前台
        
        参数:
            new_ea: 新的目标地址
        
        返回值:
            无
        """
        print(f"[PatchingController] Switching address from 0x{ego.address:X} to 0x{new_ea:X}")
        
        # 更新地址
        ego._address_origin = ida_bytes.get_item_head(new_ea)
        ego.address = ego._address_origin
        
        # 只重置状态消息
        ego.status_message = ''
        
        # 刷新数据和 UI（会重新加载指令和汇编文本）
        ego.refresh()
        
        # 如果有 UI，刷新字段并显示窗口
        if ego.view:
            ego.view.refresh_fields()
            ego.view.Show()  # 带到前台
        
        print(f"[PatchingController] Switched to 0x{ego.address:X} successfully")

    def edit_assembly(ego, assembly_text):
        """
        编辑汇编文本（用户输入时实时调用）
        
        当用户在汇编输入框中打字时，实时尝试汇编：
        1. 保存用户输入的文本
        2. 调用汇编器转换为机器码
        3. 检测是否会覆盖后续指令
        4. 高亮显示可能被覆盖的指令
        5. 通知 View 层刷新显示
        
        参数:
            assembly_text: 用户输入的汇编文本
        
        返回值:
            无
        """
        # 更新汇编文本并尝试汇编
        ego._update_assembly_text(assembly_text)

        # 获取当前正在编辑的指令
        current_insn = ego.get_insn(ego.address)
        
        # 检查指令是否有效
        if current_insn is None:
            return

        # 计算新指令的结束位置
        edit_index = ego.instructions.index(current_insn)
        clobber_end = ego.address + len(ego.assembly_bytes)
        will_clobber = clobber_end > (current_insn.address + current_insn.size)

        # 标记可能被覆盖的后续指令
        for next_insn in ego.instructions[edit_index+1:]:
            next_insn.clobbered = (next_insn.address < clobber_end) and will_clobber

        # 通知 View 层刷新显示（UI 更新由 View 层自己处理）
        if ego.view:
            ego.view.refresh_fields()
            ego.view.refresh_code()

    def commit_assembly(ego):
        """
        提交汇编补丁（应用修改到 IDA 数据库）
        
        当用户点击"确定"按钮或按 Enter 时调用：
        1. 验证汇编字节是否有效
        2. 调用核心补丁函数写入数据库
        3. 刷新指令列表
        4. 刷新 UI 显示
        
        参数:
            无
        
        返回值:
            无
        """
        # 如果没有汇编字节，直接返回
        if not ego.assembly_bytes:
            return

        # 在当前地址应用补丁
        ego.core.patch(ego.address, ego.assembly_bytes)

        # 刷新指令列表和字段
        ego._refresh_lines()
        
        # 如果 UI 存在，也刷新字段
        if ego.view:
            ego.view.refresh_fields()

    def _update_assembly_text(ego, assembly_text):
        """
        更新汇编文本并尝试汇编（内部方法）
        
        这是核心的汇编验证逻辑，执行以下步骤：
        1. 保存用户输入的文本
        2. 解析指令助记符和操作数
        3. 检查是否是 Keystone 不支持的指令
        4. 检查符号数量（防止大量符号解析导致卡顿）
        5. 检查特殊字符串（防止 Keystone bug）
        6. 调用汇编器生成机器码
        7. 设置状态消息（成功/失败）
        
        参数:
            assembly_text: 用户输入的汇编文本
        
        返回值:
            无（结果保存在 ego.assembly_bytes 和 ego.status_message）
        """
        ego.assembly_text = assembly_text
        ego.assembly_bytes = bytes()
        ego.status_message = ''

        # 解析汇编指令 components
        _, mnemonic, operands = parse_disassembly_components(assembly_text)

        # 检查是否是 Keystone 不支持的助记符
        if mnemonic.upper() in ego.core.assembler.UNSUPPORTED_MNEMONICS:
            ego.status_message = "Keystone 不支持此指令 (%s)" % mnemonic
            return

        # 检查符号数量（防止用户粘贴大量随机文本导致 IDA 卡死）
        if len(scrape_symbols(operands)) > 10:
            ego.status_message = "Too many potential symbols in the assembly text"
            return

        # 特殊字符串检查（Keystone 的已知 bug）
        assembly_normalized = assembly_text.strip().lower()

        if assembly_normalized.startswith('.string'):
            ego.status_message = "Unsupported declaration (.string can hang Keystone)"
            return

        # 暂不支持多指令输入
        if ';' in assembly_normalized:
            ego.status_message = "Multi-instruction input not yet supported (';' not allowed)"
            return

        # 尝试汇编
        ego.assembly_bytes = ego.core.assemble(ego.assembly_text, ego.address)
        if not ego.assembly_bytes:
            ego.status_message = '...'  # 汇编出错

    #-------------------------------------------------------------------------
    # 杂项方法
    #-------------------------------------------------------------------------

    def refresh(ego):
        """
        刷新控制器状态（基于当前 IDA 状态）
        
        这是主要的刷新入口，执行以下操作：
        1. 重新加载指令列表（_refresh_lines）
        2. 重新选择当前地址（select_address）
        
        注意：这个方法会被频繁调用，确保效率！
        
        参数:
            无
        
        返回值:
            无
        """
        ego._refresh_lines()
        ego.select_address(ego.address)

    def _refresh_lines(ego):
        """
        刷新反汇编列表（从 IDA 数据库加载指令）
        
        根据当前地址的类型（代码段/数据段）采用不同策略：
        
        代码段:
        - 向前扫描 16 条指令
        - 向后扫描 32 条指令
        - 使用 prev_head/next_head 确保地址有效性
        
        数据段:
        - 从当前地址开始向前扫描 256 字节
        - 跳过前导 00，从第一个非 00 字节开始
        - 以连续 00 00 或 64 字节为界分行
        - 每行作为一个独立的"数据块"显示
        
        参数:
            无
        
        返回值:
            无（结果保存在 ego.instructions）
        """
        instructions = []
        
        PREV_INSTRUCTIONS = 16   # 向前扫描的指令数
        NEXT_INSTRUCTIONS = 32   # 向后扫描的指令数
        DATA_BUFFER_SIZE = 256   # 数据段扫描缓冲区大小
        DATA_BLOCK_SIZE = 64     # 数据段每块最大字节数
        MAX_PREVIEW_BYTES = ego.core.assembler.MAX_PREVIEW_BYTES

        # 检测当前地址是代码段还是数据段
        seg_type = ida_segment.segtype(ego._address_origin)
        is_data_segment = (seg_type != ida_segment.SEG_CODE)
        
        if is_data_segment:
            # 数据段：智能分块显示
            start_ea = ego._address_origin
            buffer = ida_bytes.get_bytes(start_ea, DATA_BUFFER_SIZE)
            if not buffer:
                return
            
            # 从起始位置开始分块
            current_offset = 0
            
            while current_offset < len(buffer):
                # 使用工具方法查找下一个数据块
                block_start, block_end = Mng_Pat.find_data_block_range(
                    buffer, current_offset, DATA_BLOCK_SIZE
                )
                
                # 如果没有找到有效块，退出循环
                if block_start is None:
                    break
                
                # 为这个块创建一行 InstructionLine
                block_ea = start_ea + block_start
                block_size = block_end - block_start + 1
                
                if block_size > 0:
                    try:
                        line = InstructionLine(block_ea, block_size, MAX_PREVIEW_BYTES, is_data_block=True)
                        instructions.append(line)
                    except ValueError as e:
                        print(f"Warning: Failed to create data block at 0x{block_ea:08X}: {e}")
                
                # 移动到下一个块（跳过连续的 00）
                current_offset = block_end + 1
                while current_offset < len(buffer) and buffer[current_offset] == 0x00:
                    current_offset += 1
                
                # 如果下一个位置超出范围，停止
                if current_offset >= len(buffer):
                    break
                
        else:
            # 代码段：使用原始逻辑
            current_address = ego._address_origin
            for i in range(PREV_INSTRUCTIONS):
                prev_addr = ida_bytes.prev_head(current_address, 0)
                if prev_addr == ida_idaapi.BADADDR:
                    break
                current_address = prev_addr

            # 生成指令行
            for i in range(PREV_INSTRUCTIONS + NEXT_INSTRUCTIONS):
                if current_address == ida_idaapi.BADADDR:
                    break
                    
                try:
                    line = InstructionLine(current_address, None, MAX_PREVIEW_BYTES, is_data_block=False)
                    instructions.append(line)
                except ValueError as e:
                    print("Warning: Failed to create instruction line at 0x%08X: %s" % (current_address, str(e)))
                
                current_address = ida_bytes.next_head(current_address, ida_idaapi.BADADDR)

        ego.instructions = instructions

        # 如果有 UI，刷新代码视图
        if ego.view:
            ego.view.refresh_code()

    def get_insn(ego, ea):
        """
        获取指定地址的指令对象
        
        参数:
            ea: 目标地址
        
        返回值:
            InstructionLine 对象，如果找到；否则为 None
        """
        insn, _ = ego.get_insn_lineno(ea)
        return insn

    def get_insn_lineno(ego, ea):
        """
        获取指定地址的指令对象及其行号
        
        在指令列表中查找包含给定地址的指令，并返回：
        - 指令对象
        - 该指令在列表中的行号（考虑多行指令）
        
        如果未精确匹配，返回最接近的指令（地址 <= ea）
        
        参数:
            ea: 目标地址
        
        返回值:
            (insn, lineno) 元组，如果找到；否则 (None, 0)
        """
        # 检查是否有指令
        if not ego.instructions:
            print("Warning: No instructions available")
            return (None, 0)
        
        lineno = 0
        for insn in ego.instructions:
            if insn.address <= ea < insn.address + insn.size:
                return (insn, lineno)
            lineno += insn.num_lines
        
        # 未精确匹配，查找最接近的指令
        closest_insn = None
        closest_lineno = 0
        lineno = 0
        
        for insn in ego.instructions:
            if insn.address <= ea:
                closest_insn = insn
                closest_lineno = lineno
            else:
                break
            lineno += insn.num_lines
        
        if closest_insn:
            print("Warning: Address 0x%08X not found exactly, using closest instruction at 0x%08X" % (ea, closest_insn.address))
            return (closest_insn, closest_lineno)
        
        return (None, 0)


# ============================================================================
# 指令行类（显示辅助）
# ============================================================================

COLORED_SEP = ida_lines.COLSTR('|', ida_lines.SCOLOR_SYMBOL)

class InstructionLine(object):
    """
    指令行对象（用于在代码视图中绘制单条指令）
    
    封装了 IDA 反汇编行的所有显示信息：
    - 地址（彩色）
    - 字节（彩色）
    - 反汇编文本（彩色）
    - 标签名（如果有）
    - 高亮标记（冲突检测）
    
    属性:
        colored_instruction: 彩色的反汇编文本
        name: 标签名（如 loc_140004200）
        num_lines: 渲染行数（1-3 行）
        size: 指令长度
        bytes: 指令字节
        address: 指令地址
        clobbered: 是否被新指令覆盖
    """
    def __init__(ego, ea, block_size=None, max_preview=4, is_data_block=False):
        """
        初始化指令行对象
        
        参数:
            ea: 指令地址
            block_size: 数据块的字节数（仅数据段使用）
            max_preview: 最多显示的字节数
            is_data_block: 是否为数据块
        """
        ego.address = ea
        ego._is_data_block = is_data_block
        ego._max_preview = max_preview
        
        if is_data_block and block_size is not None:
            # 数据块模式：直接使用给定的块大小
            ego.size = block_size
            ego.bytes = ida_bytes.get_bytes(ea, ego.size)
            if not ego.bytes:
                raise ValueError("Failed to read data at 0x%08X" % ea)
            
            # 数据块没有标签名
            ego.name = None
            ego.num_lines = 1
            
            # 生成简化的反汇编文本（DB 形式）
            ego.colored_instruction = ego._generate_data_disasm()
        else:
            # 代码段模式：使用原始逻辑
            # 生成反汇编行（必须先调用，否则 get_item_size 可能获取过时的长度）
            ego.colored_instruction = ida_lines.generate_disasm_line(ea)
            if not ego.colored_instruction:
                raise ValueError("Bad address... 0x%08X" % ea)

            # 标签名
            ego.name = ida_name.get_short_name(ea)

            # 渲染行数
            ego.num_lines = 1 + (2 if ego.name else 0)

            # 指令信息
            ego.size = ida_bytes.get_item_size(ea)
            ego.bytes = ida_bytes.get_bytes(ea, ego.size)

        # 冲突高亮标记
        ego.clobbered = False
        ego._max_preview = max_preview

    def _generate_data_disasm(ego):
        """
        为数据块生成简化的反汇编文本
        
        格式：db XX, XX, XX, ... （最多显示 max_preview 个字节）
        """
        MAX_BYTES = ego._max_preview
        
        # 准备显示的字节
        if ego.size > MAX_BYTES:
            display_bytes = ego.bytes[:MAX_BYTES-1]
            truncated = True
        else:
            display_bytes = ego.bytes
            truncated = False
        
        # 生成十六进制字符串
        hex_parts = ['%02X' % b for b in display_bytes]
        if truncated:
            hex_parts.append('..')
        
        hex_str = ', '.join(hex_parts)
        
        # 添加颜色
        colored_hex = ida_lines.COLSTR(hex_str, ida_lines.SCOLOR_NUMBER)
        db_keyword = ida_lines.COLSTR('db', ida_lines.SCOLOR_INSN)
        
        return '%s %s' % (db_keyword, colored_hex)

    @property
    def colored_address(ego):
        """
        返回彩色的地址字符串
        
        格式：前缀 + 8 位十六进制地址
        颜色：SCOLOR_PREFIX（通常是灰色）
        """
        pretty_address = ida_lines.COLSTR('%08X' % ego.address, ida_lines.SCOLOR_PREFIX)
        return pretty_address

    @property
    def colored_bytes(ego):
        """
        返回彩色的指令字节字符串
        
        如果指令超过 max_preview 字节，截断并显示省略号
        颜色：SCOLOR_BINPREF（通常是蓝色）
        
        对于数据块：不显示末尾的连续 00
        """
        MAX_BYTES = ego._max_preview
        
        # 处理数据块的特殊逻辑
        if ego._is_data_block:
            # 检测是否为 UTF-16LE 模式
            is_utf16 = Mng_Pat.detect_utf16_encoding(ego.bytes, 0, len(ego.bytes))
            
            # 使用工具函数去除末尾连续 00
            trimmed_bytes = trim_trailing_zeros(ego.bytes, is_utf16=is_utf16)
            
            # 限制显示长度
            if len(trimmed_bytes) > MAX_BYTES:
                text_bytes = hexdump(trimmed_bytes[:MAX_BYTES-1]).ljust(3*MAX_BYTES-1, '.')
            else:
                text_bytes = hexdump(trimmed_bytes).ljust(3*MAX_BYTES-1, ' ')
        else:
            # 代码段：使用原始逻辑
            if ego.size > MAX_BYTES:
                text_bytes = hexdump(ego.bytes[:MAX_BYTES-1]).ljust(3*MAX_BYTES-1, '.')
            else:
                text_bytes = hexdump(ego.bytes).ljust(3*MAX_BYTES-1, ' ')

        pretty_bytes = ida_lines.COLSTR(text_bytes, ida_lines.SCOLOR_BINPREF)
        return pretty_bytes

    @property
    def line_blank(ego):
        """
        返回空白行（用于多行指令的第一行）
        
        格式：空 + 地址 + | + 空白填充 + |
        """
        byte_padding = ' ' * ((ego._max_preview*3) - 1)
        ego._line_blank = ' '.join(['', ego.colored_address, COLORED_SEP, byte_padding , COLORED_SEP])
        return ego._line_blank

    @property
    def line_name(ego):
        """
        返回标签名行（如果地址有标签）
        
        格式：空 + 地址 + | + 空白填充 + | + 标签名：
        颜色：SCOLOR_CNAME（通常是青色）
        """
        if not ego.name:
            return None

        pretty_name = ida_lines.COLSTR(ego.name, ida_lines.SCOLOR_CNAME) + ':'
        byte_padding = ' ' * ((ego._max_preview*3) - 1)

        ego._line_name = ' '.join(['', ego.colored_address, COLORED_SEP, byte_padding , COLORED_SEP, pretty_name])
        return ego._line_name

    @property
    def line_instruction(ego):
        """
        返回指令文本行
        
        格式：空 + 地址 + | + 字节 + | + 反汇编文本
        """
        ego._line_text = ' '.join(['', ego.colored_address, COLORED_SEP, ego.colored_bytes, COLORED_SEP + '  ', ego.colored_instruction])
        return ego._line_text