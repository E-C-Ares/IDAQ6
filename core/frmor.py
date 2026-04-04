# -*- coding: utf-8 -*-
"""
汇编补丁 UI 控制器模块

本模块实现了汇编补丁窗口的用户界面（MVC 模式中的 View）：
- PatchingDockable: 主窗口容器，管理所有 UI 元素
- PatchingCodeViewer: IDA 风格的代码查看器
- AsmLineEdit/BytesLineEdit: 自定义输入控件
"""

from .__deps_ import *

from .utils.qt import *
from .parti import parse_line_ea, UIHooks

from .part3 import hexdump, trim_trailing_zeros


LAST_LINE_IDX = -1  # 特殊标记，表示使用指令的最后一行

# ============================================================================
# 主窗口容器类
# ============================================================================

class Frm_Pat(ida_kernwin.PluginForm):
    """
    补丁编辑器 UI 容器（MVC 中的 View）
    
    这是汇编补丁窗口的主要 UI 组件，负责：
    - 创建所有 UI 控件（输入框、按钮、代码视图等）
    - 布局管理
    - 事件处理
    - 与控制器通信，显示数据和接收用户输入
    
    __a = None
    @staticmethod
    def create(controller):
        if PatchingDockable.__a is None:
            PatchingDockable.__a = PatchingDockable(controller)
        else:
            PatchingDockable.__a.switch_to(controller)
        return PatchingDockable.__a
    """

    def __init__(ego, controller):
        """
        初始化 UI 容器
        
        参数:
            controller: 补丁控制器实例（PatchingController）
        """
        super().__init__()
        ego.controller = controller  # 保存控制器引用
        ego._has_unsaved_changes = False  # 跟踪修改状态
        ego.count = 0  # 计数器（可能用于调试）
        
        # 标记当前地址是否在代码段或数据段
        ego._is_code_segment = True  # 默认假设为代码段，将在 refresh_fields 中更新
        
        # 跟踪字节字段的修改状态
        ego._bytes_modified = False
        
        # 存储地址范围计算得出的允许字节数
        ego._allowed_byte_count = 0  # 将在 refresh_fields 中设置

    # -------------------------------------------------------------------------
    # IDA PluginForm 重写方法
    # -------------------------------------------------------------------------

    def Show(ego):
        """
        显示窗口
        
        调用 IDA 的窗口显示函数，设置窗口为浮动居中模式，
        设置初始光标位置和键盘焦点。
        """
        # 使用 plgform_show 替代标准的 Show 方法（可能是为了浮动窗口）
        flags = ida_kernwin.PluginForm.WOPN_DP_FLOATING | ida_kernwin.PluginForm.WOPN_CENTERED
        ida_kernwin.plgform_show(ego.__clink__, ego, ego.controller.WINDOW_TITLE, flags)
        ego._center_dialog()

        # 设置初始光标位置到目标地址
        # 将光标位置向下偏移几行以更好地居中
        ego.set_cursor_pos(ego.controller.address, ego.controller.address_idx, 0, 6)

        # 设置初始键盘焦点到汇编输入框
        ego._line_assembly.setFocus(QtCore.Qt.FocusReason.ActiveWindowFocusReason)

    def OnCreate(ego, form):
        """
        窗口创建回调（当 IDA 创建窗口时调用）
        
        初始化 UI 组件和 Qt 小部件。
        
        参数:
            form: IDA 窗口小部件
        """
        ego._twidget = form
        ego.widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(ego._twidget)
        ego._ui_init()

    def OnClose(ego, form):
        """
        窗口关闭回调（当用户关闭窗口时调用）
        
        清理资源，停止定时器，清除控制器引用。
        
        参数:
            form: IDA 窗口小部件
        
        返回值:
            super().OnClose(form) 的返回值
        """
        # 安全清理资源（检查属性是否存在以防初始化失败）
        if hasattr(ego, '_code_view'):
            ego._code_view = None
        if hasattr(ego.controller, 'view'):
            ego.controller.view = None
        return super().OnClose(form)

    # -------------------------------------------------------------------------
    # UI 初始化方法
    # -------------------------------------------------------------------------

    def _ui_init(ego):
        """
        初始化 UI 元素
        
        创建所有 UI 控件，设置字体，初始化代码视图和字段，
        布局组件，连接信号。
        """
        ego.widget.setMinimumSize(420, 420)  # 设置最小窗口大小

        # 设置等宽字体用于代码显示
        ego._font = QtGui.QFont("Courier New")
        ego._font.setStyleHint(QtGui.QFont.Monospace)

        # 初始化 UI 元素
        ego._ui_init_code()    # 代码视图
        ego._ui_init_fields()  # 输入字段

        # 用数据库中的初始内容填充对话框/字段
        ego.refresh()

        # 设置代码视图聚焦到初始行
        ego._code_view.Jump(ego._code_view.GetLineNo(), y=6)

        # 布局已填充的 UI
        ego._ui_layout()
        
        # 连接信号
        ego._ex_reg.clicked.connect(ego._commit_clicked)  # 确定按钮
        ego._ex_end.clicked.connect(ego._on_full_edit_clicked)  # 全编按钮
        
        # 连接编码选择器信号 - 用于切换不同编码模式
        ego._ex_enc.currentIndexChanged.connect(ego._on_encoding_changed)
        
        # 内容框编辑信号 - 同步到字节框
        ego._line_assembly.textEdited.connect(ego._on_content_edited)
        
        # 字节框编辑信号 - 同步到内容框
        ego._fx_byt.textEdited.connect(ego._on_bytes_edited)
        
        # 回车键预览（不提交）
        ego._line_assembly.returnPressed.connect(ego._enter_pressed)

    def _ui_init_fields(ego):
        """
        初始化交互式文本字段
        
        创建地址、内容、字节等输入/显示字段。
        """
        # 地址标签
        ego._line_address = QtWidgets.QLabel()
        ego._line_address.setFont(ego._font)
        ego._label_address = QtWidgets.QLabel("里目：")  # "里目" = "Address"
        ego._label_address.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        
        # 全编辑模式标志
        ego._full_edit_mode = False

        # 内容输入框（汇编文本或字符串）
        ego._line_assembly = AsmLineEdit(ego._code_view)
        ego._line_assembly.setFont(ego._font)
        ego._line_assembly.setMinimumWidth(350)
        ego._label_assembly = QtWidgets.QLabel("内容：")  # "内容" = "Content"
        ego._label_assembly.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)

        # 字节输入框（十六进制）
        ego._fx_byt = BytesLineEdit()
        ego._fx_byt.setFont(ego._font)
        ego._label_bytes = QtWidgets.QLabel("字节：")  # "字节" = "Bytes"
        ego._label_bytes.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        ego._label_bytes.setToolTip("可直接编辑十六进制字节 (如：90 90 90)")
        
        # 连接字节字段变化信号
        ego._fx_byt.textEdited.connect(ego._on_bytes_edited)

        # 编码选择器 - 用于字符串模式
        ego._ex_enc = QtWidgets.QComboBox()
        ego._ex_enc.setEditable(False)
        ego._ex_enc.addItem("Assem", "asm")      # 汇编模式
        ego._ex_enc.addItem("ASCII", "ascii")    # ASCII 编码
        ego._ex_enc.addItem("UTF-8", "utf-8")    # UTF-8 编码
        ego._ex_enc.addItem("Latin-1", "latin-1") # Latin-1 编码
        ego._ex_enc.addItem("GBK", "gbk")        # GBK 编码
        ego._ex_enc.addItem("UTF-16LE", "utf-16-le")  # UTF-16 LE 编码
        ego._ex_enc.addItem("UTF-16BE", "utf-16-be")  # UTF-16 BE 编码
        ego._ex_enc.setToolTip("选择编码格式")
        
        # 全编辑按钮 - 用于整体编辑模式
        ego._ex_end = QtWidgets.QPushButton("全编")  # "全编" = "Full Edit"
        ego._ex_end.setToolTip("将末尾缓冲区纳入内容进行整体编辑 比如代码 nop 和字符串 00")

        # 确定按钮
        ego._ex_reg = QtWidgets.QPushButton("确定 (&O)")  # "确定" = "OK"
        ego._ex_reg.setToolTip("应用修改 (Enter)")
        ego._ex_reg.setDefault(True)

        # 状态消息标签（显示大小比较和状态）
        ego._fc_sta = QtWidgets.QLabel()
        ego._fc_sta.setStyleSheet("color: gray;")
        ego._fc_sta.setWordWrap(True)

    def _ui_init_code(ego):
        """
        初始化代码视图
        
        创建 IDA 风格的代码查看器。
        """
        ego._code_view = PatchingCodeViewer(ego.controller)

    def _ui_layout(ego):
        """
        布局 UI 组件
        
        使用网格布局排列所有 UI 元素。
        """
        _ly_out = QtWidgets.QGridLayout(ego.widget)

        # 在网格中排列组件  行 列 行跨度 列跨度
        _ly_out.addWidget(ego._label_address,     0,  0,  1,  1)  # 地址标签
        _ly_out.addWidget(ego._line_address,      0,  1,  1,  1)  # 地址显示
        _ly_out.addWidget(ego._ex_end,            0,  2,  1,  1)  # 全编按钮
        _ly_out.addWidget(ego._label_assembly,    1,  0,  1,  1)  # 内容标签
        _ly_out.addWidget(ego._line_assembly,     1,  1,  1,  1)  # 内容输入
        _ly_out.addWidget(ego._ex_enc,            1,  2,  1,  1)  # 编码选择
        _ly_out.addWidget(ego._label_bytes,       2,  0,  1,  1)  # 字节标签
        _ly_out.addWidget(ego._fx_byt,            2,  1,  1,  1)  # 字节输入
        _ly_out.addWidget(ego._ex_reg,            2,  2,  1,  1)  # 确定按钮
        _ly_out.addWidget(ego._fc_sta,            3,  0,  1,  3)  # 状态栏
        _ly_out.addWidget(ego._code_view.widget,  4,  0,  1,  3)  # 代码视图

        # 应用布局
        ego.widget.setLayout(_ly_out)

    def _center_dialog(ego):
        """
        将对话框居中到 IDA 主窗口
        
        搜索父窗口直到找到 IDA 主窗口，然后计算中心位置。
        """
        wid_main, wid_dialog = None, None

        # 向上搜索父窗口直到找到 IDA 主窗口
        parent = ego.widget.parent()
        while parent:
            if isinstance(parent, QtWidgets.QMainWindow):
                wid_main = parent
                break
            elif isinstance(parent, QtWidgets.QWidget):
                if parent.windowTitle() == ego.controller.WINDOW_TITLE:
                    wid_dialog = parent
            parent = parent.parent()

        # 如果找不到主窗口和对话框容器，返回失败
        if not (wid_main and wid_dialog):
            return False

        rect_main = wid_main.geometry()
        rect_dialog = wid_dialog.rect()

        # 计算对话框的新位置使其居中于 IDA 主窗口
        pos_dialog = rect_main.center() - rect_dialog.center()
        wid_dialog.move(pos_dialog)

    # -------------------------------------------------------------------------
    # 刷新方法
    # -------------------------------------------------------------------------

    def _commit_clicked(ego):
        """
        确定按钮点击事件处理
        
        验证输入合法性，然后将字节写入数据库。
        """
        # 检查当前状态是否为错误状态（红色）
        current_style = ego._fc_sta.styleSheet()
        if "color: red" in current_style:
            print("[Commit] Blocked: Current status is error")
            return
        
        if not ego._bytes_modified:
            print("[Commit] No changes to commit")
            return
        
        # 解析当前字节框的内容
        hex_string = ego._fx_byt.text().replace(' ', '').replace('\t', '')
        
        try:
            # 验证十六进制
            if len(hex_string) % 2 != 0:
                ego._fc_sta.setStyleSheet("color: red;")
                ego._fc_sta.setText("✗ 十六进制长度必须为偶数")
                return
            
            new_bytes = bytes.fromhex(hex_string)
            
            # 最终检查大小
            if len(new_bytes) > ego._allowed_byte_count:
                ego._fc_sta.setStyleSheet("color: red;")
                ego._fc_sta.setText(f"✗ 字节数 ({len(new_bytes)}) 超出地址范围 ({ego._allowed_byte_count})")
                return
            
            # 应用补丁到数据库
            ego.controller.core.patch(ego.controller.address, new_bytes)
            
            # 重置修改标志
            ego._bytes_modified = False
            ego._has_unsaved_changes = False
            
            # 更新状态
            ego._fc_sta.setStyleSheet("color: green;")
            ego._fc_sta.setText("✓ 修改已应用")
            
            # 刷新整个视图（从数据库重新读取）
            ego.refresh()
            
            print(f"[Commit] Patched {len(new_bytes)} bytes at 0x{ego.controller.address:08X}")
            
        except ValueError as e:
            ego._fc_sta.setStyleSheet("color: red;")
            ego._fc_sta.setText(f"✗ 提交失败：{str(e)}")
            print(f"[Commit] Error: {e}")

    def _on_bytes_edited(ego, text):
        """
        字节字段编辑事件处理
        
        当用户编辑字节字段时，解析十六进制并根据当前编码模式同步更新内容框。
        不调用任何刷新方法，仅做简单的解码转换。
        
        参数:
            text: 用户输入的文本
        """
        try:
            # 解析十六进制字符串
            hex_string = text.replace(' ', '').replace('\t', '')
            
            # 验证十六进制字符串
            if len(hex_string) % 2 != 0:
                ego._fc_sta.setStyleSheet("color: orange;")
                ego._fc_sta.setText(f"⚠ 十六进制长度必须为偶数")
                return
            
            # 转换为字节
            new_bytes = bytes.fromhex(hex_string)
            
            # 更新状态
            ego._bytes_modified = True
            ego._has_unsaved_changes = True
            
            # 检查允许的字节数
            if len(new_bytes) > ego._allowed_byte_count:
                ego._fc_sta.setStyleSheet("color: red;")
                ego._fc_sta.setText(f"✗ 字节数 ({len(new_bytes)}) 超出限制 ({ego._allowed_byte_count})")
            elif len(new_bytes) == ego._allowed_byte_count:
                ego._fc_sta.setStyleSheet("color: orange;")
                ego._fc_sta.setText(f"⚠ 字节数：{len(new_bytes)} / {ego._allowed_byte_count}")
            else:
                ego._fc_sta.setStyleSheet("color: gray;")
                ego._fc_sta.setText(f"字节数：{len(new_bytes)}/{ego._allowed_byte_count}")
            
            # 如果在字符串模式下，同步更新内容框文本
            current_encoding_idx = ego._ex_enc.currentIndex()
            current_encoding_data = ego._ex_enc.itemData(current_encoding_idx)
            
            if current_encoding_data != "asm":
                try:
                    # 将字节解码为文本并更新内容框（阻止信号防止递归）
                    decoded_text = new_bytes.decode(current_encoding_data).rstrip('\x00')
                    ego._line_assembly.blockSignals(True)
                    ego._line_assembly.setText(decoded_text)
                    ego._line_assembly.blockSignals(False)
                except (UnicodeDecodeError, LookupError) as e:
                    # 解码失败时，不清空内容框，让用户继续编辑字节
                    pass

        except ValueError as e:
            ego._fc_sta.setStyleSheet("color: red;")
            ego._fc_sta.setText(f"✗ 格式错误：{str(e)}")

    def _on_encoding_changed(ego, index):
        """
        编码选择变化事件处理
        
        当用户更改编码格式时，根据当前字节数据重新解码显示。
        不修改底层数据，仅改变显示方式。
        
        参数:
            index: 选中的编码索引
        """
        encoding = ego._ex_enc.itemData(index)
        
        # 获取当前显示的字节（优先使用用户修改的字节）
        if ego._bytes_modified:
            hex_string = ego._fx_byt.text().replace(' ', '').replace('\t', '')
            try:
                if len(hex_string) % 2 == 0:
                    current_bytes = bytes.fromhex(hex_string)
                else:
                    # 奇数字节，从 IDA 读取
                    current_bytes = ida_bytes.get_bytes(ego.controller.address, ego._allowed_byte_count)
            except ValueError:
                current_bytes = ida_bytes.get_bytes(ego.controller.address, ego._allowed_byte_count)
        else:
            # 从 IDA 读取原始字节
            current_bytes = ida_bytes.get_bytes(ego.controller.address, ego._allowed_byte_count)
        
        if not current_bytes:
            return
        
        if encoding == "asm":
            # 汇编模式：显示反汇编指令
            asm_text = ego.controller.core.assembler.format_assembly(ego.controller.address)
            ego._line_assembly.blockSignals(True)
            ego._line_assembly.setText(asm_text)
            ego._line_assembly.blockSignals(False)
            
            # 显示原始字节
            ego._fx_byt.blockSignals(True)
            ego._fx_byt.setText(hexdump(current_bytes))
            ego._fx_byt.blockSignals(False)
        else:
            # 字符串模式：尝试解码为文本
            # UTF-16 编码要求字节数必须为偶数
            is_utf16 = (encoding in ["utf-16-le", "utf-16-be"])
            if is_utf16 and len(current_bytes) % 2 != 0:
                current_bytes = current_bytes[:-1]  # 截断为偶数
            
            try:
                decoded_text = current_bytes.decode(encoding).rstrip('\x00')
                ego._line_assembly.blockSignals(True)
                ego._line_assembly.setText(decoded_text)
                ego._line_assembly.blockSignals(False)
                
                ego._fx_byt.blockSignals(True)
                ego._fx_byt.setText(hexdump(current_bytes))
                ego._fx_byt.blockSignals(False)
            except (UnicodeDecodeError, LookupError) as e:
                # 解码失败，回退到 ASCII
                try:
                    decoded_text = current_bytes.decode('ascii', errors='replace').rstrip('\x00')
                    ego._line_assembly.blockSignals(True)
                    ego._line_assembly.setText(decoded_text)
                    ego._line_assembly.blockSignals(False)
                except:
                    pass

    def _on_content_edited(ego, text):
        """
        内容框编辑事件处理
        
        当用户编辑内容框时，根据当前编码模式同步更新字节框。
        不调用任何刷新方法，不触发汇编，仅做简单的编码转换。
        
        参数:
            text: 用户输入的文本
        """
        # 获取当前选中的编码
        current_encoding_idx = ego._ex_enc.currentIndex()
        current_encoding_data = ego._ex_enc.itemData(current_encoding_idx)
        
        if current_encoding_data == "asm":
            # 汇编模式：只更新状态，不做其他操作
            # 实际的汇编和预览在回车或确定时进行
            ego._fc_sta.setStyleSheet("color: gray;")
            ego._fc_sta.setText("按 Enter 预览，点击确定提交")
            return
        
        # 字符串模式：将文本编码为字节
        try:
            # 将文本编码为字节
            encoded_bytes = text.encode(current_encoding_data)
            
            # 检查长度
            if len(encoded_bytes) > ego._allowed_byte_count:
                ego._fc_sta.setStyleSheet("color: red;")
                ego._fc_sta.setText(f"✗ 文本过长 ({len(encoded_bytes)} 字节) > 限制 ({ego._allowed_byte_count})")
                # 仍然更新字节框，让用户看到超出的部分
                ego._fx_byt.blockSignals(True)  # 阻止递归信号
                ego._fx_byt.setText(hexdump(encoded_bytes))
                ego._fx_byt.blockSignals(False)
                return
            
            # 更新状态
            ego._bytes_modified = True
            ego._has_unsaved_changes = True
            
            # 更新字节框（阻止信号防止递归）
            ego._fx_byt.blockSignals(True)
            ego._fx_byt.setText(hexdump(encoded_bytes))
            ego._fx_byt.blockSignals(False)
            
            # 更新状态栏
            ego._fc_sta.setStyleSheet("color: gray;")
            ego._fc_sta.setText(f"字节数：{len(encoded_bytes)}/{ego._allowed_byte_count}")
            
        except (UnicodeEncodeError, LookupError) as e:
            ego._fc_sta.setStyleSheet("color: red;")
            ego._fc_sta.setText(f"✗ 编码失败：{str(e)}")

    def _on_full_edit_clicked(ego):
        """
        全编辑按钮点击事件处理
        
        切换全编辑模式。
        """
        ego._full_edit_mode = not ego._full_edit_mode
        
        # 更新按钮外观
        if ego._full_edit_mode:
            ego._ex_end.setStyleSheet("background-color: orange;")
            ego._ex_end.setToolTip("全编模式：将显示到对齐块末尾的地址范围")
        else:
            ego._ex_end.setStyleSheet("")
            ego._ex_end.setToolTip("将末尾缓冲区纳入内容进行整体编辑 比如代码 nop 和字符串 00")
        
        # 刷新字段以更新地址显示
        ego.refresh_fields()

    def refresh(ego):
        """
        刷新整个补丁对话框
        
        同时刷新字段和代码视图。
        """
        ego.refresh_fields()
        ego.refresh_code()

    def refresh_fields(ego):
        """
        刷新补丁字段
        
        更新地址、内容、字节等字段的显示内容。
        """
        # 从控制器获取当前地址
        current_ea = ego.controller.address
        
        # 确定当前地址是否在代码段
        seg_type = ida_segment.segtype(current_ea)
        ego._fb_dat = (seg_type != ida_segment.SEG_CODE)
        byte_count = 0
        
        # 初始化编码检测结果
        detected_encoding = "asm"  # 默认为汇编模式
        
        # 根据段类型计算结束地址
        if ego._fb_dat: 
            # 数据段：使用控制器的工具方法查找第一个数据块
            BUFFER_SIZE = 256
            buffer = ida_bytes.get_bytes(current_ea, BUFFER_SIZE)
            
            if not buffer:
                return
            
            # 查找第一个数据块的范围
            block_start, block_end = ego.controller.find_data_block_range(buffer, 0, 64)
            
            if block_start is None:
                # 全是 00
                ego._line_address.setText('0x%08X - 0x%08X (0 字节)' % (current_ea, current_ea))
                ego._allowed_byte_count = 0
                return
            
            # 计算有效字节数（不包括末尾连续 00）
            effective_end = block_end
            while effective_end > block_start and buffer[effective_end] == 0x00:
                effective_end -= 1
            
            # UTF-16LE 特殊处理
            is_utf16 = ego.controller.detect_utf16_encoding(buffer, block_start, effective_end - block_start + 1)
            
            if is_utf16 and effective_end > block_start:
                # UTF-16LE 模式，保留一个 00
                if buffer[effective_end] != 0x00:
                    effective_end += 1
            
            end_ea = current_ea + (effective_end - block_start)
            byte_count = end_ea - current_ea + 1
            
            # 检测编码
            detected_encoding = "utf-16-le" if is_utf16 else "ascii"

        if byte_count == 0:
            # 代码段：使用原始逻辑
            next_ea = ida_bytes.next_head(current_ea, ida_idaapi.BADADDR)
            
            # 全编辑模式：跳过对齐块
            if ego._full_edit_mode and next_ea != ida_idaapi.BADADDR:
                flags = ida_bytes.get_flags(next_ea)
                if ida_bytes.is_align(flags):
                    align_size = ida_bytes.get_item_size(next_ea)
                    next_ea = ida_bytes.next_head(next_ea + align_size, ida_idaapi.BADADDR)
            
            if next_ea != ida_idaapi.BADADDR:
                end_ea = next_ea - 1
                byte_count = end_ea - current_ea + 1

        # 保存计算出的字节数用于字节字段验证
        ego._allowed_byte_count = byte_count
        
        address_text = '0x%08X - 0x%08X (%u 字节)' % (current_ea, end_ea, byte_count)

        # 更新地址字段
        ego._line_address.setText(address_text)

        # 更新汇编文本字段（保存并恢复光标位置）
        if ego._line_assembly.text() != ego.controller.assembly_text:
            # 保存当前光标位置
            cursor_pos = ego._line_assembly.cursorPosition()
            selection_start = ego._line_assembly.selectionStart()
            selection_end = ego._line_assembly.selectionEnd()
            
            # 更新文本
            ego._line_assembly.setText(ego.controller.assembly_text)
            
            # 恢复光标位置（如果位置仍然有效）
            new_text_len = len(ego.controller.assembly_text)
            if cursor_pos <= new_text_len:
                ego._line_assembly.setCursorPosition(cursor_pos)
                # 如果有选区，也恢复选区
                if selection_start >= 0 and selection_end >= 0:
                    if selection_start <= new_text_len and selection_end <= new_text_len:
                        ego._line_assembly.setSelection(selection_start, selection_end)

        # 根据检测到的编码自动切换下拉框并更新显示内容
        if ego._fb_dat and not ego._bytes_modified:
            # 获取当前选中的编码
            current_encoding_idx = ego._ex_enc.currentIndex()
            current_encoding_data = ego._ex_enc.itemData(current_encoding_idx)
            
            # 如果检测到的编码与当前不同，则切换
            if detected_encoding != current_encoding_data:
                # 查找对应的索引
                for i in range(ego._ex_enc.count()):
                    if ego._ex_enc.itemData(i) == detected_encoding:
                        ego._ex_enc.setCurrentIndex(i)
                        print(f"[Encoding] 自动切换到：{detected_encoding}")
                        break
            
            # 根据编码模式显示不同内容
            if detected_encoding != "asm":
                # 字符串模式：读取原始字节并尝试解码为文本
                raw_bytes = ida_bytes.get_bytes(current_ea, byte_count)
                if raw_bytes:
                    try:
                        # 尝试用检测到的编码解码
                        decoded_text = raw_bytes.decode(detected_encoding).rstrip('\x00')
                        
                        # 内容框显示解码后的文本，字节框显示十六进制（不含末尾连续 00）
                        if not ego._bytes_modified:
                            ego._line_assembly.setText(decoded_text)
                            
                            # 使用工具函数去除末尾连续 00
                            trimmed_bytes = trim_trailing_zeros(raw_bytes, is_utf16=(detected_encoding == "utf-16-le"))
                            ego._fx_byt.setText(hexdump(trimmed_bytes))
                    except (UnicodeDecodeError, LookupError) as e:
                        # 解码失败时回退到 ASCII 或直接显示字节
                        print(f"[Encoding] 解码失败 ({detected_encoding}): {e}")
                        if not ego._bytes_modified:
                            ego._fx_byt.setText(hexdump(raw_bytes))
        
        # 更新汇编字节字段
        if not ego._bytes_modified:
            if ego.controller.status_message and ego.controller.status_message != '...':
                ego._fx_byt.setText(ego.controller.status_message)
            elif ego._fb_dat and ego.controller.status_message == '...':
                # 数据段汇编失败是正常的，直接显示该地址的原始字节（不含末尾连续 00）
                current_bytes = ida_bytes.get_bytes(ego.controller.address, ego._allowed_byte_count)
                if current_bytes:
                    # 使用工具函数去除末尾连续 00
                    trimmed_bytes = trim_trailing_zeros(current_bytes, is_utf16=(detected_encoding == "utf-16-le"))
                    ego._fx_byt.setText(hexdump(trimmed_bytes))
                else:
                    ego._fx_byt.setText(hexdump(ego.controller.assembly_bytes))
            elif not ego._fb_dat or (ego._fb_dat and detected_encoding == "asm"):
                # 代码段或汇编模式：显示汇编字节
                ego._fx_byt.setText(hexdump(ego.controller.assembly_bytes))
        
        # 更新状态消息
        if ego._bytes_modified:
            ego._fc_sta.setStyleSheet("color: orange;")
            ego._fc_sta.setText(f"⚠ 有未保存的修改 (字节：{len(ego.controller.assembly_bytes)}/{ego._allowed_byte_count})")
        else:
            ego._fc_sta.setStyleSheet("color: gray;")
            ego._fc_sta.setText("")

    def refresh_code(ego):
        """
        刷新补丁代码视图
        
        重新生成代码视图中的所有行。
        """
        ego._code_view.ClearLines()

        # 从控制器的指令列表重新生成视图
        for line in ego.controller.instructions:
            # 如果指令有标签（如 loc_140004200）
            # 应该显示这些额外的行以更好地模拟真实的 IDA 反汇编列表
            if line.name:
                ego._code_view.AddLine(line.line_blank)
                ego._code_view.AddLine(line.line_name)

            # 发出实际的指令文本
            ego._code_view.AddLine(line.line_instruction)

        ego._code_view.Refresh()

    def refresh_cursor(ego):
        """
        刷新代码视图中的用户光标
        
        将光标移动到当前控制器选中的位置。
        """
        # 获取代码视图中的文本坐标
        ida_pos = ego._code_view.GetPos()
        lineno_sel, x, y = ida_pos if ida_pos else (0, 0, 0)

        # 获取控制器模型中选中的指令
        insn, lineno_insn = ego.controller.get_insn_lineno(ego.controller.address)

        if ego.controller.address_idx == LAST_LINE_IDX:
            lineno_new = lineno_insn + (insn.num_lines - 1)
        else:
            lineno_new = lineno_insn + ego.controller.address_idx

        ego._code_view.Jump(lineno_new, x, y)

    # -------------------------------------------------------------------------
    # 事件处理方法
    # -------------------------------------------------------------------------

    def _enter_pressed(ego):
        """
        用户在汇编文本行聚焦时按回车键的事件处理
        
        注意：仅预览更改，实际提交仅在点击确定按钮时发生。
        """
        # 在汇编模式下，触发一次汇编预览
        current_encoding_idx = ego._ex_enc.currentIndex()
        current_encoding_data = ego._ex_enc.itemData(current_encoding_idx)
        
        if current_encoding_data == "asm":
            assembly_text = ego._line_assembly.text()
            ego.controller.edit_assembly(assembly_text)
            
            # 更新字节框显示汇编结果
            if ego.controller.assembly_bytes:
                ego._fx_byt.blockSignals(True)
                ego._fx_byt.setText(hexdump(ego.controller.assembly_bytes))
                ego._fx_byt.blockSignals(False)
                
                ego._fc_sta.setStyleSheet("color: gray;")
                ego._fc_sta.setText(f"预览：{len(ego.controller.assembly_bytes)} 字节")
        
        print("[Enter] Preview mode - click OK to commit changes")

    # -------------------------------------------------------------------------
    # 辅助方法
    # -------------------------------------------------------------------------

    def get_cursor(ego):
        """
        返回当前视图光标信息
        
        返回值:
            包含视图光标位置信息的元组 (address, relative_idx, x, y)
        """
        # 视图当前聚焦的行
        view_line = ego._code_view.GetCurrentLine()
        view_address = parse_line_ea(view_line)

        # 获取代码视图中的文本坐标
        view_pos = ego._code_view.GetPos()
        lineno, x, y = view_pos if view_pos else (0, 0, 0)

        # 计算相对于聚焦地址的行号
        global_idx, relative_idx = 0, -1
        while True:
            # 获取代码视图的一行
            line = ego._code_view.GetLine(global_idx)
            if not line:
                break

            # 解包代码查看器行元组
            colored_line, _, _ = line
            line_address = parse_line_ea(colored_line)

            if line_address == view_address:
                # 找到匹配光标地址的第一个指令行，开始相对行索引计数
                if relative_idx == -1:
                    relative_idx = 0
                else:
                    relative_idx += 1
            elif line_address > view_address:
                # 已到达大于当前选择地址的行，跳出
                break

            global_idx += 1

        # 返回位置信息，可用于跳转到确切位置
        return (view_address, relative_idx, x, y)

    def set_cursor_pos(ego, address, idx=0, x=0, y=0):
        """
        设置光标位置到指定地址
        
        参数:
            address: 目标地址
            idx: 相对索引
            x, y: 坐标
        """
        insn, lineno = ego.controller.get_insn_lineno(address)
        if not insn:
            raise ValueError("Failed to jump to given address 0x%08X" % address)

        # idx 为 -1 是特殊情况，聚焦到指令的最后一条线
        if idx == -1:
            idx = insn.num_lines - 1
        elif address != insn.address:
            idx = 0

        final_lineno = lineno + idx
        ego._code_view.Jump(final_lineno, x, y)


# ============================================================================
# 自定义输入控件
# ============================================================================

class AsmLineEdit(QtWidgets.QLineEdit):
    """
    自定义汇编文本输入框
    
    继承自 QLineEdit，增加了快捷键处理和代码视图集成。
    """

    def __init__(ego, code_view, parent=None):
        """
        初始化汇编输入框
        
        参数:
            code_view: 关联的代码视图
            parent: 父控件
        """
        super().__init__(parent)
        ego.code_view = code_view

    def focusInEvent(ego, event):
        """
        获得焦点时的事件处理
        
        仅在通过 Tab 键或程序化聚焦时全选，鼠标点击时保留点击位置。
        """
        super().focusInEvent(event)
        
        # 检查是否是通过鼠标点击获得焦点
        reason = event.reason()
        
        # 只有在非鼠标点击时才全选（如 Tab 键切换）
        if reason != QtCore.Qt.FocusReason.MouseFocusReason:
            ego.selectAll()

    def keyPressEvent(ego, event):
        """
        按键事件处理
        
        处理回车、上下箭头等特殊按键。
        """
        if hasattr(ego, 'code_view') and ego.code_view:
            controller = ego.code_view.controller
        else:
            controller = None

        if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
            if controller:
                current_text = ego.text()
                try:
                    controller.edit_assembly(current_text)
                    controller.commit_assembly()
                except Exception as e:
                    print(f"[Patching UI Error] 汇编错误：{e}")

            if hasattr(ego, 'code_view') and ego.code_view:
                lineno, x, y = ego.code_view.GetPos()
                max_lines = ego.code_view.Count()
                if lineno < max_lines - 1:
                    next_lineno = lineno + 1
                    ego.code_view.Jump(next_lineno, x, y)
                    ego.code_view.OnCursorPosChanged()
                    QtCore.QTimer.singleShot(0, lambda: ego._select_all_when_focused())
            event.accept()
            return

        elif event.key() == QtCore.Qt.Key_Down:
            if hasattr(ego, 'code_view') and ego.code_view:
                lineno, x, y = ego.code_view.GetPos()
                max_lines = ego.code_view.Count()
                if lineno < max_lines - 1:
                    ego.code_view.Jump(lineno + 1, x, y)
                    ego.code_view.OnCursorPosChanged()
                    QtCore.QTimer.singleShot(0, lambda: ego._select_all_when_focused())
            event.accept()
            return

        elif event.key() == QtCore.Qt.Key_Up:
            if hasattr(ego, 'code_view') and ego.code_view:
                lineno, x, y = ego.code_view.GetPos()
                if lineno > 0:
                    ego.code_view.Jump(lineno - 1, x, y)
                    ego.code_view.OnCursorPosChanged()
                    QtCore.QTimer.singleShot(0, lambda: ego._select_all_when_focused())
            event.accept()
            return

        super().keyPressEvent(event)

    def _select_all_when_focused(ego):
        """
        聚焦时全选文本
        """
        if ego.hasFocus():
            ego.selectAll()   

class BytesLineEdit(QtWidgets.QLineEdit):
    """
    自定义字节输入框
    
    继承自 QLineEdit，专为十六进制字节输入设计，具有自动格式化功能。
    """

    def __init__(ego, parent=None):
        """
        初始化字节输入框
        
        参数:
            parent: 父控件
        """
        super().__init__(parent)
        ego.setPlaceholderText("90 90 90 或 909090")  # 占位提示
        ego.setToolTip("输入十六进制字节，自动格式化为空格分隔")
        ego._updating = False  # 防止递归更新标志

    def focusInEvent(ego, event):
        """
        获得焦点时的事件处理
        
        仅在通过 Tab 键或程序化聚焦时全选，鼠标点击时保留点击位置。
        """
        super().focusInEvent(event)
        
        # 检查是否是通过鼠标点击获得焦点
        reason = event.reason()
        
        # 只有在非鼠标点击时才全选（如 Tab 键切换）
        if reason != QtCore.Qt.FocusReason.MouseFocusReason:ego.selectAll()

    def keyPressEvent(ego, event):
        """
        按键事件处理
        
        处理回车键提交，其他按键交给父类处理。
        """
        # 回车键提交更改
        if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
            # 接受输入，实际提交等待确定按钮
            print(f"[BytesLineEdit] Enter pressed, waiting for OK to commit")
            return
        
        # 其他按键正常处理
        super().keyPressEvent(event)

    def textChanged(ego, text):
        """
        文本变化事件处理
        
        自动格式化十六进制字符串。
        """
        # ARES 防止递归调用
        if ego._updating:
            return
        
        try:
            ego._updating = True
            
            # Ori 移除所有空格
            clean_text = text.replace(' ', '').replace('\t', '')
            
            # 只允许有效的十六进制字符
            valid_chars = '0123456789ABCDEFabcdef'
            filtered = ''.join(c for c in clean_text if c in valid_chars)
            
            # 每 2 个字符插入空格以提高可读性
            if len(filtered) > 2:
                formatted = ' '.join(filtered[i:i+2] for i in range(0, len(filtered), 2))
                # 仅在不同才更新以避免光标跳跃
                if formatted != text:
                    cursor_pos = ego.cursorPosition()
                    ego.setText(formatted)
                    # 尝试保持光标位置
                    ego.setCursorPosition(min(cursor_pos + 1, len(formatted)))
        finally:
            ego._updating = False


# ============================================================================
# IDA 代码查看器
# ============================================================================

class PatchingCodeViewer(ida_kernwin.simplecustviewer_t):
    """
    IDA 风格的代码查看器
    
    继承自 IDA 的 simplecustviewer_t，用于显示 IDA 风格的反汇编代码。
    支持语法高亮、光标导航、自定义渲染等。
    """

    def __init__(ego, controller):
        """
        初始化代码查看器
        
        参数:
            controller: 关联的控制器
        """
        super().__init__()
        ego.controller = controller
        ego._ui_hooks = UIHooks()  # UI 钩子，用于行渲染信息
        ego._ui_hooks.get_lines_rendering_info = ego._highlight_lines
        ego.Create()

    def Create(ego):
        """
        创建代码查看器
        
        返回值:
            成功返回 True，失败返回 False
        """
        if not super().Create('PatchingCodeViewer'):
            return False
        ego._twidget = ego.GetWidget()
        ego.widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(ego._twidget)
        ego._ui_hooks.hook()
        return True

    def OnClose(ego):
        """
        关闭代码查看器
        """
        ego._ui_hooks.unhook()
        ego._filter = None

    def OnCursorPosChanged(ego):
        """
        光标位置改变事件处理
        
        当用户在代码视图中移动光标时调用，更新控制器状态。
        """
        # 获取代码视图中当前选中的行
        view_line = ego.GetCurrentLine()
        view_lineno = ego.GetLineNo()
        view_address = parse_line_ea(view_line)

        # 从底层控制器/模型获取有关选中指令的信息
        insn, insn_lineno = ego.controller.get_insn_lineno(view_address)

        # 计算光标相对于同一地址行的索引
        relative_idx = view_lineno - insn_lineno

        # 通知控制器更新光标/选择
        ego.controller.select_address(view_address, relative_idx)

    def OnPopup(ego, form, popup_handle):
        """
        弹出菜单事件处理
        
        过滤 IDA 的默认动作。
        """
        #ego._filter = remove_ida_actions(popup_handle)
        return False

    def _highlight_lines(ego, out, widget, rin):
        """
        行高亮处理
        
        IDA 正在绘制反汇编行并请求高亮信息。
        
        参数:
            out: 输出高亮信息
            widget: 当前小部件
            rin: 渲染输入信息
        """
        # 如果事件不是针对当前代码视图，忽略
        if widget != ego._twidget:
            return

        selected_lnnum, x, y = ego.GetPos()

        # 高亮已被用户补丁的行
        assert len(rin.sections_lines) == 1
        for i, line in enumerate(rin.sections_lines[0]):
            splace = ida_kernwin.place_t_as_simpleline_place_t(line.at)
            line_info = ego.GetLine(splace.n)
            if not line_info:
                continue

            colored_text, _, _ = line_info
            address = parse_line_ea(colored_text)

            current_insn = ego.controller.get_insn(address)
            if not current_insn:
                continue

            # 将 (ea, size) 转换为代表指令中每个字节的完整地址
            insn_addresses = set(range(current_insn.address, current_insn.address + current_insn.size))

            # 绿色：选中行
            if splace.n == selected_lnnum:
                color = ida_kernwin.CK_EXTRA1

            # 红色：被覆盖的行
            elif current_insn.clobbered:
                color = ida_kernwin.CK_EXTRA11

            # 黄色：已补丁的行
            elif insn_addresses & ego.controller.core.patched_addresses:
                color = ida_kernwin.CK_EXTRA2

            # 无需高亮
            else:
                continue

            # 高亮行
            e = ida_kernwin.line_rendering_output_entry_t(line)
            e.bg_color = color
            e.flags = ida_kernwin.LROEF_FULL_LINE

            # 保存高亮到输出列表
            out.entries.push_back(e)