# TODO 未来用专业工具替代

def hexdump(data, wrap=0):
    """
    Return a spaced string of printed hex bytes for the given data.
    """
    wrap = wrap if wrap else len(data)
    if not data:
        return ''

    lines = []
    for i in range(0, len(data), wrap):
        lines.append(' '.join(['%02X' % x for x in data[i:i+wrap]]))

    return '\n'.join(lines)



def trim_trailing_zeros(data, is_utf16=False):
    """
    去除字节数据末尾的连续 00
    
    参数:
        data: 字节数据
        is_utf16: 是否为 UTF-16LE 模式（保留第一个 00）
    
    返回值:
        处理后的字节数据
    """
    if not data:
        return data
    
    # 去除末尾所有连续 00
    trimmed = data
    while len(trimmed) > 0 and trimmed[-1] == 0x00:
        trimmed = trimmed[:-1]
    
    # UTF-16LE 特殊处理：如果原始数据有末尾 00，保留一个
    if is_utf16 and len(data) > len(trimmed):
        trimmed = trimmed + b'\x00'
    
    return trimmed