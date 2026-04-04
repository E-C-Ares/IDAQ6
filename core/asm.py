# IDA imports
from.__deps_ import* 
from .parti  import *


TEST_KS_RESOLVER = False

class KeystoneAssembler(object):
    """
    An abstraction of a CPU-specific fixup layer to wrap Keystone.
    """

    # the mnemonic for an unconditional jump
    UNCONDITIONAL_JUMP = NotImplementedError

    # the list of known conditional jump mnemonics
    CONDITIONAL_JUMPS = []

    # a list of mnemonics that we KNOW are currently unsupported
    UNSUPPORTED_MNEMONICS = []

    # the number of instruction bytes to show in the patch preview pane
    MAX_PREVIEW_BYTES = 4

    #
    # NOTE: for now, we explicitly try to print operands using 'blank' type
    # info because it can produce simpler output for the assembler engine
    #
    # we initialize just one instance of this blank printop for performance
    # reasons, so we do not have to initialize a new one for *every* print.
    #
    # it is particularly useful when using the assemble_all(...) DEV / test
    # function to round-trip assemble an entire IDB
    #

    _NO_OP_TYPE = ida_nalt.printop_t()

    def __init__(ego, arch, mode):

        # Assert to ensure we're not using incomplete code
        assert ego.UNCONDITIONAL_JUMP != NotImplementedError, "Incomplete Assembler Implementation"

        # initialize a backing keystone assembler
        ego._arch = arch
        ego._mode = mode | (keystone.KS_OPT_SYM_RESOLVER if TEST_KS_RESOLVER else 0)
        ego._ks = keystone.Ks(arch, mode)

        # NOTE: the keystone sym resolver callback is only for DEV / testing
        # It's disabled by default as it can cause issues with symbol resolution
        if TEST_KS_RESOLVER:
            ego._ks.sym_resolver = ego._ks_sym_resolver

    def _ks_sym_resolver(ego, symbol, value):
        """
        NOTE: the keystone symbol resolver can be a bit goofy, so we opt not
        to use it (keypatch doesn't, either!) for now. it has been left here
        for future testing or further bugfixing of keystone

        This callback is beneficial for MULTI INSTRUCTION assembly,
        such as assembling a block of instructions (eg. shellcode, or a
        more complex patch) which makes use of labels within said block.
        
        However, due to reliability issues, it's disabled by default.
        """
        symbol = symbol.decode('utf-8')

        #
        # some symbols in IDA names / chars cannot pass cleanly through
        # keystone. for that reason, we try to replace some 'problematic'
        # characters that may appear in IDA symbols (and then disas text)
        #
        # when they pop back up here, in keystone's symbol resolver, we
        # try to subsitute the 'problematic' characters back in so that
        # we can look up the original symbol value in IDA
        #

        if 'AT_SPECIAL_AT' in symbol:
            symbol = symbol.replace('AT_SPECIAL_AT', '@')
        if 'QU_SPECIAL_QU' in symbol:
            symbol = symbol.replace('QU_SPECIAL_QU', '?')

        #
        # NOTE: symbol collision resolution is complex and not fully implemented.
        # In rare cases where multiple symbols match, we use the first match.
        # This approach works well for typical use cases.
        #

        for sym_value, sym_real_name in resolve_symbol(ego._ks_address, symbol):
            value[0] = sym_value
            return True

        # symbol resolution failed
        return False

    def rewrite_symbols(ego, assembly, ea):
        """
        Rewrite the symbols in the given assembly text to their concrete values.
        
        This method parses symbol names from assembly operands and replaces them
        with their resolved hexadecimal values for reliable assembly.
        """

        # Parse disassembly into mnemonic and operands
        mnem, sep, ops = assembly.partition(' ')

        # 'mnem' appears to be an instruction prefix actually, so keep parsing
        if mnem in KNOWN_PREFIXES:
            real_mnem, sep, ops = ops.partition(' ')
            mnem += ' ' + real_mnem

        #
        # scrape symbols from *just* the operands text, as that's the only
        # place we would expect to see them in assembly code anyway!
        #

        symbols = scrape_symbols(ops)

        #
        # if the symbol count is too high, it might take 'too long' to try
        # and resolve them all in a big database. At 10+ symbols, it is
        # probably just an invalid input to the assembler as is (at least,
        # for a single instruction ...)
        #

        if len(symbols) > 10:
            print("Aborting symbol re-writing, too (%u) many potential symbols..." % (len(symbols)))
            return assembly

        #
        # with a list of believed symbols and their text location, we will
        # try to resolve a value for each text symbol and swap a raw hex
        # number in to replace the symbol text
        #
        #   eg. 'mov    eax, [foo]' --> 'mov    eax, [0x410800]'
        #
        # where 'foo' was a symbol name entered by the user, but we can
        # query IDA to try and resolve (func address, data address, etc)
        #

        prev_index = 0
        new_ops = ''

        for name, location in symbols:
            sym_start, sym_end = location

            for sym_value, sym_real_name in resolve_symbol(ea, name):
                sym_value_text = '0x%X' % sym_value

                #
                # we are carefully carving around the original symbol text
                # to build out a new 'string' for the full operand text
                #

                new_ops += ops[prev_index:sym_start] + sym_value_text
                prev_index = sym_end

                #
                # NOTE: the case where resolve_symbol can return 'multiple'
                # results (eg, a symbol 'collision') is currently unhandled
                # but could happen in very rare cases
                #
                # By always breaking on the first iteration of this loop,
                # we're effectively always selecting the first symbol value
                # without any consideration of others. acceptable for
                # most use cases where symbol collisions are extremely rare.
                #

                break

            else:
                #print("%08X: Failed to resolve possible symbol '%s'" % (ea, name))
                continue

        new_ops += ops[prev_index:]
        raw_assembly = mnem + sep + new_ops

        #
        # return assembly text that has (ideally) had possible symbols
        # replaced with unambiguous values that are easy for the assembler
        # to consume
        #

        return raw_assembly

    def asm(ego, assembly, ea=0, resolve=True):
        """
        Assemble the given instruction with an optional base address.
        
        Args:
            assembly: Assembly instruction text
            ea: Base address for assembly
            resolve: Whether to resolve symbols in the assembly text
            
        Returns:
            Assembled instruction bytes
        """
        unaliased_assembly = ego.unalias(assembly)

        if TEST_KS_RESOLVER:
            raw_assembly = unaliased_assembly
            raw_assembly = raw_assembly.replace('@', 'AT_SPECIAL_AT')
            raw_assembly = raw_assembly.replace('?', 'QU_SPECIAL_QU')
            ego._ks_address = ea
        elif resolve:
            raw_assembly = ego.rewrite_symbols(unaliased_assembly, ea)
        else:
            raw_assembly = unaliased_assembly

        #print(" Assembling: '%s' @ ea 0x%08X" % (raw_assembly, ea))

        #
        # NOTE: Future improvement could involve surfacing more descriptive
        # error information from keystone on failures, as the current error
        # handling is minimal.
        #

        # try assemble
        try:
            asm_bytes, count = ego._ks.asm(raw_assembly, ea, True)
            if asm_bytes == None:
                return bytes()
        except Exception as e:
            #print("FAIL", e)
            return bytes()

        # return the generatied instruction bytes if keystone succeeded
        return asm_bytes

    def is_conditional_jump(ego, mnem):
        """
        Return True if the given mnemonic is a conditional jump.
        
        NOTE: IDA does have CPU agnostic APIs to determine if an instruction
        is a conditional jump, but manual definition provides more control
        and better compatibility across different IDA versions.
        """
        return bool(mnem.upper() in ego.CONDITIONAL_JUMPS)

    def is_thumb(ego, ea):
        """
        Return True if the given address is in THUMB mode.
        
        Default implementation returns False for non-ARM architectures.
        ARM-specific implementations should override this method.
        """
        return False

    def nop_buffer(ego, start_ea, end_ea):
        """
        Generate a NOP buffer for the given address range.
        
        NOTE: For ARM/THUMB, this method preserves instruction sizes to maintain
        IT block integrity. Mis-aligned ranges are handled by filling complete
        instructions only.
        """
        range_size = end_ea - start_ea
        if range_size < 0:
            return bytes()

        # the crafted buffer on NOP instructions to return
        nop_list = []

        #
        # with ARM, it is imperative we attempt to retain the size of the
        # instruction being NOP'd. this is to help account for cases such as
        # the ITTT blocks in THUMB
        #

        cur_ea = ida_bytes.get_item_head(start_ea)
        while cur_ea < end_ea:
            item_size = ida_bytes.get_item_size(cur_ea)

            # special handling to pick THUMB 2 / 4 byte NOP as applicable
            if ego.is_thumb(cur_ea):
                if item_size == 2:
                    nop_list.append(ego.__THUMB_NOP_2)
                else:
                    nop_list.append(ego.__THUMB_NOP_4)

            # NOP'ing a normal 4-byte ARM instruction
            else:
                nop_list.append(ego.__ARM_NOP_4)

            # continue to next instruction
            cur_ea += item_size

        # return a buffer of (NOP) instruction bytes
        return b''.join(nop_list)

    
    # Assembly Normalization
    

    def format_prefix(ego, insn, prefix):
        """
        Return an assembler compatible version of the given prefix.
        """
        return prefix

    def format_mnemonic(ego, insn, mnemonic):
        """
        Return an assembler compatible version of the given mnemonic.
        """
        return mnemonic

    def format_memory_op(ego, insn, n):
        """
        Return an assembler compatible version of the given memory op.
        """
        op_text = ida_ua.print_operand(insn.ea, n, 0, ego._NO_OP_TYPE)
        return op_text

    def format_imm_op(ego, insn, n):
        """
        Return an assembler compatible version of the given imm val op.
        """
        return ida_ua.print_operand(insn.ea, n)

    def format_assembly(ego, ea):
        """
        Return assembler compatible disassembly for the given address.

        This function re-implements the general instruction printing
        pipeline of the loaded processor module with custom fixups.
        """
        prefix, mnem, _ = get_disassembly_components(ea)

        if mnem is None:
            return ''

        #
        # decode the instruction just once so the CPU-specific layers can
        # read and use it to apply specific fixups when needed
        #

        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, ea)

        # this will accumulate the final fixed up text for all ops
        ops = []

        # this will hold the fixed up operand text for the current op
        op_text = ''

        #
        # generate the operand text for each op, with callbacks into the
        # processor specific fixups as necessary for each op type
        #

        for op in insn.ops:

            #
            # NOTE/PERF: these if/elif statements have been arranged based on
            # frequency (at least in x86/x64) for performance reasons
            #
            # be careful re-ordering them, as it may make assemble_all(...)
            # run twice as slow!!
            #

            if op.type in [ida_ua.o_reg, ida_ua.o_far, ida_ua.o_near]:
                op_text = ida_ua.print_operand(ea, op.n)

            # reached final operand in this instruction
            elif op.type == ida_ua.o_void:
                break

            #
            # NOTE: ideally we should allow users to toggle between 'pretty'
            # and 'raw' displacement / phrase ops, but there's keystone /
            # LLVM weirdness that causes bad assembly to be generated.
            #
            # Current workaround: generate asm without IDA's special offsetting
            # to avoid issues like:
            #   IDA: 'mov     [esp+6Ch+dest], esi'
            #   RAW: 'mov     [esp+6Ch+0xFFFFFF94], esi'
            #

            elif op.type in [ida_ua.o_displ, ida_ua.o_phrase]:
                op_text = ida_ua.print_operand(ea, op.n, 0, ego._NO_OP_TYPE)

            elif op.type == ida_ua.o_imm:
                op_text = ego.format_imm_op(insn, op.n)

            elif op.type == ida_ua.o_mem:
                op_text = ego.format_memory_op(insn, op.n)

            else:
                op_text = ida_ua.print_operand(ea, op.n)

            #
            # the operand is marked as invisible according to IDA,
            # so we shouldn't be showing / generating text for it anyway
            # (eg. Op4 for UMULH in ARM64)
            #

            if not(op.flags & ida_ua.OF_SHOW):
                continue

            ops.append(op_text)

        ops = list(map(ida_lines.tag_remove, filter(None, ops)))
        prefix = ego.format_prefix(insn, prefix)
        mnem = ego.format_mnemonic(insn, mnem)

        if prefix:
            mnem = prefix + ' ' + mnem

        # generate the fully disassembled instruction / text
        text = '%s %s' % (mnem.ljust(7, ' '), ', '.join(ops))

        # Clean up assembly text by removing verbose prefixes that keystone
        # doesn't need or handles differently
        for banned in ['[offset ', '(offset ', ' offset ', ' short ', ' near ptr ', ' far ptr ', ' large ']:
            text = text.replace(banned, banned[0])

        return text.strip()

    def unalias(ego, assembly):
        """
        Translate an instruction alias / shorthand to its full version.
        """
        return assembly


# x86 / x86_64

class AsmX86(KeystoneAssembler):
    """
    Intel x86 & x64 specific wrapper for Keystone.
    """

    UNCONDITIONAL_JUMP = 'JMP'
    CONDITIONAL_JUMPS = \
    [
        'JZ', 'JE', 'JNZ', 'JNE', 'JC', 'JNC',
        'JO', 'JNO', 'JS', 'JNS', 'JP', 'JPE',
        'JNP', 'JPO', 'JCXZ', 'JECXZ', 'JRCXZ',
        'JG', 'JNLE', 'JGE', 'JNL', 'JL', 'JNGE',
        'JLE', 'JNG', 'JA', 'JNBE', 'JAE', 'JNB',
        'JB', 'JNAE', 'JBE', 'JNA'
    ]

    UNSUPPORTED_MNEMONICS = \
    [
        # intel CET
        'ENDBR32', 'ENDBR64',
        'RDSSPD', 'RDSSPQ',
        'INCSSPD', 'INCSSPQ',
        'SAVEPREVSSP', 'RSTORSSP',
        'WRSSD', 'WRSSQ', 'WRUSSD', 'WRUSSQ',
        'SETSSBSY', 'CLRSSBSY',

        # misc
        'MONITOR', 'MWAIT', 'MONITORX', 'MWAITX',
        'INVPCID',

        # bugged?
        'REPE CMPSW',
    ]

    def __init__(ego):
        arch = keystone.KS_ARCH_X86

        if ida_ida.inf_is_64bit():
            mode = keystone.KS_MODE_64
            ego.MAX_PREVIEW_BYTES = 7
        elif ida_ida.inf_is_32bit_exactly():
            mode = keystone.KS_MODE_32
            ego.MAX_PREVIEW_BYTES = 6
        else:
            mode = keystone.KS_MODE_16

        # initialize keystone-based assembler
        super(AsmX86, ego).__init__(arch, mode)

    
    # Intel Assembly Formatting / Fixups
    

    def format_mnemonic(ego, insn, mnemonic):
        original = mnemonic.strip()

        # normalize the mnemonic case for fixup checking
        mnemonic = original.upper()

        if mnemonic == 'RETN':
            return 'ret'
        if mnemonic == 'XLAT':
            return 'xlatb'

        # no mnemonic fixups, return the original
        return original

    def format_memory_op(ego, insn, n):

        #
        # because IDA generates some 'non-standard' syntax in favor of human
        # readability, we have to fixup / re-print most memory operands to
        # reconcile them with what the assembler expects.
        #
        # (i'll go through later and document examples of each 'case' below)
        #

        op_text = super(AsmX86, ego).format_memory_op(insn, n)
        op_text = ida_lines.tag_remove(op_text)

        #
        # since this is a memory operation, we expect there to be a '[...]'
        # present in the operand text. if there isn't we should try to wrap
        # the appropriate parts of operand with square brackets
        #

        if '[' not in op_text:

            #
            # this case is to wrap segment:offset kind of prints:
            #
            # eg.
            #  - .text:00000001400AD89A 65 48 8B 04 25 58 00+        mov     rax, gs:58h
            #
            # NOTE: the secondary remaining[0] != ':' check is to avoid 'cpp'
            # cases, basically ensuring we are not modifying a '::'
            #
            # eg.
            #  - .text:000000014000A4F2 48 8D 05 EF 14 25 00         lea     rax, const QT::QSplitter::'vftable'
            #

            start, sep, remaining = op_text.partition(':')
            if sep and remaining[0] != ':':
                op_text = start + sep + '[' + remaining + ']'

            #
            # eg.
            #  - .text:08049F52 F6 05 A4 40 0F 08 02         test    byte ptr dword_80F40A4, 2
            #

            elif ' ptr ' in op_text:
                start, sep, remaining = op_text.partition(' ptr ')
                op_text = start + sep + '[' + remaining + ']'

            #
            # eg.
            #  - .text:000000014002F0C6 48 8D 0D 53 B9 E2 00         lea     rcx, unk_140E5AA20
            #

            else:
                op_text = '[' + op_text + ']'

        if ' ptr ' in op_text and ego._mode is keystone.KS_MODE_32:
            return op_text

        op = insn.ops[n]
        seg_reg = (op.specval & 0xFFFF0000) >> 16

        if seg_reg:
            #print("SEG REG: 0x%X 0x%X" % (op.specval & 0xFFFF, ((op.specval & 0xFFFF0000) >> 16)))
            seg_reg_name = ida_idp.ph.regnames[seg_reg]
            if seg_reg_name == 'cs':
                op_text = op_text.replace('cs:', '')
            elif seg_reg_name not in op_text:
                op_text = '%s:%s' % (seg_reg_name, op_text)

        if ' ptr ' in op_text:
            return op_text

        # Add type pointer for memory operations when not already present
        t_name = get_dtype_name(op.dtype, ida_ua.get_dtype_size(op.dtype))
        op_text = '%s ptr %s' % (t_name, op_text)

        return op_text

    def format_imm_op(ego, insn, n):
        op_text = super(AsmX86, ego).format_imm_op(insn, n)
        if '$+' in op_text:
            op_text = ida_ua.print_operand(insn.ea, n, 0, ego._NO_OP_TYPE)
        return op_text

    def nop_buffer(ego, start_ea, end_ea):
        """
        Generate a NOP buffer for the given address range.
        
        Default implementation generates x86-style NOP bytes (0x90).
        ARM-specific implementations should override this method.
        """
        range_size = end_ea - start_ea
        if range_size < 0:
            return bytes()
        
        # Default: generate x86-style NOP bytes (0x90)
        return b'\x90' * range_size

    def unalias(ego, assembly):

        # normalize spacing / capitalization
        parts = list(filter(None, assembly.lower().split(' ')))
        full = ' '.join(parts)
        if not full:
            return assembly

        #
        # IDA64 likes to print 'int 3' for 'CC', but keystone assembles this
        # to 'CD 03'... so we alias 'int 3' to 'int3' here instead which will
        # emit the preferred form 'CC'
        #

        if full == 'int 3':
            return 'int3'

        #
        # NOTE: keystone doesn't know about 'movsd' (string instruction),
        # so we correct it here by expanding it to explicit memory operands.
        # This handles both 'movsd' and 'rep* movsd' cases.
        #

        if parts[-1] == 'movsd':

            if ego._mode & keystone.KS_MODE_64:
                regs = ('rdi', 'rsi')
            else:
                 regs = ('edi', 'esi')

            # preserves prefix ... if there was one
            return assembly + ' dword ptr [%s], dword ptr [%s]' % regs

        # no special aliasing / fixups
        return assembly


# ARM / ARM64

class AsmARM(KeystoneAssembler):
    """
    ARM specific wrapper for Keystone.
    """

    UNCONDITIONAL_JUMP = 'B'
    CONDITIONAL_JUMPS = \
    [
        # ARM
        'BEQ', 'BNE', 'BCC', 'BCS', 'BVC', 'BVS',
        'BMI', 'BPL', 'BHS', 'BLO', 'BHI', 'BLS',
        'BGE', 'BLT', 'BGT', 'BLE',

        # ARM64
        'B.EQ', 'B.NE', 'B.CS', 'B.CC', 'B.MI', 'B.PL',
        'B.VS', 'B.VC', 'B.HI', 'B.LS', 'B.GE', 'B.LT',
        'B.GT', 'B.LE', 'CBNZ', 'CBZ', 'TBZ', 'TBNZ'
    ]

    UNSUPPORTED_MNEMONICS = \
    [
        'ADR', 'ADRL',

        # Pointer Authentication
        'AUTDA', 'AUTDZA', 'AUTDB', 'AUTDZB',
        'AUTIA', 'AUTIA1716', 'AUTIASP', 'AUTIAZ', 'AUTIZA',
        'AUTIB', 'AUTIB1716', 'AUTIBSP', 'AUTIBZ', 'AUTIZB',

        'BLRAA', 'BLRAAZ', 'BLRAB', 'BLRABZ',
        'BRAA',  'BRAAZ', 'BRAB', 'BRABZ',

        'PACDA', 'PACDZA', 'PACDB', 'PACDZB', 'PACGA',
        'PACIA', 'PACIA1716', 'PACIASP', 'PACIAZ', 'PACIZA',
        'PACIB', 'PACIB1716', 'PACIBSP', 'PACIBZ', 'PACIZB',
        'RETAA', 'RETAB',

        'XPACD', 'XPACI', 'XPACLRI'

        # NOTE: MRS and MOV (32/64 bit) semi-support could be added in future
    ]

    def __init__(ego):

        # ARM64
        if ida_ida.inf_is_64bit():
            arch = keystone.KS_ARCH_ARM64

            if ida_ida.inf_is_be():
                mode = keystone.KS_MODE_BIG_ENDIAN
            else:
                mode = keystone.KS_MODE_LITTLE_ENDIAN

            # AArch64 does not use THUMB
            ego._ks_thumb = None

        # ARM
        else:
            arch = keystone.KS_ARCH_ARM

            if ida_ida.inf_is_be():
                mode = keystone.KS_MODE_ARM | keystone.KS_MODE_BIG_ENDIAN
                ego._ks_thumb = keystone.Ks(arch, keystone.KS_MODE_THUMB | keystone.KS_MODE_BIG_ENDIAN)
            else:
                mode = keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN
                ego._ks_thumb = keystone.Ks(arch, keystone.KS_MODE_THUMB | keystone.KS_MODE_LITTLE_ENDIAN)

        # initialize keystone-based assembler
        super(AsmARM, ego).__init__(arch, mode)

        # pre-assemble for later, repeated use
        ego.__ARM_NOP_4, _ = ego._ks.asm('NOP', as_bytes=True)
        if ego._ks_thumb:
            ego.__THUMB_NOP_2, _ = ego._ks_thumb.asm('NOP', as_bytes=True)
            ego.__THUMB_NOP_4, _ = ego._ks_thumb.asm('NOP.W', as_bytes=True)

    def asm(ego, assembly, ea=0, resolve=True):

        # swap engines when trying to assemble to a THUMB region
        if ego.is_thumb(ea):
            ks = ego._ks
            ego._ks = ego._ks_thumb
            data = super(AsmARM, ego).asm(assembly, ea, resolve)
            ego._ks = ks
            return data

        # assemble as ARM
        return super(AsmARM, ego).asm(assembly, ea, resolve)

    @staticmethod
    def is_thumb(ea):
        """
        Return True if the given address is marked as THUMB.
        """
        return bool(ida_segregs.get_sreg(ea, ida_idp.str2reg('T')) == 1)

    def nop_buffer(ego, start_ea, end_ea):
        """
        Generate a NOP buffer for the given address range.
        
        For ARM/THUMB, this method preserves instruction sizes to maintain
        IT block integrity. Mis-aligned ranges are handled by filling complete
        instructions only.
        """
        range_size = end_ea - start_ea
        if range_size < 0:
            return bytes()

        # the crafted buffer on NOP instructions to return
        nop_list = []

        cur_ea = ida_bytes.get_item_head(start_ea)
        while cur_ea < end_ea:
            item_size = ida_bytes.get_item_size(cur_ea)

            # special handling to pick THUMB 2 / 4 byte NOP as applicable
            if ego.is_thumb(cur_ea):
                if item_size == 2:
                    nop_list.append(ego.__THUMB_NOP_2)
                else:
                    nop_list.append(ego.__THUMB_NOP_4)

            # NOP'ing a normal 4-byte ARM instruction
            else:
                nop_list.append(ego.__ARM_NOP_4)

            # continue to next instruction
            cur_ea += item_size

        # return a buffer of (NOP) instruction bytes
        return b''.join(nop_list)

    
    # ARM Assembly Formatting / Fixups
    

    def format_memory_op(ego, insn, n):
        op = insn.ops[n]

        # ARM / ARM64
        if ida_idp.ph.regnames[op.reg] == 'PC':
            offset = (op.addr - insn.ea) - 8
            op_text = '[PC, #%s0x%X]' % ('-' if offset < 0 else '', abs(offset))
            return op_text

        elif ego.is_thumb(insn.ea):
            offset = (op.addr - insn.ea) - 4 + (insn.ea % 4)
            op_text = '[PC, #%s0x%X]' % ('-' if offset < 0 else '', abs(offset))
            return op_text

        op_text = ida_lines.tag_remove(super(AsmARM, ego).format_memory_op(insn, n))

        if op_text[0] == '=':
            op_text = '#0x%X' % op.addr

        return op_text

    def format_imm_op(ego, insn, n):
        """
        Format immediate operand for ARM assembly.
        
        Uses blank printop type to generate simpler output compatible with keystone.
        """
        op_text = ida_ua.print_operand(insn.ea, n, 0, ego._NO_OP_TYPE)
        return op_text

    def unalias(ego, assembly):
        prefix, mnemonic, ops = parse_disassembly_components(assembly)

        # IDA seems to prefer showing 'STMFA', but keystone expects 'STMIB'
        if mnemonic.upper() == 'STMFA':
            return ' '.join([prefix, 'STMIB', ops])

        return assembly


# PPC / PPC64

class AsmPPC(KeystoneAssembler):
    """
    PowerPC specific wrapper for Keystone.
    
    NOTE: Keystone PPC support is limited. Big Endian mode is the default
    and Little Endian mode may not be fully supported by Keystone engine.
    """

    UNCONDITIONAL_JUMP = 'B'
    CONDITIONAL_JUMPS = [
        'BEQ', 'BNE', 'BC', 'BNC', 'BLT', 'BGT', 'BLE', 'BGE',
        'BDNZ', 'BDZ', 'Bdnz', 'Bdz'
    ]

    UNSUPPORTED_MNEMONICS = [
        # PowerPC Book-E instructions (embedded)
        'MSYNC', 'SYNC',
        'ISYNC', 'DSYNC',
        'TLBSYNC', 'TLBWE', 'TLBRE', 'TLBIVAX',
        
        # Altivec/VMX instructions (may have limited support)
        'VADDUBM', 'VADDUHM', 'VADDUWM',
        'VSUBUBM', 'VSUBUHM', 'VSUBUWM',
    ]

    def __init__(ego):
        arch = keystone.KS_ARCH_PPC

        if ida_ida.inf_is_64bit():
            mode = keystone.KS_MODE_PPC64
            ego.MAX_PREVIEW_BYTES = 8
        else:
            mode = keystone.KS_MODE_PPC32
            ego.MAX_PREVIEW_BYTES = 4

        # NOTE: Keystone PPC primarily supports Big Endian mode
        # Little Endian support is limited/experimental
        if ida_ida.inf_is_be():
            mode |= keystone.KS_MODE_BIG_ENDIAN
        # else: Little Endian mode (experimental)

        # initialize keystone-based assembler
        super(AsmPPC, ego).__init__(arch, mode)

    def format_mnemonic(ego, insn, mnemonic):
        """
        Return an assembler compatible version of the given mnemonic.
        """
        original = mnemonic.strip()
        mnemonic = original.upper()

        # PPC mnemonic fixups can be added here as needed
        # For now, return as-is since Keystone generally handles PPC mnemonics well
        
        return original

    def format_memory_op(ego, insn, n):
        """
        Return an assembler compatible version of the given memory op.
        
        PPC memory operands typically use d(r) or r formats for load/store instructions.
        """
        op_text = super(AsmPPC, ego).format_memory_op(insn, n)
        op_text = ida_lines.tag_remove(op_text)

        # PPC uses d(r) format for displacement
        # IDA may print it differently, so we might need to adjust
        # For now, return as formatted by IDA
        
        return op_text

    def unalias(ego, assembly):
        """
        Translate an instruction alias / shorthand to its full version.
        """
        # normalize spacing / capitalization
        parts = list(filter(None, assembly.lower().split(' ')))
        full = ' '.join(parts)
        if not full:
            return assembly

        # PPC-specific aliases can be handled here
        # For example, some assemblers accept 'blr' but keystone might want 'blr'
        
        return assembly


# MIPS / MIPS64

class AsmMIPS(KeystoneAssembler):
    """
    MIPS specific wrapper for Keystone.
    
    Supports both MIPS32 and MIPS64 architectures in Big or Little Endian modes.
    """

    UNCONDITIONAL_JUMP = 'J'
    CONDITIONAL_JUMPS = [
        'BEQ', 'BNE', 'BEQZ', 'BNEZ',
        'BLTZ', 'BGTZ', 'BLEZ', 'BGEZ',
        'BLTZAL', 'BGEZAL',
        'BC1T', 'BC1F', 'BC1FL', 'BC1TL'
    ]

    UNSUPPORTED_MNEMONICS = [
        # MIPS DSP instructions (limited Keystone support)
        'ADDQH', 'SUBQH', 'MULTQH',
        'ABSQ_S', 'PRECRQ', 'PRECRQU',
        
        # MIPS SIMD Architecture (MSA) instructions
        'ADDV', 'SUBV', 'MULV',
    ]

    def __init__(ego):
        arch = keystone.KS_ARCH_MIPS

        if ida_ida.inf_is_64bit():
            mode = keystone.KS_MODE_MIPS64
            ego.MAX_PREVIEW_BYTES = 8
        else:
            mode = keystone.KS_MODE_MIPS32
            ego.MAX_PREVIEW_BYTES = 4

        if ida_ida.inf_is_be():
            mode |= keystone.KS_MODE_BIG_ENDIAN
        else:
            mode |= keystone.KS_MODE_LITTLE_ENDIAN

        # initialize keystone-based assembler
        super(AsmMIPS, ego).__init__(arch, mode)

    def format_mnemonic(ego, insn, mnemonic):
        """
        Return an assembler compatible version of the given mnemonic.
        """
        original = mnemonic.strip()
        mnemonic = original.upper()

        # MIPS delay slot handling - IDA may show branch instructions
        # with special annotations that keystone doesn't need
        
        return original

    def format_memory_op(ego, insn, n):
        """
        Return an assembler compatible version of the given memory op.
        
        MIPS uses offset(base) format for load/store instructions.
        """
        op_text = super(AsmMIPS, ego).format_memory_op(insn, n)
        op_text = ida_lines.tag_remove(op_text)

        # MIPS memory operands are typically in format: offset(base)
        # e.g., '0x10($sp)' or '-8($fp)'
        
        return op_text

    def unalias(ego, assembly):
        """
        Translate an instruction alias / shorthand to its full version.
        """
        # normalize spacing / capitalization
        parts = list(filter(None, assembly.lower().split(' ')))
        full = ' '.join(parts)
        if not full:
            return assembly

        # Handle common MIPS aliases
        # e.g., 'move' is often an alias for 'addu' or 'or'
        # but keystone may prefer the base instruction
        
        return assembly


# SPARC / SPARC64

class AsmSPARC(KeystoneAssembler):
    """
    SPARC specific wrapper for Keystone.
    
    Supports both SPARC V8 (32-bit) and SPARC V9 (64-bit) architectures.
    """

    UNCONDITIONAL_JUMP = 'BA'
    CONDITIONAL_JUMPS = [
        'BE', 'BNE', 'BG', 'BLE', 'BL', 'BGE',
        'BLEU', 'BGU', 'BLU', 'BGEU',
        'BCOND', 'BSCOND'
    ]

    UNSUPPORTED_MNEMONICS = [
        # SPARC VIS (Visual Instruction Set) instructions
        'FPMERGE', 'FPADD', 'FPSUB', 'FPMUL',
        'ARRAY8', 'ARRAY16', 'ARRAY32',
        
        # SPARC HPC (High Performance Computing) instructions
        'EDGE*', 'PDIST', 'FAND', 'FNAND',
    ]

    def __init__(ego):
        arch = keystone.KS_ARCH_SPARC

        if ida_ida.inf_is_64bit():
            mode = keystone.KS_MODE_SPARC64
            ego.MAX_PREVIEW_BYTES = 8
        else:
            mode = keystone.KS_MODE_SPARC32
            ego.MAX_PREVIEW_BYTES = 4

        if ida_ida.inf_is_be():
            mode |= keystone.KS_MODE_BIG_ENDIAN
        else:
            mode |= keystone.KS_MODE_LITTLE_ENDIAN

        # initialize keystone-based assembler
        super(AsmSPARC, ego).__init__(arch, mode)

    def format_mnemonic(ego, insn, mnemonic):
        """
        Return an assembler compatible version of the given mnemonic.
        """
        original = mnemonic.strip()
        mnemonic = original.upper()

        # SPARC has many condition codes and annulled branches
        # Annotations like ',a' (annulled) should be preserved
        
        return original

    def format_memory_op(ego, insn, n):
        """
        Return an assembler compatible version of the given memory op.
        
        SPARC uses various addressing modes including:
        - [reg1+reg2]
        - [reg+imm]
        """
        op_text = super(AsmSPARC, ego).format_memory_op(insn, n)
        op_text = ida_lines.tag_remove(op_text)

        # SPARC memory operands are typically in bracket notation
        # IDA's format should generally be compatible with keystone
        
        return op_text

    def unalias(ego, assembly):
        """
        Translate an instruction alias / shorthand to its full version.
        """
        # normalize spacing / capitalization
        parts = list(filter(None, assembly.lower().split(' ')))
        full = ' '.join(parts)
        if not full:
            return assembly

        # SPARC has many synthetic instructions (aliases)
        # Most should work fine with keystone as-is
        
        return assembly


# System-Z (s390x)

class AsmSystemZ(KeystoneAssembler):
    """
    IBM SystemZ (s390x) specific wrapper for Keystone.
    
    Big Endian only architecture used in IBM mainframes.
    """

    UNCONDITIONAL_JUMP = 'BR'
    CONDITIONAL_JUMPS = [
        'BE', 'BNE', 'BH', 'BL', 'BHE', 'BLE',
        'BHR', 'BLR', 'BER', 'BNR', 'BHER', 'BLER'
    ]

    UNSUPPORTED_MNEMONICS = [
        # Decimal arithmetic instructions
        'AP', 'SP', 'MP', 'DP', 'SRP',
        'ZAP', 'PACK', 'UNPK', 'CVB', 'CVD',
        
        # Control instructions (privileged)
        'LCTL', 'STCTL', 'LCTLG', 'STCTLG',
        'DIAG', 'SIGP', 'IPL',
    ]

    def __init__(ego):
        # SystemZ is always big endian
        super(AsmSystemZ, ego).__init__(
            keystone.KS_ARCH_SYSTEMZ, 
            keystone.KS_MODE_BIG_ENDIAN
        )
        ego.MAX_PREVIEW_BYTES = 6

    def format_mnemonic(ego, insn, mnemonic):
        """
        Return an assembler compatible version of the given mnemonic.
        """
        original = mnemonic.strip()
        
        # SystemZ mnemonics are generally standardized
        # No special fixups needed in most cases
        
        return original

    def format_memory_op(ego, insn, n):
        """
        Return an assembler compatible version of the given memory op.
        
        SystemZ uses various addressing modes:
        - D(X,B) - Displacement with index and base
        - L - Literal pool reference
        - V - Vector register
        """
        op_text = super(AsmSystemZ, ego).format_memory_op(insn, n)
        op_text = ida_lines.tag_remove(op_text)

        # SystemZ memory operands use D(X,B) format
        # e.g., '0(15,13)' means displacement 0, index reg 15, base reg 13
        
        return op_text

    def unalias(ego, assembly):
        """
        Translate an instruction alias / shorthand to its full version.
        """
        # normalize spacing / capitalization
        parts = list(filter(None, assembly.lower().split(' ')))
        full = ' '.join(parts)
        if not full:
            return assembly

        # SystemZ has some extended mnemonics that are aliases
        # Keystone should handle standard SystemZ instructions
        
        return assembly