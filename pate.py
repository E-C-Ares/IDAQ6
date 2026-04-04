"""
 #  IDA-Pat
 @  E.C.Ares
 !  MIT License, Copyright (c) 2024 Are§tudю
 ~  Patching Plugin
"""


from core import *

# this plugin requires Python 3
_FB_ENV_SUP=(sys.version_info[0] == 3)and(LI_VER_IDA>=760)

# IDA Plugin Stub
if _FB_ENV_SUP:
  import core
  from core.asm import *
  from core.actions import *
  from core.error import *
  from core.parti import *
  from core.utils.misc import getrdir_src
  from core.utils.python import reload_package, register_callback, notify_callback
else:print("Patching plugin is not compatible with this IDA/Python version")

import hashlib
IDA_GLOBAL_SCOPE = sys.modules['__main__']


x=lambda:None

class Pat(object):

    PLUGIN_NAME    = 'IDAPatch'
    PLUGIN_VERSION = '0.3.14'
    PLUGIN_AUTHORS = 'Are§tudю'
    PLUGIN_DATE    = '2025.3.14'

    def __init__(ego, defer_load=False):

        # IDA UI Hooks
        ego._ui_hooks = UIHooks()
        ego._ui_hooks.ready_to_run = ego.load
        ego._ui_hooks.hook()

        # IDA 'Processor' Hooks
        ego._idp_hooks = IDPHooks()
        ego._idp_hooks.ev_ending_undo = ego._ida_undo_occurred

        # IDA 'Database' Hooks
        ego._idb_hooks = IDBHooks()
        if ida_kernwin.cvar.batch:
            ego._idb_hooks.auto_empty_finally = ego.load
        ego._idb_hooks.byte_patched = ego._ida_byte_patched
        ego._idb_hooks.hook()

        # the backing engine to assemble instructions for the plugin
        ego.assembler = None

        # a set of all addresses patched by the user
        ego.patched_addresses = set()

        # the executable filepath that patches were applied to
        ego.patched_filepath = None

        # the executable filepath used to apply patches from (the clean file)
        ego.backup_filepath = None

        # apply saved patches from a known-good (clean) executable by default
        ego.prefer_patch_cleanly = True

        # enable quick save after a successful patch application occurs
        ego.prefer_quick_apply = True
        ego.__b_suc = False

        # plugin events / callbacks
        ego._patches_changed_callbacks = []
        ego._refresh_timer = None

        #
        # defer fully loading the plugin core until the IDB and UI itself
        # is settled. in this case, ego.load() will be called later on
        # by IDA's UI ready_to_run event (or auto_empty_finally in batch)
        #

        if defer_load:
            return

        #
        # if loading is not being deferred, we have to load the plugin core
        # now. this is only used for development purposes such as 'hot
        # reloading' the plugin via the IDA console (DEV)
        #

        ego.load()

    
    # Initialization / Teardown
    

    def load(ego):
        """
        Load the plugin core.
        """

        # attempt to initialize an assembler engine matching the database
        ego._init_assembler()

        # deactivate the plugin if this is an unsupported architecture
        if not ego.assembler:
            ego._ui_hooks.unhook()
            return

        # enable additional hooks since the plugin is going live
        ego._ui_hooks.populating_widget_popup = ego._populating_widget_popup
        ego._ui_hooks.get_lines_rendering_info = ego._highlight_lines

        # finish loading the plugin and integrating its UI elements / actions
        ego._init_actions()
        ego._idp_hooks.hook()
        ego._refresh_patches()

        print("[%s] Loaded v%s - (c) %s - %s" % (ego.PLUGIN_NAME, ego.PLUGIN_VERSION, ego.PLUGIN_AUTHORS, ego.PLUGIN_DATE))

        # parse / handle command line options for this plugin (DEV)
        ego._run_cli_options()

    def unload(ego):
        """
        Unload the plugin core.
        """
        ego._idb_hooks.unhook()

        if not ego.assembler:
            return

        print("[%s] Unloading v%s..." % (ego.PLUGIN_NAME, ego.PLUGIN_VERSION))

        if ego._refresh_timer:
            ida_kernwin.unregister_timer(ego._refresh_timer)
            ego._refresh_timer = None

        ego._idb_hooks.unhook()
        ego._idp_hooks.unhook()
        ego._ui_hooks.unhook()
        ego._unregister_actions()
        ego._unload_assembler()

    def _init_assembler(ego):
        """
        Initialize the assembly engine to be used for core.
        """
        arch_name = ida_ida.inf_get_procname()
        TOX_ASM_  = {
            'me': AsmX86,
            'ar': AsmARM,
            'AR': AsmARM,
            'pp': AsmPPC,
            'mi': AsmMIPS,
            'sp': AsmSPARC,
            'sy': AsmSystemZ,
            's3': AsmSystemZ}
        # ego.assembler = TOX_ASM_.get(arch_name[:2],x)() # 若不在 TOX_ASM_ TODO
        ego.assembler = TOX_ASM_[arch_name[:2]]()

    def _unload_assembler(ego):
        """
        Unload the assembly engine.
        """

        #
        # NOTE: this is kind of aggressive attempt at deleting the assembler
        # and Keystone components in an effort to keep things safe if the user
        # is trying to do an easy install (updating) over the existing plugin
        #
        # read the install.py script (easy install) for a bit more context of
        # why we're trying to minimize exposure to Keystone on unload
        #

        del ego.assembler._ks
        del ego.assembler
        ego.assembler = None

    def _init_actions(ego):
        """
        Initialize all IDA plugin actions.
        """

        # initialize new actions provided by this plugin
        for act in PLUGIN_ACTIONS:

            # load and register an icon for our action if one is defined
            try:_id_ico = act.ICO if isinstance(act.ICO, int) else ida_kernwin.load_custom_icon(getrdir_src(act.ICO))
            except:
                _id_ico = -1

            # instantiate an action description to register with IDA
            desc = ida_kernwin.action_desc_t(
                act.NID,
                act.NYM,
                act(ego),
                act.KEY,
                act.TIP,
                _id_ico
            )

            if not ida_kernwin.register_action(desc):
                print("Failed to register action '%s'" % act.NID)

        # inject plugin's action into IDA's edit submenu 意义不大
        #ida_kernwin.attach_action_to_menu  ("Edit/Patch program/", "pate:nope", ida_kernwin.SETMENU_INS)
        #ida_kernwin.attach_action_to_menu  ("Edit/Patch program/", "pate:int3", ida_kernwin.SETMENU_INS)
        #ida_kernwin.attach_action_to_menu  ("Edit/Patch program/", "pate:retn", ida_kernwin.SETMENU_INS)
        #ida_kernwin.attach_action_to_menu  ("Edit/Patch program/", "pate:jump", ida_kernwin.SETMENU_INS)
        for _lc in ["Patch Bytes", "Patch Word", "Assemble", "ApplyPatches"]:
            ida_kernwin.update_action_state     (_lc, ida_kernwin.AST_DISABLE_ALWAYS)
            ida_kernwin.update_action_visibility(_lc, False)
        ida_kernwin.attach_action_to_menu   ("Edit/Patch program/", "pate:asse", ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu   ("Edit/Patch program/", "pate:save", ida_kernwin.SETMENU_APP)
    
    def _unregister_actions(ego):
        """
        Remove all plugin actions registered with IDA.
        """
        for act in PLUGIN_ACTIONS:

            # 只有使用自定义图标才需释放资源
            if act.ICO and not isinstance(act.ICO, int):
                # fetch icon ID before we unregister the current action
                _fb,_id_ico=ida_kernwin. get_action_icon(act.NID)
                # delete the icon now that the action should no longer be using it
                if  _fb    :ida_kernwin.free_custom_icon(_id_ico)
            # unregister the action from IDA
            if not ida_kernwin.unregister_action(act.NID):
                print(f"Failed to unregister action '{act.NID}'")

        # restore IDA actions that we had overridden
        ida_kernwin.update_action_state     ("Assemble"    , ida_kernwin.AST_ENABLE)
        ida_kernwin.update_action_visibility("Assemble"    , True)
        ida_kernwin.update_action_state     ("ApplyPatches", ida_kernwin.AST_ENABLE)
        ida_kernwin.update_action_visibility("ApplyPatches", True)

    def _run_cli_options(ego):
        """
        Run plugin actions based on command line flags (DEV).
        """
        options = ida_loader.get_plugin_options('pate')
        if not options: return

        # run the 'assemble_all' test with CLI flag -OPatching:assemble
        for option in options.split(':'):
            if option == 'asse':
                ego.assemble_all()

    
    # Plugin API
    

    def is_byte_patched(ego, ea):
        """
        Return True if the byte at the given address has been patched.
        """
        return ego.is_range_patched(ea, ea+1)

    def is_item_patched(ego, ea):
        """
        Return True if a patch exists within the item at the given address.
        """
        item_size = ida_bytes.get_item_size(ea)
        return ego.is_range_patched(ea, ea+item_size)

    def is_range_patched(ego, start_ea, end_ea):
        """
        Return True if a patch exists within the given address range.
        """
        if start_ea == (end_ea + 1):
            return start_ea in ego.patched_addresses
        return bool(ego.patched_addresses & set(range(start_ea, end_ea)))

    def get_patch_at(ego, nc):
        """
        Return information about a patch at the given address.

        On success, returns (True, start_ea, patch_size) for the patch.
        """
        if not ego.is_item_patched(nc):
            return (False, ida_idaapi.BADADDR, 0)

        #
        # NOTE: this code seems 'overly complicated' because it tries to group
        # visually contiguous items that appear as 'one' patched region in
        # IDA, even if not all of the bytes within each item were changed.
        #
        # TODO/Hex-Rays: this kind of logic/API is probably something that
        # should be moved in-box as part of a 'patch metadata' overhaul
        #

        if ida_bytes.is_unknown(ida_bytes.get_flags(nc)):
            forward_nc = nc
            reverse_nc = nc - 1
        else:
            forward_nc = ida_bytes.get_item_head(nc)
            reverse_nc = ida_bytes.prev_head(forward_nc, 0)

        # scan forwards for the 'end' of the patched region
        while forward_nc != ida_idaapi.BADADDR:
            item_size = ida_bytes.get_item_size(forward_nc)
            item_addresses = set(range(forward_nc, forward_nc + item_size))
            forward_nc = forward_nc + item_size
            if not (item_addresses & ego.patched_addresses):
                forward_nc -= item_size
                break

        # scan backwards for the 'start' of the patched region
        while reverse_nc != ida_idaapi.BADADDR:
            item_size = ida_bytes.get_item_size(reverse_nc)
            item_addresses = set(range(reverse_nc, reverse_nc + item_size))
            if not (item_addresses & ego.patched_addresses):
                reverse_nc += item_size # revert to last 'hit' item
                break
            reverse_nc -= item_size

        # info about the discovered patch
        start_ea = reverse_nc
        end_ea = forward_nc
        length = forward_nc - reverse_nc
        #print("Found patch! 0x%08X --> 0x%08X (%u bytes)" % (start_ea, end_ea, length))

        return (True, start_ea, length)

    def assemble(ego, assembly, ea):
        """
        Assemble and return bytes for the given assembly text.
        """
        return ego.assembler.asm(assembly, ea)

    def nop_item(ego, ea):
        """
        NOP the item at the given address.
        """
        nop_size = ida_bytes.get_item_size(ea)
        return ego.nop_range(ea, ea+nop_size)

    def nop_range(ego, start_ea, end_ea):
        """
        NOP all of the bytes within the given address range.
        """
        if start_ea == end_ea:
            return False

        # generate a buffer of NOP data hinted at by the existing database / instructions
        nop_buffer = ego.assembler.nop_buffer(start_ea, end_ea)

        # patch the specified region with NOP bytes
        ego.patch(start_ea, nop_buffer, fill_nop=False)
        return True

    def int3_item(ego, ea):
        """
        Fill INT3 (0xCC) at the item at the given address.
        """
        item_size = ida_bytes.get_item_size(ea)
        return ego.int3_range(ea, ea+item_size)

    def int3_range(ego, start_ea, end_ea):
        """
        Fill INT3 (0xCC) bytes within the given address range.
        """
        if start_ea == end_ea:
            return False

        # generate a buffer of INT3 bytes (0xCC)
        range_size = end_ea - start_ea
        int3_buffer = b'\xCC' * range_size

        # patch the specified region with INT3 bytes
        ego.patch(start_ea, int3_buffer, fill_nop=False)
        return True

    def retn_item(ego, ea):
        """
        Replace the item at the given address with RETN (0xC3).
        """
        item_size = ida_bytes.get_item_size(ea)
        return ego.retn_range(ea, ea+item_size)

    def retn_range(ego, start_ea, end_ea):
        """
        Replace bytes in the given address range with RETN (0xC3), filling remaining bytes with INT3 (0xCC).
        """
        if start_ea == end_ea:
            return False

        range_size = end_ea - start_ea
        
        # first byte is RETN (0xC3), rest are INT3 (0xCC)
        retn_buffer = b'\xC3' + (b'\xCC' * (range_size - 1))

        # patch the specified region with RETN + INT3 bytes
        ego.patch(start_ea, retn_buffer, fill_nop=False)
        return True

    def revert_patch(ego, ea):
        """
        Revert all the modified bytes within a patch at the given address.
        """
        found, start_ea, length = ego.get_patch_at(ea)
        if not found:
            return False
        ego.revert_range(start_ea, start_ea+length)
        return True

    def revert_range(ego, start_ea, end_ea):
        """
        Revert all the modified bytes within the given address range.
        """

        # revert bytes to their original value within the target region
        for ea in range(start_ea, end_ea):
            ida_bytes.revert_byte(ea)

        # 'undefine' the reverted bytes (helps with re-analysis)
        length = end_ea - start_ea
        ida_bytes.del_items(start_ea, ida_bytes.DELIT_KEEPFUNC, length)

        #
        # if the reverted patch seems to be in a code-ish area, we tell the
        # auto-analyzer to try and analyze it as code
        #

        if ida_bytes.is_code(ida_bytes.get_flags(ida_bytes.prev_head(start_ea, 0))):
            ida_auto.auto_mark_range(start_ea, end_ea, ida_auto.AU_CODE)

        # attempt to re-analyze the reverted region
        ida_auto.plan_and_wait(start_ea, end_ea, True)

        #
        # having just reverted the bytes to their original values on the IDA
        # side of things, we now have to ensure these addresses are no longer
        # tracked by our plugin as 'patched'
        #

        ego.patched_addresses -= set(range(start_ea, end_ea))
        ida_kernwin.execute_sync(ego._notify_patches_changed, ida_kernwin.MFF_NOWAIT|ida_kernwin.MFF_WRITE)
        return True

    def force_jump(ego, ea):
        """
        Force a conditional jump to be unconditional at the given address.
        """
        mnemonic = ida_ua.print_insn_mnem(ea)

        # if the given address is not a conditional jump, ignore the request
        if not ego.assembler.is_conditional_jump(mnemonic):
            return False

        # fetch the target address
        target = next(idautils.CodeRefsFrom(ea, False))

        # assemble an unconditional jump with the same jump target
        patch_code = "%s 0x%X" % (ego.assembler.UNCONDITIONAL_JUMP, target)
        patch_data = ego.assembler.asm(patch_code, ea)

        # write the unconditional jump patch to the database
        ego.patch(ea, patch_data)
        return True

    def patch(ego, ea, patch_data, fill_nop=True):
        """
        Write patch data / bytes to a given address.
        """
        patch_size = len(patch_data)

        # incoming patch matches existing data, nothing to do
        original_data = ida_bytes.get_bytes(ea, patch_size)
        if original_data == patch_data:
            return

        next_address = ea + patch_size
        inst_start = ida_bytes.get_item_head(next_address)
        if ida_bytes.is_code(ida_bytes.get_flags(inst_start)):

            # if the patch clobbers part of an instruction, fill it with NOP
            if inst_start < next_address:
                inst_size = ida_bytes.get_item_size(inst_start)
                fill_size = (inst_start + inst_size) - next_address
                ego.nop_range(next_address, next_address+fill_size)
                ida_auto.auto_make_code(next_address)

        #
        # write the actual patch data to the database. we also unhook the IDB
        # events to prevent the plugin from seeing the numerous 'patch' events
        # that IDA will generate as we write the patch data to the database
        #

        ego._idb_hooks.unhook()
        ida_bytes.patch_bytes(ea, patch_data)
        ego._idb_hooks.hook()

        #
        # record the region of patched addresses
        #

        addresses = set(range(ea, ea+patch_size))
        if is_range_patched(ea, ea+patch_size):
            ego.patched_addresses |= addresses

        #
        # according to IDA, none of the 'patched' addresses in the database
        # actually have a different value... so they technically were not
        # patched (eg. maybe they were patched back to their ORIGINAL value!)
        #
        # in this case it means the patching plugin shouldn't see these
        # addresses as patched, either...
        #

        else:
            ego.patched_addresses -= addresses

        # request re-analysis of the patched range
        ida_auto.auto_mark_range(ea, ea+patch_size, ida_auto.AU_USED)
        ida_kernwin.execute_sync(ego._notify_patches_changed, ida_kernwin.MFF_NOWAIT|ida_kernwin.MFF_WRITE)

    def apply_patches(ego, target_filepath, clean=False):
        """
        Apply the current patches to the given filepath.
        """
        ego.__b_suc = False

        #
        # ensure that a 'clean' source executable exists for this operation,
        # and then write (or overwrite) the target filepath with the clean
        # file so that we can apply patches to it from a known-good state
        #

        if clean:
            ego.backup_filepath = ego._ensure_clean_backup(target_filepath)

            #
            # due to the variety of errors that may occur from trying to copy
            # a file, we simply trap them all to a more descriptive issue for
            # what action failed in the context of our patching attempt
            #

            try:
                shutils.copyfile(ego.backup_filepath, target_filepath)
            except Exception:
                raise PatchTargetError("Failed to overwrite patch target with a clean executable", target_filepath)

        #
        # attempt to apply the patches to the target filepath
        #
        # NOTE: this 'Exception' catch-all is probably a bit too liberal,
        # instead we should probably have apply_patches(...) raise a generic
        # error if opening the target file for writing fails, leaving any
        # other (unexpected!) patching exceptions uncaught
        #

        try:
            apply_patches(target_filepath)
        except Exception:
            raise PatchApplicationError("Failed to write patches into the target file", target_filepath)

        # patching seems successful? update the stored filepath to the patched binary
        ego.patched_filepath = target_filepath

        #
        # if we made it this far, we assume the file on disk was patched
        # setting __saved_successfully ensures that we start showing the
        # 'quick apply' right click context menu going forward
        #
        # this is to help cut down on crowding the right click menu only
        # until the user explicitly starts using the patching plugin, but
        # also applying their patches to a a binary
        #

        if ego.prefer_quick_apply:
            ego.__b_suc = True

    def quick_apply(ego):
        """
        Apply the current patches using the last-known settings.
        """

        try:
            ego.apply_patches(ego.patched_filepath, ego.prefer_patch_cleanly)
        except Exception as e:
            return (False, e)

        return (True, None)

    
    # Plugin Internals
    

    def _ensure_clean_backup(ego, target_filepath):
        """
        Return True if a clean executable matching the open IDB is available on disk.
        """

        #
        # TODO: what do we do if one/both of these are invalid or blank?
        # such as a blank or tmp IDB? what do they return in this case?
        #

        input_md5 = ida_nalt.retrieve_input_file_md5()
        input_filepath = ida_nalt.get_input_file_path()

        #
        # we will search this list of filepaths for an executable / source
        # file that matches the reported hash of the file used to generate
        # this IDA database
        #

        filepaths = [target_filepath, ego.backup_filepath, input_filepath]
        filepaths = list(filter(None, filepaths))

        # search the list of filepaths for a clean file
        while filepaths:

            # get the next filepath to evaluate
            filepath = filepaths.pop(0)

            #
            # if the given filepath does not end with a '.bak', push a version
            # of the current filepath with that extension to make for a more
            # comprehensive search of a clean backup file
            #
            # we insert this at the front of the list because it should be
            # searched next (the list is kind of ordered by relevance already)
            #

            if not filepath.endswith('.bak'):
                filepaths.insert(0, filepath + '.bak')

            #
            # attempt to read (and then hash) each file that is being
            # considered as a possible source for our clean backup
            #

            try:
                disk_data = open(filepath, 'rb').read()
            except Exception as e:
                #print(" - Failed to read '%s' -- Reason: %s" % (filepath, str(e)))
                continue

            disk_md5 = hashlib.md5(disk_data).digest()

            #
            # MD5 of the tested file does not match the ORIGINAL (clean) file
            # so we simply ignore it cuz it is useless for our purposes
            #

            if disk_md5 != input_md5:
                #print(" - MD5: '%s' -- does not match IDB (probably previously patched)" % filepath)
                continue

            #
            # the MD5 matches between the original executable hash provided by
            # IDA and a hashed file on disk. use this as the source filepath
            # for our dialog
            #

            clean_filepath = filepath
            #print(" - Found unpatched binary! '%s'" % filepath)
            break

        #
        # if we did not break from the loop above, that means we could not
        # find an executable with a hash that is deemed valid to cleanly
        # patch from, so there is nothing else we can do
        #

        else:
            raise PatchBackupError("Failed to locate a clean executable")

        #
        # we have verified that a clean version of the executable matching
        # this database exists on-disk.
        #
        # in the case below, the clean file (presumably a '.bak' file that
        # was previously created) is not at risk of getting overwritten as
        # target_filepath is where the resulting / patched binary is going
        # to be written by the ongoing save action
        #
        # nothing else to do but return success
        #

        if clean_filepath != target_filepath:
            return clean_filepath

        #
        # if the clean filepath does not match the target (output) path, we
        # make a copy of the file and add a '.bak' extension to it as we don't
        # want to overwrite potentially the only clean copy of the file
        #
        # in this case, the user is probably patching foo.exe for the first
        # time, so we are going to be creating foo.exe.bak here
        #

        clean_filepath += '.bak'

        #
        # before attempting to make a clean file backup, we can try checking
        # the hash of the existing file (if there is one) ...
        #
        # if the hash matches what we expect of the clean backup, then the
        # file appears to be readable and sufficient to use as a backup as-is
        #

        try:
            clean_md5 = hashlib.md5(open(clean_filepath, 'rb').read()).digest()
            if clean_md5 == input_md5:
                return clean_filepath

        #
        # failed to read/hash file? maybe it doesn't exist... or it's not
        # readable/writable (locked?) in which case the next action will
        # fail and throw the necessary exception for us instead
        #

        except:
            pass

        #
        # finally, attempt to make the backup of our patch target, as it
        # doesn't seem to exist yet (... or we can't seem to read the file,
        # in which case we're trying a last ditch attempt at overwriting it)
        #

        try:
            shutils.copyfile(target_filepath, clean_filepath)

        #
        # if we failed to write (overwrite?) the desired file for our clean
        # backup, then we cannot ensure that a clean backup exists
        #

        except Exception as e:
            raise PatchBackupError("Failed to write backup executable", clean_filepath)

        # all done
        return clean_filepath

    def _refresh_patches(ego):
        """
        Refresh the list of patched addresses directly from the database.
        """
        addresses = set()

        def visitor(ea, file_offset, original_value, patched_value):
            addresses.add(ea)
            return 0

        ida_bytes.visit_patched_bytes(0, ida_idaapi.BADADDR, visitor)
        ego.patched_addresses = addresses
        ida_kernwin.execute_sync(ego._notify_patches_changed, ida_kernwin.MFF_NOWAIT|ida_kernwin.MFF_WRITE)

    def __deferred_refresh_callback(ego):
        """
        A deferred callback to refresh the list of patched addresses.
        """
        ego._refresh_timer = None
        ego._refresh_patches()
        return -1 # unregisters the timer

    
    # Plugin Events
    

    def patches_changed(ego, callback):
        """
        Subscribe a callback for patch change events.
        """
        register_callback(ego._patches_changed_callbacks, callback)

    def _notify_patches_changed(ego):
        """
        Notify listeners that the patches changed.
        """

        #
        # this function is supposed to notify the plugin components (such as
        # UI) that they should refresh because their data may be stale.
        #
        # currently, the plugin calls this function via async (MFF_FAST)
        # callbacks queued with execute_sync().
        #
        # the reason we do this is because we need to give IDA some time to
        # process pending actions/events/analysis/ui (etc.) after patching
        # or reverting bytes.
        #
        # if we don't execute 'later' (MFF_FAST), some things like generating
        # disassembly text for a patched instruction may be ... wrong or
        # incomplete (eg )
        #

        notify_callback(ego._patches_changed_callbacks)

        # ensure the IDA views are refreshed so highlights are updated
        ida_kernwin.refresh_idaview_anyway()

        # for execute_sync(...)
        return 1

    
    # IDA Events
    

    def _populating_widget_popup(ego, wid, pou, ctx):
        """
        IDA is populating the context menu for a widget.
        """
        #ego._patching_submenu = attach_submenu_to_popup(pou, "patch", Act_I_3.NID)
        # extended list of 'less common' actions saved under a patching submenu
        ida_kernwin.attach_action_to_popup(wid, pou, "PatchByte",    "Patch/")
        ida_kernwin.attach_action_to_popup(wid, pou, "PatchedBytes", "Patch/")
        ida_kernwin.attach_action_to_popup(wid, pou, Act_Sav.NID,    "Patch/")
        # IDA disassembly view
        _fb_iav = ida_kernwin.get_widget_type(wid) == ida_kernwin.BWN_DISASM
        # custom / interactive patching view
        if not(ida_kernwin.get_widget_title(wid) == 'PatchingCodeViewer' or _fb_iav):return
        # check if the user has 'selected'
        p0, p1 = ida_kernwin.twinpos_t(), ida_kernwin.twinpos_t()
        _fb_sel = ida_kernwin.read_selection(wid, p0, p1)
        _fbMsel = p0.place_as_simpleline_place_t() != p1.place_as_simpleline_place_t() if _fb_sel else False
        _fbEsel,_li_enb,_li_end=read_range_selection(ctx)
        _li_enc                = get_current_ea(ctx)
        if  not _fbEsel:_li_enb=_li_enc
        _fb_lev = ego.is_range_patched(_li_enb, _li_end) if _fb_sel and _fbEsel else ego.is_item_patched(_li_enc)

        # determine if the user right clicked code
        _fb_cod = ida_bytes.is_code(ida_bytes.get_flags(_li_enc))
        #PRE_NYM_ACT = Act_XXX.NYM
        
        # if the user right clicked a single instruction or data item...
        if not _fbMsel:

            # inject the 'assemble' action in both code and data segments
            # this allows editing assembly in code segments and text/bytes in data segments
            if _fb_iav:
                ida_kernwin.attach_action_to_popup(wid, pou, Act_Asm.NID, "Rename", ida_kernwin.SETMENU_APP)
            
            # inject the 'force jump' action only if a conditional jump was right clicked (code only)
            if _fb_cod:
                mnemonic = ida_ua.print_insn_mnem(_li_enc)
                if ego.assembler.is_conditional_jump(mnemonic):
                    ida_kernwin.attach_action_to_popup(wid, pou, Act_Jmp.NID, None, ida_kernwin.SETMENU_APP)

        
        # if the user selected some patched bytes, show the 'revert' action
        if      _fb_lev:ida_kernwin.attach_action_to_popup(wid, pou, Act_Rev.NID, None, ida_kernwin.SETMENU_APP)
        # quick save
        if  ego.__b_suc:ida_kernwin.attach_action_to_popup(wid, pou, ActQSav.NID, None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(wid, pou, Act_NoP.NID, None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(wid, pou, Act_Ret.NID, None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(wid, pou, Act_I_3.NID, None, ida_kernwin.SETMENU_APP)
        # insert start spacer before / after our action group
        ida_kernwin.attach_action_to_popup(wid, pou, "-", "Patch",     ida_kernwin.SETMENU_INS)
        ida_kernwin.attach_action_to_popup(wid, pou, "-", Act_I_3.NYM, ida_kernwin.SETMENU_APP)
        
    def _highlight_lines(ego, out, widget, rin):
        """
        IDA is drawing disassembly lines and requesting highlighting info.
        """

        # if there are no patches, there is nothing to highlight
        if not ego.patched_addresses:
            return

        # ignore line highlight events that are not for a disassembly view
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return

        # cache item heads that have been checked for patches
        ignore_item_ea = set()
        highlight_item_ea = set()

        # highlight lines/addresses that have been patched by the user
        for section_lines in rin.sections_lines:
            for line in section_lines:
                line_ea = line.at.toea()

                #
                # fast path to ignore entire items that have not been patched
                # but may span multiple lines in the disassembly view
                #

                item_head = ida_bytes.get_item_head(line_ea)
                if item_head in ignore_item_ea:
                    continue

                #
                # this is a fast-path to avoid having to re-check an entire
                # item if the current line address has already been checked
                # and determined to contain an applied patch.
                #

                if line_ea in highlight_item_ea:

                    # highlight the line if it is patched in some way
                    e = ida_kernwin.line_rendering_output_entry_t(line)
                    e.bg_color = ida_kernwin.CK_EXTRA2
                    e.flags = ida_kernwin.LROEF_FULL_LINE

                    # save the highlight to the output line highlight list
                    out.entries.push_back(e)
                    continue

                #
                # for lines of IDA disas that normally have a small number of
                # backing bytes (such as an instruction or simple data item)
                # we explode it out to its individual addresses and use sets
                # to check if any bytes within it have been patched
                #
                # this scales well to an infinite number of patched bytes
                #

                item_len = ida_bytes.get_item_size(line_ea)
                end_ea = line_ea + item_len

                if item_len <= 256:
                    line_addresses = set(range(line_ea, end_ea))
                    if not(line_addresses & ego.patched_addresses):
                        ignore_item_ea.add(line_ea)
                        continue

                #
                # for lines with items that are reportedly quite 'large' (maybe
                # a struct, array, alignment directive, etc.) where a line may
                # contribute to an item that's tens of thousands of bytes...
                #
                # we will instead loop through all of the patched addresses
                # to see if any of them fall within the range of the line.
                #
                # it seems unlikely that the user will ever have very many
                # patched bytes (maybe hundreds?) versus generating a large
                # set and checking potentially tens of thousands of addresses
                # that make up an item, like the above condition would
                #
                # NOTE: this was a added during a slight re-factor of this
                # function / logic to help minimize the chance of notable lag
                # when scrolling past large data structures in the disas view
                #

                elif not any(line_ea <= ea < end_ea for ea in ego.patched_addresses):
                    ignore_item_ea.add(line_ea)
                    continue

                # highlight the line if it is patched in some way
                e = ida_kernwin.line_rendering_output_entry_t(line)
                e.bg_color = ida_kernwin.CK_EXTRA2
                e.flags = ida_kernwin.LROEF_FULL_LINE

                # save the highlight to the output line highlight list
                out.entries.push_back(e)
                highlight_item_ea.add(line_ea)

    def _ida_undo_occurred(ego, action_name, is_undo):
        """
        IDA completed an Undo / Redo action.
        """

        #
        # if the user happens to use IDA's native UNDO or REDO functionality
        # we will completely discard our tracked set of patched addresses and
        # query IDA for the true, current set of patches
        #

        ego._refresh_patches()
        return 0
    
    def _ida_byte_patched(ego, ea, old_value):
        """
        IDA is reporting a byte has been patched.
        """

        #
        # if a timer already exists, unregister it so that we can register a
        # new one. this is to effectively resest the timer as patched bytes
        # are coming in 'rapidly' (eg. externally scripted patches, etc)
        #

        if ego._refresh_timer:
            ida_kernwin.unregister_timer(ego._refresh_timer)
        
        #
        # register a timer to wait 200ms before doing a full reset of the
        # patched addresses. this is to help 'batch' the changes
        #

        ego._refresh_timer = ida_kernwin.register_timer(200, ego.__deferred_refresh_callback)

    def profile(ego):
        """
        Profile assemble_all(...) to

        NOTE: you should probably only call this in 'small' databases.
        """
        import pprofile
        prof = pprofile.Profile()
        with prof():
            ego.assemble_all()
        prof.print_stats()

    def parse_all(ego):
        for ea in all_instruction_addresses(0):
            ida_auto.show_addr(ea)
            comps = get_disassembly_components(ea)
            if comps[0]:
                print("%08X: %s" % (ea, str(comps)))

    def assemble_all(ego):
        """
        Attempt to re-assemble every instruction in the IDB, byte-for-byte.

        TODO: build out some actual dedicated tests
        """
        import time, datetime
        start_time = time.time()
        start = 0

        headless = ida_kernwin.cvar.batch

        # the number of correctly re-assembled instructions
        good = 0
        total = 0
        fallback = 0
        unsupported = 0
        unsupported_map = collections.defaultdict(int)

        slow_limit = -1
        asm_threshold = 0.1

        # track failures
        fail_addrs = collections.defaultdict(list)
        fail_bytes = collections.defaultdict(set)
        alternates = set()

        # unhook so the plugin doesn't try to handle a billion 'patch' events
        ego._idb_hooks.unhook()

        for ea in all_instruction_addresses(start):

            # update the navbar cursor based on progress (only when in UI)
            if not headless:
                ida_auto.show_addr(ea)

            #
            # skip some instructions to cut down on noise (lots of noise /
            # false positives with NOP)
            #

            mnemonic = ida_ua.print_insn_mnem(ea)

            # probably undefined data in code / can't be disas / bad instructions
            if not mnemonic:
                continue

            mnemonic = mnemonic.upper()

            # ignore instructions that can decode a wild number of ways
            if mnemonic in ['NOP', 'XCHG']:
                continue

            # keep track of how many instructions we care to 'assemble'
            total += 1

            # ignore instructions that simply aren't supported yet
            if mnemonic in ego.assembler.UNSUPPORTED_MNEMONICS:
                unsupported += 1
                unsupported_map[mnemonic] += 1
                continue

            # fetch raw info about the instruction
            disas_raw = ego.assembler.format_assembly(ea)
            disas_size = ida_bytes.get_item_size(ea)
            disas_bytes = ida_bytes.get_bytes(ea, disas_size)

            #print("0x%08X: ASSEMBLING '%s'" % (ea, disas_raw))
            start_asm = time.time()
            asm_bytes = ego.assembler.asm(disas_raw, ea)
            end_asm = time.time()
            asm_time = end_asm - start_asm

            if asm_time > asm_threshold:
                print("%08X: SLOW %0.2fs - %s" % (ea, asm_time, disas_raw))
                slow_limit -= 1
                if slow_limit == 0:
                    break

            # assembled vs expected
            byte_tuple = (asm_bytes, disas_bytes)

            # assembled bytes match what is in the database
            if asm_bytes == disas_bytes or byte_tuple in alternates:
                good += 1
                continue

            asm_bytes = ego.assembler.asm(disas_raw, ea)

            byte_tuple = (asm_bytes, disas_bytes)

            # assembled bytes match what is in the database
            if asm_bytes == disas_bytes or byte_tuple in alternates:
                good += 1
                fallback += 1
                continue

            known_text = disas_raw in fail_addrs
            known_bytes = byte_tuple in fail_bytes[disas_raw]

            if not known_bytes and len(asm_bytes):

                # the assembled patch is the same size, or smaller than the og
                if len(asm_bytes) <= len(disas_bytes):
                    ida_before = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea))
                    ida_after = disassemble_bytes(asm_bytes, ea)

                    ida_after = ida_after.split(';')[0]
                    ida_after = ida_after.replace(' short ', ' ')
                    ida_before = ida_before.split(';')[0]

                    okay = False
                    if ida_after == ida_before:
                        okay = True

                    #
                    # BEFORE: 'add     [rax+rax+0], ch'
                    #  AFTER: 'add     [rax+rax], ch
                    # 0x18004830B: NEW FAILURE 'add     [rax+rax+0], ch'
                    #  - IDA: 00 6C 00 00
                    #  - ASM: 00 2C 00
                    #

                    elif ida_before.replace('+0]', ']') == ida_after:
                        okay = True

                    elif '$+5' in ida_before:
                        okay = True

                    if okay:
                        alternates.add(byte_tuple)
                        good += 1
                        continue

                    print("BEFORE: '%s'\n AFTER: '%s" % (ida_before, ida_after))

            fail_addrs[disas_raw].append(ea)
            fail_bytes[disas_raw].add(byte_tuple)

            if known_text and known_bytes:
                continue

            if not known_text:
                print("0x%08X: NEW FAILURE '%s'" % (ea, disas_raw))
            else:
                print("0x%08X: NEW BYTES '%s'" % (ea, disas_raw))

            disas_hex = ' '.join(['%02X' % x for x in disas_bytes])
            asm_hex = ' '.join(['%02X' % x for x in asm_bytes])
            print(" - IDA: %s\n - ASM: %s" % (disas_hex, asm_hex))
            #break

        # re-hook the to re-enable the plugin's ability to see patch events
        ego._idb_hooks.hook()

        print("-"*50)
        print("RESULTS")
        print("-"*50)

        for disas_raw in sorted(fail_addrs, key=lambda k: len(fail_addrs[k]), reverse=True):
            print("%-5u Fails -- %-40s -- (%u unique patterns)" % (len(fail_addrs[disas_raw]), disas_raw, len(fail_bytes[disas_raw])))

        if False:

            print("-"*50)
            print("ALTERNATE MAPPINGS")
            print("-"*50)

            for x, y in alternates:
                print('%-20s\t%s' % (' '.join(['%02X' % z for z in x]), ' '.join(['%02X' % z for z in y])))

        if unsupported_map:

            print("-"*50)
            print("(KNOWN) Unsupported Mnemonics")
            print("-"*50)

            for mnem, hits in unsupported_map.items():
                print(" - %s - hits %u" % (mnem.ljust(10), hits))

        if total:
            percent = str((good/total)*100)
        else:
            percent = "100.0"

        percent_truncated = percent[:percent.index('.')+3] # truncate! don't round this float...

        arch_name = ida_ida.inf_get_procname()

        total_failed = total - good
        unknown_fails = total_failed - unsupported
        print("-"*50)
        print(" - Success Rate {percent}% -- {good:,} / {total:,} ({fallback:,} fallbacks, {total_failed:,} failed ({unsupported:,} were unsupported mnem, {unknown_fails:,} were unknown)) -- arch '{arch_name}' -- file '{input_path}'".format(
                percent=percent_truncated.rjust(6, ' '),
                good=good,
                total=total,
                fallback=fallback,
                total_failed=total_failed,
                unsupported=unsupported,
                unknown_fails=unknown_fails,
                arch_name=arch_name,
                input_path=ida_nalt.get_input_file_path()
            )
        )

        total_time = int(time.time() - start_time)
        print(" - Took %s %s..." % (datetime.timedelta(seconds=total_time), 'minutes' if total_time >= 60 else 'seconds'))


class Plg_Pat(ida_idaapi.plugin_t):
    """
     #  The IDA Patching plugin stub.
     #  This pattern of splitting out the plugin core from the IDA plugin_t stub
     #  is primarily to help separate the plugin functionality from IDA's and
     #  make it easier to 'reload' for development / testing purposes.
    """

    #
    # Plugin flags:
    # - PLUGIN_PROC: Load / unload this plugin when an IDB opens / closes
    # - PLUGIN_HIDE: Hide this plugin from the IDA plugin menu
    # - PLUGIN_UNL:  Unload the plugin after calling run()
    #

    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
    comment = "A plugin to enable binary patching in IDA"
    help = ""
    wanted_name = "pate"
    wanted_hotkey = ""

    def __init__(ego):
        ego.__updated = getattr(IDA_GLOBAL_SCOPE, 'RESTART_REQUIRED', False)

    def init(ego):
        """
        called by IDA when it is loading the plugin.
        """
        if not _FB_ENV_SUP or ego.__updated:
            return ida_idaapi.PLUGIN_SKIP

        # load the plugin core
        ego._ng = Pat(defer_load=True)

        # inject a reference to the plugin context into the IDA console scope
        IDA_GLOBAL_SCOPE.pate = ego

        # mark the plugin as loaded
        return ida_idaapi.PLUGIN_KEEP

    def run(ego, arg):
        """
        called by IDA when this file is loaded as a script.
        """
        pass

    def term(ego):
        """
        called by IDA when it is unloading the plugin.
        """
        try:ego._ng.unload()
        except Exception as e: pass
        ego._ng = None

    def reload(ego):
        """
        Hot-reload the plugin.
        """
        if ego._ng: ego._ng.unload()
        reload_package(core)
        ego._ng = Pat()

# Required plugin entry point for IDAPython plugins.
def PLUGIN_ENTRY():return Plg_Pat()