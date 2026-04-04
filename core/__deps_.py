# this plugin requires IDA 7.6 or newer
try:
  import ida_ua
  import ida_pro
  import ida_ida
  import ida_idp
  import idautils
  import ida_auto
  import ida_name
  import ida_nalt
  import ida_bytes
  import ida_lines
  import ida_idaapi
  import ida_loader
  import ida_kernwin
  import ida_segregs
  import ida_segment
  import idc
  LI_VER_IDA = ida_pro.IDA_SDK_VERSION
except:
  LI_VER_IDA = False

import keystone
import shiboken6

import os,sys