# -*- coding: utf-8 -*-
import ctypes
import time
import win32con
import win32gui

u32 = ctypes.windll.user32
WM_GETTEXT = 0x0D
WM_GETTEXTLENGTH = 0x0E
WM_SETTEXT = 0x0C

def get_text(h):
    n = u32.SendMessageW(h, WM_GETTEXTLENGTH, 0, 0)
    buf = ctypes.create_unicode_buffer(n + 1)
    u32.SendMessageW(h, WM_GETTEXT, n + 1, buf)
    return buf.value

def set_text(h, s):
    u32.SendMessageW(h, WM_SETTEXT, 0, s)

name = 0x480ae2
code = 0xdb09b6
out = 0x1cd0616
comp = 0xbc0934
ok = 0xbf0984

SRC = (
    "ST1:=DATE=20170810 AND HOUR=9 AND MINUTE=31;\r\n"
    "ST3:=DATE=20170810 AND HOUR=13 AND MINUTE=1;\r\n"
    "ST2:=DATE=20170810 AND HOUR=13 AND MINUTE=6;\r\n"
    "DRAWTEXT(ST2,12.80,'买入价 12.72'),COLORCYAN;\r\n"
    "DRAWTEXT(ST3,12.70,'止损价 12.70'),COLORRED;\r\n"
    "DRAWTEXT(ST1,12.78,'状态1 12.72'),COLORYELLOW;\r\n"
    "DRAWICON(ST2,L,1);\r\n"
    "WNMRSHOW:C;"
)

lines = []
lines.append("name before %r" % get_text(name))
lines.append("draw %r" % get_text(0xc50ab0))
lines.append("coord %r" % get_text(0x20b05d8))
lines.append("type %r" % get_text(0x1fa0944))
lines.append("ver %r" % get_text(0x51704ae))
lines.append("auth %r" % get_text(0x2d0ac0))
set_text(name, "WNMRSHOW")
set_text(code, SRC)
time.sleep(0.3)
lines.append("name after %r" % get_text(name))
lines.append("code after %r" % get_text(code)[:80])
u32.SendMessageW(comp, win32con.BM_CLICK, 0, 0)
time.sleep(1.2)
lines.append("compile:\n" + get_text(out))
open(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\compile.txt", "w", encoding="utf-8").write("\n".join(lines))
print("wrote")
