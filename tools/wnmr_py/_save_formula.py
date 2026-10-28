# -*- coding: utf-8 -*-
import ctypes
import time
import win32con
import win32gui

u32 = ctypes.windll.user32
CB_SELECTSTRING = 0x014D
combo = 0x2f0a30
edit = 0xc50ab0
ok = 0xbf0984

def get_text(h):
    n = u32.SendMessageW(h, 0x0E, 0, 0)
    buf = ctypes.create_unicode_buffer(n + 1)
    u32.SendMessageW(h, 0x0D, n + 1, buf)
    return buf.value

for label in ("主图叠加", "主图", "叠加"):
    r = u32.SendMessageW(combo, CB_SELECTSTRING, 0xFFFFFFFF, label)
    print(label, "sel", r, "now", get_text(edit))

# prefer overlay on the price pane
if get_text(edit) != "主图叠加":
    # leave 副图 if overlay name is absent; try exact list via select of 副图 to confirm control works
    print("stay", get_text(edit))

time.sleep(0.2)
u32.SendMessageW(ok, win32con.BM_CLICK, 0, 0)
time.sleep(1.0)
print("editor alive", win32gui.IsWindow(0x8100696))
print("draw now", get_text(edit) if win32gui.IsWindow(edit) else "closed")
