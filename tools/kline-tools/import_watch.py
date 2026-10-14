# -*- coding: utf-8 -*-
"""触发 0508 导入并轮询对话框状态文本，捕捉错误信息。"""
import time, sys, win32gui, win32con

TITLE = "导入0508历史数据"


def find_dialog():
    return win32gui.FindWindow(None, TITLE)


def children():
    h = find_dialog()
    if not h:
        return None, []
    out = []
    def cb(ch, _):
        out.append((ch, win32gui.GetClassName(ch), win32gui.GetWindowText(ch), win32gui.GetWindowRect(ch)))
    win32gui.EnumChildWindows(h, cb, None)
    return h, out


def main():
    path = sys.argv[1]
    h, cs = children()
    if not h:
        print("no dialog")
        return
    edit = btn = None
    for ch, cls, txt, r in cs:
        if cls == "Edit":
            edit = ch
        if cls == "Button" and txt == "导入":
            btn = ch
    print("dialog", h, "edit", edit, "btn", btn)
    win32gui.SendMessage(edit, win32con.WM_SETTEXT, 0, path)
    time.sleep(0.3)
    win32gui.SendMessage(btn, win32con.BM_CLICK, 0, 0)
    prev = None
    t0 = time.time()
    for i in range(60):
        time.sleep(0.5)
        _, cs2 = children()
        stats = [(c, t, r) for c, cls, t, r in cs2 if cls in ("Static", "Button")]
        cur = tuple((t, r) for c, t, r in stats)
        if cur != prev:
            print(f"[{time.time()-t0:5.1f}s]")
            for c, t, r in stats:
                print(f"        {t!r} {r}")
            prev = cur
    print("watch done")


main()
