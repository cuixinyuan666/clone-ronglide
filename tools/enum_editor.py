# -*- coding: utf-8 -*-
import win32gui, io

out = io.open(r'D:\a_ronglide\clone-ronglide\tools\_editor_controls.txt', 'w', encoding='utf-8')

def find():
    res = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h) == '指标公式编辑器':
            res.append(h)
    win32gui.EnumWindows(cb, None)
    return res

def walk(h, depth=0):
    def cb(ch, _):
        cls = win32gui.GetClassName(ch)
        txt = win32gui.GetWindowText(ch)
        cid = win32gui.GetDlgCtrlID(ch)
        r = win32gui.GetWindowRect(ch)
        out.write('%s%s %s id=%#x rect=%s %r\n' % ('  '*depth, hex(ch), cls, cid, r, txt[:40]))
        walk(ch, depth+1)
    win32gui.EnumChildWindows(h, cb, None)

for d in find():
    out.write('DIALOG %s rect=%s\n' % (hex(d), win32gui.GetWindowRect(d)))
    walk(d)
out.close()
print('done')
