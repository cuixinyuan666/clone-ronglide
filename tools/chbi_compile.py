# -*- coding: utf-8 -*-
"""在指标公式编辑器中填 TESTCHBI1 (调用 CHBI/CHDUAN), 读授权下拉, 点击编译, 读输出"""
import ctypes, time, win32gui, io

u32 = ctypes.windll.user32
u32.SetProcessDPIAware()

name_h = 0xb907e4      # 指标名称 Edit
code_h = 0x48080e      # 代码 RichEdit20A
comp_h = 0x8608d0      # 编译 Button
out_h  = 0xd8082e      # 输出 RichEdit20A
auth_h = 0xd70642      # 授权 ComboBox

WM_SETTEXT = 0xC
WM_GETTEXT = 0xD
WM_GETTEXTLENGTH = 0xE
BM_CLICK = 0xF5

def set_text(h, s):
    u32.SendMessageW(h, WM_SETTEXT, 0, ctypes.c_wchar_p(s))

def get_text(h):
    n = u32.SendMessageW(h, WM_GETTEXTLENGTH, 0, 0)
    buf = ctypes.create_unicode_buffer(n + 1)
    u32.SendMessageW(h, WM_GETTEXT, n + 1, buf)
    return buf.value

out = io.open(r'D:\a_ronglide\clone-ronglide\tools\_chbi_result.txt', 'w', encoding='utf-8')

out.write('授权 combo text: %r\n' % get_text(auth_h))

NAME = 'TESTCHBI1'
CODE = 'VAR1:=CHBI(H,L,11);\r\nVAR2:=CHDUAN;\r\nTESTCHBI:VAR1;'
set_text(name_h, NAME)
set_text(code_h, CODE)
time.sleep(0.3)
out.write('set name=%r code=%r\n' % (get_text(name_h), get_text(code_h)))

u32.SendMessageW(comp_h, BM_CLICK, 0, 0)
time.sleep(1.5)
res = get_text(out_h)
out.write('compile output:\n%s\n' % res)

out.write('授权 combo text after: %r\n' % get_text(auth_h))
out.close()
print('done')
