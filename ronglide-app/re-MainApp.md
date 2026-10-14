# Reverse Engineering Report: MainApp.exe

_Portable Executable (PE) | 4,726,784 bytes (4.5 MiB) | SHA-256 e368144f365df647a1ae2cb47f16df627e068a574f243f77d914d0f3d217c9e5_

## Executive Summary

Observed: MainApp.exe is a 32-bit Windows executable for X86, a Portable Executable (PE) file of 4,726,784 bytes (4.5 MiB).

- Derived: imports support Process execution, Network communication, File system, Anti-analysis, Dynamic API resolution, Clipboard access, System reconnaissance.
- Inferred: the file is not packed (packing score 0).
- Observed: missing mitigations: ASLR, DEP / NX, Control Flow Guard, Forced integrity checks, Authenticode signature.
- Observed: 11 indicators extracted, including 2 URLs.
- Derived: recovered 583 functions (27,215 instructions).
- Inferred: start with sub_60b550 at 0x60b550: References text "Default".

Evidence labels: Observed facts are read directly from the file; Derived facts are computed deterministically from observed data; Inferred statements are interpretations that an analyst should confirm.

## What This Program Does

MainApp.exe is a 32-bit X86 executable.

### Execution Lifecycle & Boot Sequence

Under Windows X86, the operating system loader maps executable image sections at 0x400000 and transfers control to the process entry point at 0x65272f.

The C runtime startup routines initialize the process environment, register Structured Exception Handling (SEH) or TLS callbacks, initialize standard I/O, and transfer execution to the application entry.

### Variable Storage & Compiler Optimization

Variable Storage Analysis: Read-only constants and string literals reside in the `.rdata` section, initialized global variables are stored in the `.data` section, and uninitialized globals reside in `.bss` allocated in virtual memory.

Local function variables and call arguments are allocated dynamically within processor registers and thread stack frames.

### Binary Patching & Reverse Engineering Vectors

Binary Patching: Analysis revealed no direct immediate constants in the main execution loop.

## Identity and Fingerprints

| Property | Value |
| --- | --- |
| File name | MainApp.exe |
| Size | 4,726,784 bytes (4.5 MiB) |
| Format | Portable Executable (PE) |
| Entropy (bits/byte) | 6.36 |
| MD5 | 95c31b0360c5c4c8f84615795684c62e |
| SHA-1 | ddf23f69646453b06da2305a764070f1f162e6d9 |
| SHA-256 | e368144f365df647a1ae2cb47f16df627e068a574f243f77d914d0f3d217c9e5 |
| Import hash (imphash) | c9139987fe3f909fd397d941d74abaa7 |
| Image kind | Executable |
| Architecture | X86 |
| Address width | 32 bits |
| Entry point | 0x65272f |
| Image base | 0x400000 |

### Build and Metadata Facts

| Fact | Value |
| --- | --- |
| Link timestamp | 2023-03-15 04:22:01 UTC (raw 0x641147e9) |
| Subsystem | Windows GUI (2) |
| Linker version | 8.0 |
| Debug database (PDB) | d:\RLD\pro\RNF_X\release\MainApp.pdb (GUID 61c15d50575c80459cbea69c44b903a7, age 336) |
| Rich header | Present (Microsoft toolchain fingerprint, key 0x3b3c6c85) |
| TLS callbacks | 0x672f80 |
| Internal module name | MainApp.exe |

## Sections and Memory Layout

Observed: 5 sections (1 executable, 2 writable, 0 both).

| Name | Address | Virtual size | Raw size | Entropy | Access |
| --- | --- | --- | --- | --- | --- |
| .text | 0x401000 | 0x37a788 | 0x37b000 | 6.55 | R-X |
| .rdata | 0x77c000 | 0xdb13f | 0xdc000 | 4.76 | R-- |
| .data | 0x858000 | 0x24680 | 0x13000 | 5.33 | RW- |
| .tls | 0x87d000 | 0x2 | 0x1000 | -0.00 | RW- |
| .rsrc | 0x87e000 | 0x15474 | 0x16000 | 4.61 | R-- |

## Security Mitigations

Observed: each verdict cites the header field or import that decides it.

| Mitigation | Status | Evidence |
| --- | --- | --- |
| ASLR | Missing | OptionalHeader.DllCharacteristics DYNAMIC_BASE |
| DEP / NX | Missing | OptionalHeader.DllCharacteristics NX_COMPAT |
| Control Flow Guard | Missing | OptionalHeader.DllCharacteristics GUARD_CF |
| Forced integrity checks | Missing | OptionalHeader.DllCharacteristics FORCE_INTEGRITY |
| Authenticode signature | Missing | Certificate table |

## Capabilities

Derived: capabilities come from the APIs the program imports; an import shows ability, not proof of use.

| Capability | What it enables | Imported APIs |
| --- | --- | --- |
| Process execution | Launches other programs or shell commands | ShellExecuteExW, ShellExecuteW |
| Network communication | Opens sockets or performs HTTP and other network transfers | curl_easy_cleanup, curl_easy_getinfo, curl_easy_init, curl_easy_perform, curl_easy_setopt |
| File system | Creates, modifies, deletes, or enumerates files | CopyFileW, CreateFileW, DeleteFileW, FindFirstFileW, FindNextFileW, _unlink, fopen, rename |
| Anti-analysis | Detects debuggers or hides from analysis | IsDebuggerPresent |
| Dynamic API resolution | Loads libraries and resolves functions at run time | GetProcAddress, LoadLibraryA, LoadLibraryW |
| Clipboard access | Reads or writes clipboard data | GetClipboardData, OpenClipboard, SetClipboardData |
| System reconnaissance | Collects host, user, or operating system details | GetVersionExA |

## Imports

Observed: 2,007 imported functions from 24 libraries.

| Library | Imported functions |
| --- | --- |
| COMCTL32.dll | 2 |
| GDI32.dll | 57 |
| KERNEL32.dll | 81 |
| MFC80U.DLL | 614 |
| MSIMG32.dll | 2 |
| MSVCP80.dll | 170 |
| MSVCR80.dll | 162 |
| OLEAUT32.dll | 3 |
| RCommon.dll | 19 |
| RCtrl.dll | 281 |
| RDM_C.dll | 154 |
| RData.dll | 118 |
| RNC.dll | 40 |
| SHELL32.dll | 4 |
| SHLWAPI.dll | 2 |
| TAFLib.dll | 11 |
| USER32.dll | 82 |
| WINMM.dll | 1 |
| WS2_32.dll | 4 |
| gdiplus.dll | 18 |
| libcurl.dll | 6 |
| ole32.dll | 1 |
| rdm.dll | 10 |
| rld_lib.dll | 165 |

### Import Table

| Library | Function | Slot |
| --- | --- | --- |
| libcurl.dll | curl_easy_getinfo | 0x77dcd4 |
| libcurl.dll | curl_slist_append | 0x77dcd8 |
| libcurl.dll | curl_easy_perform | 0x77dcdc |
| libcurl.dll | curl_easy_setopt | 0x77dce0 |
| libcurl.dll | curl_easy_cleanup | 0x77dce4 |
| libcurl.dll | curl_easy_init | 0x77dce8 |
| rld_lib.dll | ?crc16@@YAGPBDH@Z | 0x77dd24 |
| rld_lib.dll | ?write@binwriter@rld@@QAE_NG@Z | 0x77dd28 |
| rld_lib.dll | ?read@binreader@rld@@QAE_NAAN@Z | 0x77dd2c |
| rld_lib.dll | ?write@binwriter@rld@@QAE_NN@Z | 0x77dd30 |
| rld_lib.dll | ?decode@base64@rld@@QAE_NPBDAAVbinbuffer@2@@Z | 0x77dd34 |
| rld_lib.dll | ?write@binwriter@rld@@QAE_NABVxdatetime@2@@Z | 0x77dd38 |
| rld_lib.dll | ?write@binwriter@rld@@QAE_N_K@Z | 0x77dd3c |
| rld_lib.dll | ?write@binwriter@rld@@QAE_NABVbinbuffer@2@@Z | 0x77dd40 |
| rld_lib.dll | ?read@binreader@rld@@QAE_NAA_K@Z | 0x77dd44 |
| rld_lib.dll | ?read@binreader@rld@@QAE_NAAVbinbuffer@2@@Z | 0x77dd48 |
| rld_lib.dll | ??Pxdate@rld@@QBE_NABV01@@Z | 0x77dd4c |
| rld_lib.dll | ?unread_size@binreader@rld@@QBEIXZ | 0x77dd50 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAVxtime@3@@Z | 0x77dd54 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAA_J@Z | 0x77dd58 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAD@Z | 0x77dd5c |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAF@Z | 0x77dd60 |
| rld_lib.dll | ??0xdate@rld@@QAE@ABI@Z | 0x77dd64 |
| rld_lib.dll | ??9xdatetime@rld@@QBE_NABV01@@Z | 0x77dd68 |
| rld_lib.dll | ?tostr@xtime@rld@@QBE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ | 0x77dd6c |
| rld_lib.dll | ?tostr@xdatetime@rld@@QBE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ | 0x77dd70 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAE@Z | 0x77dd74 |
| rld_lib.dll | ?get_field_by_item@record@rs@rld@@QBE?AVfield@23@G@Z | 0x77dd78 |
| rld_lib.dll | ?copy@field@rs@rld@@QAE_NABV123@@Z | 0x77dd7c |
| rld_lib.dll | ?set@field@rs@rld@@QAE_NM@Z | 0x77dd80 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z | 0x77dd84 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAI@Z | 0x77dd88 |
| rld_lib.dll | ??4recordset@rs@rld@@QAEAAV012@ABV012@@Z | 0x77dd8c |
| rld_lib.dll | ??4field@rs@rld@@QAEAAV012@ABV012@@Z | 0x77dd90 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAN@Z | 0x77dd94 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAH@Z | 0x77dd98 |
| rld_lib.dll | ??0field@rs@rld@@QAE@XZ | 0x77dd9c |
| rld_lib.dll | ??8xdatetime@rld@@QBE_NABV01@@Z | 0x77dda0 |
| rld_lib.dll | ?clear@xdatetime@rld@@QAEXXZ | 0x77dda4 |
| rld_lib.dll | ?MD5_Final@@YAXPAUMD5Context@@QAE@Z | 0x77dda8 |
| rld_lib.dll | ?MD5_Update@@YAXPAUMD5Context@@PAEH@Z | 0x77ddac |
| rld_lib.dll | ?MD5_Init@@YAXPAUMD5Context@@@Z | 0x77ddb0 |
| rld_lib.dll | ?crc64@@YA_K_KPBE0@Z | 0x77ddb4 |
| rld_lib.dll | ?str2hex16@str@rld@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PBDH@Z | 0x77ddb8 |
| rld_lib.dll | ?SHA1Final@@YAXQAEPAUSHA1_CTX@@@Z | 0x77ddbc |
| rld_lib.dll | ?SHA1Update@@YAXPAUSHA1_CTX@@PBEI@Z | 0x77ddc0 |
| rld_lib.dll | ?SHA1Init@@YAXPAUSHA1_CTX@@@Z | 0x77ddc4 |
| rld_lib.dll | ?get_fieldinfo_pos@record@rs@rld@@QBEHG@Z | 0x77ddc8 |
| rld_lib.dll | ??Mxtime@rld@@QBE_NABV01@@Z | 0x77ddcc |
| rld_lib.dll | ??8xtime@rld@@QBE_NABV01@@Z | 0x77ddd0 |
| rld_lib.dll | ?set_time@xtime@rld@@QAEXABI@Z | 0x77ddd4 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAG@Z | 0x77ddd8 |
| rld_lib.dll | ??4xtime@rld@@QAEAAV01@ABV01@@Z | 0x77dddc |
| rld_lib.dll | ??0xtime@rld@@QAE@ABV01@@Z | 0x77dde0 |
| rld_lib.dll | ?set_reccount@recordset@rs@rld@@QAEXK@Z | 0x77dde4 |
| rld_lib.dll | ?get_fieldcount@rsfile@rs@rld@@QBEGXZ | 0x77dde8 |
| rld_lib.dll | ?get_fieldinfo@rsfile@rs@rld@@QBEPBUrs_fieldinfo_t@23@H@Z | 0x77ddec |
| rld_lib.dll | ?get_reccount@rsfile@rs@rld@@QBEKXZ | 0x77ddf0 |
| rld_lib.dll | ??0recordset@rs@rld@@QAE@GPBUrs_fieldinfo_t@12@KG@Z | 0x77ddf4 |
| rld_lib.dll | ?open@rsfile@rs@rld@@QAE_NPBD@Z | 0x77ddf8 |
| rld_lib.dll | ??1rsfile@rs@rld@@QAE@XZ | 0x77ddfc |
| rld_lib.dll | ??0rsfile@rs@rld@@QAE@_N00@Z | 0x77de00 |
| rld_lib.dll | ?split_s@str@rld@@SAXAAV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@4@1@Z | 0x77de04 |
| rld_lib.dll | ?save@recordset@rs@rld@@QAE_NPBD@Z | 0x77de08 |
| rld_lib.dll | ?clear@recordset@rs@rld@@QAEXXZ | 0x77de0c |
| rld_lib.dll | ?get_time@xtime@rld@@QBEIXZ | 0x77de10 |
| rld_lib.dll | ?is_valid@recordset@rs@rld@@QBE_NXZ | 0x77de14 |
| rld_lib.dll | ?buffer@binwriter@rld@@QBEPBEXZ | 0x77de18 |
| rld_lib.dll | ?write@binwriter@rld@@QAE_NH@Z | 0x77de1c |
| rld_lib.dll | ?len@binwriter@rld@@QBEIXZ | 0x77de20 |
| rld_lib.dll | ?read@binreader@rld@@QAE_NAAH@Z | 0x77de24 |
| rld_lib.dll | ?write@binwriter@rld@@QAE_NPBEI@Z | 0x77de28 |
| rld_lib.dll | ?write@binwriter@rld@@QAE_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z | 0x77de2c |
| rld_lib.dll | ?write@binwriter@rld@@QAE_NE@Z | 0x77de30 |
| rld_lib.dll | ?write@binwriter@rld@@QAE_NI@Z | 0x77de34 |
| rld_lib.dll | ??1binwriter@rld@@UAE@XZ | 0x77de38 |
| rld_lib.dll | ??0binwriter@rld@@QAE@I@Z | 0x77de3c |
| rld_lib.dll | ?read@binreader@rld@@QAE_NPAEI@Z | 0x77de40 |
| rld_lib.dll | ?read@binreader@rld@@QAE_NAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z | 0x77de44 |
| rld_lib.dll | ?read@binreader@rld@@QAE_NAAE@Z | 0x77de48 |
| rld_lib.dll | ?read@binreader@rld@@QAE_NAAI@Z | 0x77de4c |
| rld_lib.dll | ??1binreader@rld@@UAE@XZ | 0x77de50 |
| rld_lib.dll | ??Nxdatetime@rld@@QBE_NABV01@@Z | 0x77de54 |
| rld_lib.dll | ?get_fieldinfo_pos@recordset@rs@rld@@QBEHG@Z | 0x77de58 |
| rld_lib.dll | ?isempty@xdate@rld@@QBE_NXZ | 0x77de5c |
| rld_lib.dll | ?get_field@recordset@rs@rld@@QBE?AVfield@23@HH@Z | 0x77de60 |
| rld_lib.dll | ?clear@xdate@rld@@QAEXXZ | 0x77de64 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAVxdate@3@@Z | 0x77de68 |
| rld_lib.dll | ?set_date@xdate@rld@@QAEXABGABE1@Z | 0x77de6c |
| rld_lib.dll | ?tostr@xdate@rld@@QBE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ | 0x77de70 |
| rld_lib.dll | ?isvalid@xdate@rld@@QBE_NXZ | 0x77de74 |
| rld_lib.dll | ??4xdate@rld@@QAEAAV01@ABV01@@Z | 0x77de78 |
| rld_lib.dll | ??0xdate@rld@@QAE@ABV01@@Z | 0x77de7c |
| rld_lib.dll | ?get_currtime@xtime@rld@@SA?AV12@XZ | 0x77de80 |
| rld_lib.dll | ??Oxtime@rld@@QBE_NABV01@@Z | 0x77de84 |
| rld_lib.dll | ?set_date@xdate@rld@@QAEXABI@Z | 0x77de88 |
| rld_lib.dll | ?is_valid@record@rs@rld@@QBE_NXZ | 0x77de8c |
| rld_lib.dll | ??1record@rs@rld@@QAE@XZ | 0x77de90 |
| rld_lib.dll | ?get_record@recordset@rs@rld@@QBE?AVrecord@23@H@Z | 0x77de94 |
| rld_lib.dll | ?get_fieldcount@recordset@rs@rld@@QBEGXZ | 0x77de98 |
| rld_lib.dll | ?get_reccount@recordset@rs@rld@@QBEKXZ | 0x77de9c |
| rld_lib.dll | ??1recordset@rs@rld@@QAE@XZ | 0x77dea0 |
| rld_lib.dll | ??0recordset@rs@rld@@QAE@XZ | 0x77dea4 |
| rld_lib.dll | ??0xdate@rld@@QAE@XZ | 0x77dea8 |
| rld_lib.dll | ??1field@rs@rld@@UAE@XZ | 0x77deac |
| rld_lib.dll | ?read@binreader@rld@@QAE_NAAG@Z | 0x77deb0 |
| rld_lib.dll | ?xml_encode@str@rld@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PBD@Z | 0x77deb4 |
| rld_lib.dll | ?set_datetime@xdatetime@rld@@QAEXABGABE1111@Z | 0x77deb8 |
| rld_lib.dll | ?get_field@record@rs@rld@@QBE?AVfield@23@H@Z | 0x77debc |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAM@Z | 0x77dec0 |
| rld_lib.dll | ?get_fieldinfo@recordset@rs@rld@@QBEPBUrs_fieldinfo_t@23@H@Z | 0x77dec4 |
| rld_lib.dll | ?get_currdate@xdate@rld@@SA?AV12@XZ | 0x77dec8 |
| rld_lib.dll | ?get_date@xdate@rld@@QBEIXZ | 0x77decc |
| rld_lib.dll | ?get_year@xdate@rld@@QBEGXZ | 0x77ded0 |
| rld_lib.dll | ?get_month@xdate@rld@@QBEEXZ | 0x77ded4 |
| rld_lib.dll | ?get_day@xdate@rld@@QBEEXZ | 0x77ded8 |
| rld_lib.dll | ??9xdate@rld@@QBE_NABV01@@Z | 0x77dedc |
| rld_lib.dll | ?Jul_getWeekDay@xdate@rld@@SAEABH@Z | 0x77dee0 |
| rld_lib.dll | ?Jul_fromDate@xdate@rld@@SA_NAAHABV12@@Z | 0x77dee4 |
| rld_lib.dll | ??Mxdate@rld@@QBE_NABV01@@Z | 0x77dee8 |
| rld_lib.dll | ?set_date@xdatetime@rld@@QAEXABVxdate@2@@Z | 0x77deec |
| rld_lib.dll | ??Oxdatetime@rld@@QBE_NABV01@@Z | 0x77def0 |
| rld_lib.dll | ??Oxdate@rld@@QBE_NABV01@@Z | 0x77def4 |
| rld_lib.dll | ??0xtime@rld@@QAE@ABE00@Z | 0x77def8 |
| rld_lib.dll | ?set_time@xdatetime@rld@@QAEXABE00@Z | 0x77defc |
| rld_lib.dll | ??8xdate@rld@@QBE_NABV01@@Z | 0x77df00 |
| rld_lib.dll | ??0xdatetime@rld@@QAE@ABVxdate@1@ABVxtime@1@@Z | 0x77df04 |
| rld_lib.dll | ??Mxdatetime@rld@@QBE_NABV01@@Z | 0x77df08 |
| rld_lib.dll | ?set_time@xdatetime@rld@@QAEXABVxtime@2@@Z | 0x77df0c |
| rld_lib.dll | ?isempty@xtime@rld@@QBE_NXZ | 0x77df10 |
| rld_lib.dll | ?get_date@xdatetime@rld@@QBE?AVxdate@2@XZ | 0x77df14 |
| rld_lib.dll | ??0xtime@rld@@QAE@XZ | 0x77df18 |
| rld_lib.dll | ?isempty@xdatetime@rld@@QBE_NXZ | 0x77df1c |
| rld_lib.dll | ?isvalid@xdatetime@rld@@QBE_NXZ | 0x77df20 |
| rld_lib.dll | ?format@str@rld@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PBDZZ | 0x77df24 |
| rld_lib.dll | ??1base64@rld@@QAE@XZ | 0x77df28 |
| rld_lib.dll | ??0base64@rld@@QAE@XZ | 0x77df2c |
| rld_lib.dll | ?encode@base64@rld@@QAE_NPBEHAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z | 0x77df30 |
| rld_lib.dll | ?get_second@xtime@rld@@QBEEXZ | 0x77df34 |
| rld_lib.dll | ?get_time@xdatetime@rld@@QBE?AVxtime@2@XZ | 0x77df38 |
| rld_lib.dll | ?get_year@xdatetime@rld@@QBEGXZ | 0x77df3c |
| rld_lib.dll | ?_write_logline@logfile@log@rld@@MAEXW4log_level_e@23@PBD@Z | 0x77df40 |
| rld_lib.dll | ?get_month@xdatetime@rld@@QBEEXZ | 0x77df44 |
| rld_lib.dll | ?_open_logfile@logfile@log@rld@@MAEPAU_iobuf@@AA_N@Z | 0x77df48 |
| rld_lib.dll | ?get_day@xdatetime@rld@@QBEEXZ | 0x77df4c |
| rld_lib.dll | ?Debug@logfile@log@rld@@UAAXPBDZZ | 0x77df50 |
| rld_lib.dll | ?get_hour@xdatetime@rld@@QBEEXZ | 0x77df54 |
| rld_lib.dll | ?Detail@logfile@log@rld@@UAAXPBDZZ | 0x77df58 |
| rld_lib.dll | ?get_minute@xdatetime@rld@@QBEEXZ | 0x77df5c |
| rld_lib.dll | ?Event@logfile@log@rld@@UAAXPBDZZ | 0x77df60 |
| rld_lib.dll | ?get_second@xdatetime@rld@@QBEEXZ | 0x77df64 |
| rld_lib.dll | ?Warn@logfile@log@rld@@UAAXPBDZZ | 0x77df68 |
| rld_lib.dll | ?Error@logfile@log@rld@@UAAXPBDZZ | 0x77df6c |
| rld_lib.dll | ?get_curdatetime@xdatetime@rld@@SA?AV12@XZ | 0x77df70 |
| rld_lib.dll | ??4xdatetime@rld@@QAEAAV01@ABV01@@Z | 0x77df74 |
| rld_lib.dll | ??0xdatetime@rld@@QAE@ABV01@@Z | 0x77df78 |
| rld_lib.dll | ??1spin_lock@lock@rld@@UAE@XZ | 0x77df7c |
| rld_lib.dll | ??0spin_lock@lock@rld@@QAE@XZ | 0x77df80 |
| rld_lib.dll | ??1logfile@log@rld@@UAE@XZ | 0x77df84 |
| rld_lib.dll | ??0logfile@log@rld@@QAE@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@W4log_level_e@12@0KH@Z | 0x77df88 |
| rld_lib.dll | ??0xdatetime@rld@@QAE@XZ | 0x77df8c |
| rld_lib.dll | ?get_hour@xtime@rld@@QBEEXZ | 0x77df90 |
| rld_lib.dll | ?get_minute@xtime@rld@@QBEEXZ | 0x77df94 |
| rld_lib.dll | ?read@binreader@rld@@QAE_NAAVxdatetime@2@@Z | 0x77df98 |
| rld_lib.dll | ??Pxdatetime@rld@@QBE_NABV01@@Z | 0x77df9c |
| rld_lib.dll | ??Nxdate@rld@@QBE_NABV01@@Z | 0x77dfa0 |
| rld_lib.dll | ?seconds@xtime@rld@@QBEIXZ | 0x77dfa4 |
| rld_lib.dll | ?get@field@rs@rld@@QBE_NAAVxdatetime@3@@Z | 0x77dfa8 |
| rld_lib.dll | ??0xdatetime@rld@@QAE@ABVxdate@1@@Z | 0x77dfac |
| rld_lib.dll | ??0binreader@rld@@QAE@PBEI@Z | 0x77dfb0 |
| rld_lib.dll | ??0xtime@rld@@QAE@ABI@Z | 0x77dfb4 |
| rdm.dll | ?fieldinfo_count@dm_rec_info@@QBEIXZ | 0x77dcf8 |
| rdm.dll | ?get_fieldinfo@dm_rec_info@@QBEPBUrs_fieldinfo_t@rs@rld@@XZ | 0x77dcfc |
| rdm.dll | ?append@dm_rec_info@@QAE_NGEE@Z | 0x77dd00 |
| rdm.dll | ?clear@dm_rec_info@@QAEXXZ | 0x77dd04 |
| rdm.dll | ?get_fieldinfo_pos_by_item@dm_rec_info@@QBEIG@Z | 0x77dd08 |
| rdm.dll | ??1dm_rec_info@@UAE@XZ | 0x77dd0c |
| rdm.dll | ??0dm_rec_info@@QAE@XZ | 0x77dd10 |
| rdm.dll | ?dm_copy_recordset@@YA_NAAVrecordset@rs@rld@@HABV123@HH@Z | 0x77dd14 |
| rdm.dll | ?dm_copy_recordset@@YA_NAAVrecordset@rs@rld@@HAAVrsfile@23@HH@Z | 0x77dd18 |
| rdm.dll | ?append@dm_rec_info@@QAE_NG@Z | 0x77dd1c |
| RDM_C.dll | ?GetHistoryByPos@QuoApi@@SA?AW4dmresult_t@@AAVrecordset@rs@rld@@ABVsymbol_info@@GHHABUDividenMode@@@Z | 0x77d5e4 |
| RDM_C.dll | ?PopEvent@DmcApi@@SA_NAAV?$vector@V?$shared_ptr@Vevtbase@evt@rld@@@boost@@V?$allocator@V?$shared_ptr@Vevtbase@evt@rld@@@boost@@@std@@@std@@H@Z | 0x77d5e8 |
| RDM_C.dll | ?RequestRegisterCloudItem@SymbolRegister@@QAE_NABV?$vector@Vclouditem_info@@V?$allocator@Vclouditem_info@@@std@@@std@@0@Z | 0x77d5ec |
| RDM_C.dll | ?RequestUnregisterCloudItem@SymbolRegister@@QAE_NABV?$vector@Vclouditem_info@@V?$allocator@Vclouditem_info@@@std@@@std@@@Z | 0x77d5f0 |
| RDM_C.dll | ?GetSystemBlockListOfSymbol@BlockApi@@SA?AW4dmresult_t@@ABVsymbol_info@@AAV?$vector@Vblock_info@@V?$allocator@Vblock_info@@@std@@@std@@@Z | 0x77d5f4 |
| RDM_C.dll | ?SymbolIsIndex@QuoApi@@SA_NABVsymbol_info@@@Z | 0x77d5f8 |
| RDM_C.dll | ?RequestTAMemory@NetApi@@SA_NABV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@GG@Z | 0x77d5fc |
| RDM_C.dll | ?RequestF10@NetApi@@SA_NABVsymbol_info@@E@Z | 0x77d600 |
| RDM_C.dll | ?GetF10Content@QuoApi@@SA?AW4dmresult_t@@ABVsymbol_info@@EAAVbinbuffer@rld@@@Z | 0x77d604 |
| RDM_C.dll | ?GetSymbolMainIndex@QuoApi@@SA?AVsymbol_info@@ABV2@@Z | 0x77d608 |
| RDM_C.dll | ?IsInOpenTime@QuoApi@@SA_NABVsymbol_info@@ABVxtime@rld@@@Z | 0x77d60c |
| RDM_C.dll | ?GetTmkPosByTime@QuoApi@@SAHABVsymbol_info@@ABVxtime@rld@@@Z | 0x77d610 |
| RDM_C.dll | ?GetSymbolStatus@QuoApi@@SAEABVsymbol_info@@@Z | 0x77d614 |
| RDM_C.dll | ?IsBlockMember@BlockApi@@SA_NABVblock_info@@ABVsymbol_info@@@Z | 0x77d618 |
| RDM_C.dll | ?GetRealHistoryType@QuoApi@@SA_NGAAG0@Z | 0x77d61c |
| RDM_C.dll | ?SymbolSupportAuction@QuoApi@@SA_NABVsymbol_info@@@Z | 0x77d620 |
| RDM_C.dll | ?RequestHistory@NetApi@@SA_NABVsymbol_info@@GH_N1@Z | 0x77d624 |
| RDM_C.dll | ?GetBlockIndexListOfSymbol@BlockApi@@SAXABVsymbol_info@@AAV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@@Z | 0x77d628 |
| RDM_C.dll | ?GetTAMemoryString@QuoApi@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@GH@Z | 0x77d62c |
| RDM_C.dll | ?GetMarketMainIndex@QuoApi@@SA?AVsymbol_info@@E@Z | 0x77d630 |
| RDM_C.dll | ?GetMemoryRecordsetByItemno@QuoApi@@SA?AW4dmresult_t@@AAVrecordset@rs@rld@@ABV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@ABV?$vector@GV?$allocator@G@std@@@7@@Z | 0x77d634 |
| RDM_C.dll | ?GetTAMemoryRecordset@QuoApi@@SA?AW4dmresult_t@@ABVsymbol_info@@AAVrecordset@rs@rld@@@Z | 0x77d638 |
| RDM_C.dll | ?GetSymbolVolUnit@QuoApi@@SAGABVsymbol_info@@@Z | 0x77d63c |
| RDM_C.dll | ?AuthorizeCloudFactorName@AuthApi@@SA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z | 0x77d640 |
| RDM_C.dll | ?GetMarketSectionVector@QuoApi@@SAXEAAV?$vector@Usection_t@@V?$allocator@Usection_t@@@std@@@std@@@Z | 0x77d644 |
| RDM_C.dll | ?GetSectionName@QuoApi@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@G@Z | 0x77d648 |
| RDM_C.dll | ?GetSectionAbbreviation@QuoApi@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@G@Z | 0x77d64c |
| RDM_C.dll | ?GetMinPosByTradeTime@QuoApi@@SAHABVsymbol_info@@ABVxtime@rld@@@Z | 0x77d650 |
| RDM_C.dll | ?RequestTAHistory@NetApi@@SA_NABVsymbol_info@@GH_N1@Z | 0x77d654 |
| RDM_C.dll | ?GetSymbolRldHyIndex@BlockApi@@SA?AVsymbol_info@@ABV2@@Z | 0x77d658 |
| RDM_C.dll | ?Save@BlockApi@@SA_NPBDABV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@@Z | 0x77d65c |
| RDM_C.dll | ?GetMemberCount@BlockApi@@SAHABVblock_info@@@Z | 0x77d660 |
| RDM_C.dll | ?RequestTAPlanSelect@NetApi@@SA_NEABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@G@Z | 0x77d664 |
| RDM_C.dll | ?RequestUploadUserFile@NetApi@@SA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVbinbuffer@rld@@@Z | 0x77d668 |
| RDM_C.dll | ?RequestDownloadUserFile@NetApi@@SA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I_K@Z | 0x77d66c |
| RDM_C.dll | ?GetBlockInfoByIndex@BlockApi@@SA?AVblock_info@@ABVsymbol_info@@@Z | 0x77d670 |
| RDM_C.dll | ?GetPrivBlockMemberList@BlockApi@@SA?AW4dmresult_t@@ABVblock_info@@AAV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@@Z | 0x77d674 |
| RDM_C.dll | ?SymbolIsST@QuoApi@@SA_NABVsymbol_info@@@Z | 0x77d678 |
| RDM_C.dll | ?GetMarketMainSymbolVector@QuoApi@@SAXAAV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@E@Z | 0x77d67c |
| RDM_C.dll | ?ReqeustActMemory@NetApi@@SA_NABV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@ABV?$vector@GV?$allocator@G@std@@@3@@Z | 0x77d680 |
| RDM_C.dll | ?GetBlockIndex@BlockApi@@SA?AVsymbol_info@@ABVblock_info@@@Z | 0x77d684 |
| RDM_C.dll | ?GetTASignalString@QuoApi@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@G@Z | 0x77d688 |
| RDM_C.dll | ?GetTASignalName@QuoApi@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@G@Z | 0x77d68c |
| RDM_C.dll | ?LoadPriv@BlockApi@@SA_NPBD@Z | 0x77d690 |
| RDM_C.dll | ?GetMarketContinuousSymbolVector@QuoApi@@SAXAAV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@E@Z | 0x77d694 |
| RDM_C.dll | ?GetMarketFuturesIndexVector@QuoApi@@SAXAAV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@E@Z | 0x77d698 |
| RDM_C.dll | ?NeedRequestMemoryItemno@QuoApi@@SA_NABVsymbol_info@@G@Z | 0x77d69c |
| RDM_C.dll | ?GetMinTradeTimeByPos@QuoApi@@SA?AVxtime@rld@@ABVsymbol_info@@H@Z | 0x77d6a0 |
| RDM_C.dll | ?GetMinTradeTimeList@QuoApi@@SA_NABVsymbol_info@@AAV?$vector@Vxtime@rld@@V?$allocator@Vxtime@rld@@@std@@@std@@@Z | 0x77d6a4 |
| RDM_C.dll | ?UndivBackward@QuoApi@@SAMABVxdate@rld@@MABV?$vector@UXdrData@@V?$allocator@UXdrData@@@std@@@std@@@Z | 0x77d6a8 |
| RDM_C.dll | ?DivBackward@QuoApi@@SAMABVxdate@rld@@MABV?$vector@UXdrData@@V?$allocator@UXdrData@@@std@@@std@@@Z | 0x77d6ac |
| RDM_C.dll | ?SetBlockIndex@BlockApi@@SA?AW4dmresult_t@@ABVblock_info@@ABVsymbol_info@@@Z | 0x77d6b0 |
| RDM_C.dll | ?SetBlockBeginDate@BlockApi@@SA?AW4dmresult_t@@ABVblock_info@@ABVxdate@rld@@@Z | 0x77d6b4 |
| RDM_C.dll | ?SetBlockComboMethod@BlockApi@@SA?AW4dmresult_t@@ABVblock_info@@E@Z | 0x77d6b8 |
| RDM_C.dll | ?GetBlockBeginDate@BlockApi@@SA?AW4dmresult_t@@ABVblock_info@@AAVxdate@rld@@@Z | 0x77d6bc |
| RDM_C.dll | ?GetBlockComboMethod@BlockApi@@SA?AW4dmresult_t@@ABVblock_info@@AAE@Z | 0x77d6c0 |
| RDM_C.dll | ?DivForward@QuoApi@@SAMABVxdate@rld@@MABV?$vector@UXdrData@@V?$allocator@UXdrData@@@std@@@std@@@Z | 0x77d6c4 |
| RDM_C.dll | ?UndivForward@QuoApi@@SAMABVxdate@rld@@MABV?$vector@UXdrData@@V?$allocator@UXdrData@@@std@@@std@@@Z | 0x77d6c8 |
| RDM_C.dll | ?GetHistoryPosByDate@QuoApi@@SAHABVsymbol_info@@GABVxdate@rld@@@Z | 0x77d6cc |
| RDM_C.dll | ?RequestTmk@NetApi@@SA_NABVsymbol_info@@Vxdate@rld@@_N@Z | 0x77d6d0 |
| RDM_C.dll | ?RequestTmk5s@NetApi@@SA_NABVsymbol_info@@Vxdate@rld@@_N@Z | 0x77d6d4 |
| RDM_C.dll | ?GetBlockNameOfSymbol@BlockApi@@SA?AW4dmresult_t@@ABVsymbol_info@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAV45@@Z | 0x77d6d8 |
| RDM_C.dll | ?GetSymbolChiSpel@QuoApi@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVsymbol_info@@@Z | 0x77d6dc |
| RDM_C.dll | ?Authorize@AuthApi@@SA_NI@Z | 0x77d6e0 |
| RDM_C.dll | ?Stop@NetApi@@SAXXZ | 0x77d6e4 |
| RDM_C.dll | ?Uninitialize@QuoApi@@SAXXZ | 0x77d6e8 |
| RDM_C.dll | ?SetLogPath@DmcApi@@SAXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z | 0x77d6ec |
| RDM_C.dll | ?SetDefaultDstShSzL1@QuoApi@@SAX_N@Z | 0x77d6f0 |
| RDM_C.dll | ?PushEvent@DmcApi@@SA_NABV?$shared_ptr@Vevtbase@evt@rld@@@boost@@@Z | 0x77d6f4 |
| RDM_C.dll | ?AddMember@BlockApi@@SA_NABVblock_info@@ABVsymbol_info@@@Z | 0x77d6f8 |
| RDM_C.dll | ?AddMembers@BlockApi@@SA_NABVblock_info@@ABV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@@Z | 0x77d6fc |
| RDM_C.dll | ?Remove@BlockApi@@SAXABVblock_info@@@Z | 0x77d700 |
| RDM_C.dll | ?Create@BlockApi@@SA?AW4dmresult_t@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z | 0x77d704 |
| RDM_C.dll | ?Has@BlockApi@@SA_NABVblock_info@@@Z | 0x77d708 |
| RDM_C.dll | ?GetNotifyCount@NotifyApi@@SAHXZ | 0x77d70c |
| RDM_C.dll | ?GetNotifyList@NotifyApi@@SA?AW4dmresult_t@@AAV?$vector@V?$shared_ptr@Vnotify_data@@@boost@@V?$allocator@V?$shared_ptr@Vnotify_data@@@boost@@@std@@@std@@@Z | 0x77d710 |
| RDM_C.dll | ?GetNotifyList@NotifyApi@@SA?AW4dmresult_t@@AAV?$vector@V?$shared_ptr@Vnotify_data@@@boost@@V?$allocator@V?$shared_ptr@Vnotify_data@@@boost@@@std@@@std@@HH@Z | 0x77d714 |
| RDM_C.dll | ?RequestUnregisterSymbol@SymbolRegister@@QAE_NABV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@@Z | 0x77d718 |
| RDM_C.dll | ?RequestRegisterSymbol@SymbolRegister@@QAE_NABV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@0@Z | 0x77d71c |
| RDM_C.dll | ?GetTotalMinCount@QuoApi@@SAHABVsymbol_info@@@Z | 0x77d720 |
| RDM_C.dll | ??1SymbolRegister@@QAE@XZ | 0x77d724 |
| RDM_C.dll | ??0SymbolRegister@@QAE@XZ | 0x77d728 |
| RDM_C.dll | ?TestWebWorkSpeed@NetApi@@SA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@H@Z | 0x77d72c |
| RDM_C.dll | ?RequestMarketSectionStatus@NetApi@@SA_NE@Z | 0x77d730 |
| RDM_C.dll | ?RequestMarketStatus@NetApi@@SA_NE@Z | 0x77d734 |
| RDM_C.dll | ?RequestTAHisSymbolFile@NetApi@@SA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@E@Z | 0x77d738 |
| RDM_C.dll | ?RequestDownloadPrivBlockFile@NetApi@@SA_NXZ | 0x77d73c |
| RDM_C.dll | ?RequestDownloadBlockFile@NetApi@@SA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z | 0x77d740 |
| RDM_C.dll | ?RequestDownloadHolidayFile@NetApi@@SA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z | 0x77d744 |
| RDM_C.dll | ?AddMarket@QuoApi@@SA_NE@Z | 0x77d748 |
| RDM_C.dll | ?Initialize@QuoApi@@SA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z | 0x77d74c |
| RDM_C.dll | ?RequestVersionCheck@NetApi@@SA_NXZ | 0x77d750 |
| RDM_C.dll | ?ConnectNM@NetApi@@SA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@H@Z | 0x77d754 |
| RDM_C.dll | ?Start@NetApi@@SA_NXZ | 0x77d758 |
| RDM_C.dll | ?SetProxy@NetApi@@SAXIABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@00@Z | 0x77d75c |
| RDM_C.dll | ?SetUserInfo@NetApi@@SAXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z | 0x77d760 |
| RDM_C.dll | ?SetAppInfo@NetApi@@SAXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z | 0x77d764 |
| RDM_C.dll | ?ConnectSvr@NetApi@@SA_NXZ | 0x77d768 |
| RDM_C.dll | ?RequestServerList@NetApi@@SA_NXZ | 0x77d76c |
| RDM_C.dll | ?DisconnectNM@NetApi@@SAXXZ | 0x77d770 |
| RDM_C.dll | ?RequestSectionTable@NetApi@@SA_NE@Z | 0x77d774 |
| RDM_C.dll | ?Load@BlockApi@@SA_NPBD@Z | 0x77d778 |
| RDM_C.dll | ?ReregisterAll@SymbolRegister@@SAXXZ | 0x77d77c |
| RDM_C.dll | ?RequestStaMemory@NetApi@@SA_NE@Z | 0x77d780 |
| RDM_C.dll | ?RequestSymbolTable@NetApi@@SA_NE@Z | 0x77d784 |
| RDM_C.dll | ?RequestXdrFile@NetApi@@SA_NE@Z | 0x77d788 |
| RDM_C.dll | ?RequestLatelyDays@NetApi@@SA_NE@Z | 0x77d78c |
| RDM_C.dll | ?GetMarketShortName@QuoApi@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@E@Z | 0x77d790 |
| RDM_C.dll | ?ImportHistory@QuoApi@@SAHABVsymbol_info@@ABVrecordset@rs@rld@@G@Z | 0x77d794 |
| RDM_C.dll | ?ImportLongAgoHistory@QuoApi@@SAHABVsymbol_info@@ABVrecordset@rs@rld@@G@Z | 0x77d798 |
| RDM_C.dll | ?GetHistoryByDate@QuoApi@@SA?AW4dmresult_t@@AAVrecordset@rs@rld@@ABVsymbol_info@@GABVxdate@5@2UDividenMode@@@Z | 0x77d79c |
| RDM_C.dll | ?GetSymbolMarketStatus@QuoApi@@SA?AW4dmresult_t@@ABVsymbol_info@@AAE@Z | 0x77d7a0 |
| RDM_C.dll | ?RequestShrStru@NetApi@@SA_NABVsymbol_info@@@Z | 0x77d7a4 |
| RDM_C.dll | ?RequestTASelect@NetApi@@SA_NEABV?$vector@Utaselect_t@@V?$allocator@Utaselect_t@@@std@@@std@@E@Z | 0x77d7a8 |
| RDM_C.dll | ?GetHistoryCount@QuoApi@@SA?AW4dmresult_t@@AAHABVsymbol_info@@G@Z | 0x77d7ac |
| RDM_C.dll | ?DownloadMin@NetApi@@SA_NABVsymbol_info@@Vxdate@rld@@_N@Z | 0x77d7b0 |
| RDM_C.dll | ?GetSectionSymbolInfoVector@QuoApi@@SAXAAV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@GE@Z | 0x77d7b4 |
| RDM_C.dll | ?DownloadHistory@NetApi@@SA_NABVsymbol_info@@GABVxdate@rld@@H_N@Z | 0x77d7b8 |
| RDM_C.dll | ?DownloadHistory@NetApi@@SA_NABVsymbol_info@@GH_N1@Z | 0x77d7bc |
| RDM_C.dll | ?GetSymbolLatelyDays@QuoApi@@SAXABVsymbol_info@@HAAV?$vector@Vxdate@rld@@V?$allocator@Vxdate@rld@@@std@@@std@@@Z | 0x77d7c0 |
| RDM_C.dll | ?CheckAndRepairHistoryFile@QuoApi@@SAXABVsymbol_info@@G@Z | 0x77d7c4 |
| RDM_C.dll | ?GetHistoryFirstTime@QuoApi@@SA?AVxtime@rld@@ABVsymbol_info@@GABV23@@Z | 0x77d7c8 |
| RDM_C.dll | ?MarketExist@QuoApi@@SA_NE@Z | 0x77d7cc |
| RDM_C.dll | ?DisconnectSvr@NetApi@@SAXXZ | 0x77d7d0 |
| RDM_C.dll | ?RequestNotifyList@NetApi@@SA_NXZ | 0x77d7d4 |
| RDM_C.dll | ?RequestTASignal@NetApi@@SA_NEH@Z | 0x77d7d8 |
| RDM_C.dll | ?IsConnected@NetApi@@SA_NXZ | 0x77d7dc |
| RDM_C.dll | ?GetFirstDateByType@QuoApi@@SA?AVxdate@rld@@GABV23@@Z | 0x77d7e0 |
| RDM_C.dll | ?GetMinbaseHistoryCountPreday@QuoApi@@SAHABVsymbol_info@@G@Z | 0x77d7e4 |
| RDM_C.dll | ?IsSameDateGroup@QuoApi@@SA_NGABVxdate@rld@@0@Z | 0x77d7e8 |
| RDM_C.dll | ?GetSectionVector@QuoApi@@SAXAAV?$vector@Usection_t@@V?$allocator@Usection_t@@@std@@@std@@@Z | 0x77d7ec |
| RDM_C.dll | ?GetCategoryList@BlockApi@@SA?AW4dmresult_t@@AAV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@@Z | 0x77d7f0 |
| RDM_C.dll | ?GetBlockList@BlockApi@@SA?AW4dmresult_t@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAV?$vector@Vblock_info@@V?$allocator@Vblock_info@@@std@@@4@_N@Z | 0x77d7f4 |
| RDM_C.dll | ?GetPrivBlockList@BlockApi@@SA?AW4dmresult_t@@AAV?$vector@Vblock_info@@V?$allocator@Vblock_info@@@std@@@std@@@Z | 0x77d7f8 |
| RDM_C.dll | ?GetBlockChildrenSize@BlockApi@@SAHABVblock_info@@@Z | 0x77d7fc |
| RDM_C.dll | ?GetBlockChildren@BlockApi@@SA?AW4dmresult_t@@ABVblock_info@@AAV?$vector@Vblock_info@@V?$allocator@Vblock_info@@@std@@@std@@@Z | 0x77d800 |
| RDM_C.dll | ?GetMemberList@BlockApi@@SA?AW4dmresult_t@@ABVblock_info@@AAV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@@Z | 0x77d804 |
| RDM_C.dll | ?ClearMember@BlockApi@@SAXABVblock_info@@@Z | 0x77d808 |
| RDM_C.dll | ?GetSymbolPriceDigit@QuoApi@@SAEABVsymbol_info@@@Z | 0x77d80c |
| RDM_C.dll | ?GetSymbolName@QuoApi@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVsymbol_info@@@Z | 0x77d810 |
| RDM_C.dll | ?ReqeustActMemory@NetApi@@SA_NABVsymbol_info@@@Z | 0x77d814 |
| RDM_C.dll | ?GetMemoryRecordsetByItemno@QuoApi@@SA?AW4dmresult_t@@AAVrecordset@rs@rld@@ABVsymbol_info@@ABV?$vector@GV?$allocator@G@std@@@std@@@Z | 0x77d818 |
| RDM_C.dll | ?IsSelfSymbol@BlockApi@@SA_NABVblock_info@@@Z | 0x77d81c |
| RDM_C.dll | ?IsSelfBlock@BlockApi@@SA_NABVblock_info@@@Z | 0x77d820 |
| RDM_C.dll | ?RemoveMember@BlockApi@@SAXABVblock_info@@ABVsymbol_info@@@Z | 0x77d824 |
| RDM_C.dll | ?GetSymbolSecid@QuoApi@@SAGABVsymbol_info@@@Z | 0x77d828 |
| RDM_C.dll | ?GetAllMarkets@QuoApi@@SAXAAV?$vector@EV?$allocator@E@std@@@std@@@Z | 0x77d82c |
| RDM_C.dll | ?GetMarketStatus@QuoApi@@SA?AW4dmresult_t@@AAEE@Z | 0x77d830 |
| RDM_C.dll | ?GetMarketTradeDate@QuoApi@@SA?AW4dmresult_t@@AAVxdate@rld@@E@Z | 0x77d834 |
| RDM_C.dll | ?GetMarketSymbolInfoVector@QuoApi@@SAXAAV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@EE@Z | 0x77d838 |
| RDM_C.dll | ?DownloadActMemory@NetApi@@SA_NABV?$vector@Vsymbol_info@@V?$allocator@Vsymbol_info@@@std@@@std@@ABV?$vector@GV?$allocator@G@std@@@3@@Z | 0x77d83c |
| RDM_C.dll | ?GetSymbolTradeDate@QuoApi@@SA?AW4dmresult_t@@ABVsymbol_info@@AAVxdate@rld@@@Z | 0x77d840 |
| RDM_C.dll | ?DownloadTmk@NetApi@@SA_NABVsymbol_info@@Vxdate@rld@@_N@Z | 0x77d844 |
| RDM_C.dll | ?GetBlockListOfSymbol@BlockApi@@SA?AW4dmresult_t@@ABVsymbol_info@@AAV?$vector@Vblock_info@@V?$allocator@Vblock_info@@@std@@@std@@@Z | 0x77d848 |
| RNC.dll | ?SetCaptionBkImage@CCustomTitle@@QAEHPAVCBitmap@@H@Z | 0x77da2c |
| RNC.dll | ?SetMenuTextColor@CCustomTitle@@QAEXKKK@Z | 0x77da30 |
| RNC.dll | ?SetCaptionTextColor@CCustomTitle@@QAEXK@Z | 0x77da34 |
| RNC.dll | ?UncheckAllToolButton@CCustomTitle@@QAEXXZ | 0x77da38 |
| RNC.dll | ?SetToolBarBkImage@CCustomTitle@@QAEHPAVCBitmap@@H@Z | 0x77da3c |
| RNC.dll | ?CheckToolButton@CCustomTitle@@QAEXI@Z | 0x77da40 |
| RNC.dll | ??0CCustomTitle@@QAE@XZ | 0x77da44 |
| RNC.dll | ?GetToolButtonCount@CCustomTitle@@QAEHXZ | 0x77da48 |
| RNC.dll | ?SetPageInfoText@CCustomTitle@@QAEXABV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z | 0x77da4c |
| RNC.dll | ?AddToolSeparator@CCustomTitle@@QAEHK@Z | 0x77da50 |
| RNC.dll | ??1CCustomTitle@@UAE@XZ | 0x77da54 |
| RNC.dll | ?SetToolSeparatorColor@CCustomTitle@@QAEXK@Z | 0x77da58 |
| RNC.dll | ?IsSubClassed@CCustomTitle@@QBEHXZ | 0x77da5c |
| RNC.dll | ?AddToolButton@CCustomTitle@@QAEHIABV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@0KKKK@Z | 0x77da60 |
| RNC.dll | ?GetMenu@CCustomTitle@@QAEPAVCMenu@@XZ | 0x77da64 |
| RNC.dll | ?SetToolButtonTextColor@CCustomTitle@@QAEXIKKKK@Z | 0x77da68 |
| RNC.dll | ?SetMenu@CCustomTitle@@QAEHPAVCMenu@@@Z | 0x77da6c |
| RNC.dll | ?SubClassWnd@CCustomTitle@@QAEHPAVCWnd@@HH@Z | 0x77da70 |
| RNC.dll | ?RemoveAllQuickButtons@CCustomTitle@@QAEXXZ | 0x77da74 |
| RNC.dll | ?SetMX_NCTITLE@CCustomTitle@@QAEXH@Z | 0x77da78 |
| RNC.dll | ?SetMenuLeftMargin@CCustomTitle@@QAEXH@Z | 0x77da7c |
| RNC.dll | ?AddQuickButton@CCustomTitle@@QAEHIABV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@0KKKK@Z | 0x77da80 |
| RNC.dll | ?SetToolBarLeftMargin@CCustomTitle@@QAEXH@Z | 0x77da84 |
| RNC.dll | ?RefreshFrame@CCustomTitle@@QAEHXZ | 0x77da88 |
| RNC.dll | ?SetCaptionTextMargin@CCustomTitle@@QAEXHH@Z | 0x77da8c |
| RNC.dll | ?SetCaptionText@CCustomTitle@@QAEXABV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z | 0x77da90 |
| RNC.dll | png_create_read_struct | 0x77da94 |
| RNC.dll | png_create_info_struct | 0x77da98 |
| RNC.dll | png_destroy_read_struct | 0x77da9c |
| RNC.dll | png_set_read_fn | 0x77daa0 |
| RNC.dll | png_set_error_fn | 0x77daa4 |
| RNC.dll | png_read_info | 0x77daa8 |
| RNC.dll | png_get_tRNS | 0x77daac |
| RNC.dll | png_set_bgr | 0x77dab0 |
| RNC.dll | png_set_interlace_handling | 0x77dab4 |
| RNC.dll | png_read_row | 0x77dab8 |
| RNC.dll | png_read_end | 0x77dabc |
| RNC.dll | png_get_io_ptr | 0x77dac0 |
| RNC.dll | png_error | 0x77dac4 |
| RNC.dll | ?AddToolButton@CCustomTitle@@QAEHIABV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@0PB_W@Z | 0x77dac8 |
| RCtrl.dll | ??1CStaticEx@@UAE@XZ | 0x77d17c |
| RCtrl.dll | ?SetForeColor@CStaticEx@@QAEXK@Z | 0x77d180 |
| RCtrl.dll | ?SetBkColor@CStaticEx@@QAEXK@Z | 0x77d184 |
| RCtrl.dll | ?Show@CSTipWnd@@QAEXVCPoint@@PB_W1W4E_ShowTitle@1@@Z | 0x77d188 |
| RCtrl.dll | ??0CSTipWnd@@QAE@XZ | 0x77d18c |
| RCtrl.dll | ??1CSTipWnd@@UAE@XZ | 0x77d190 |
| RCtrl.dll | ?RedrawColumn@CGridCtrl@@QAEHH@Z | 0x77d194 |
| RCtrl.dll | ?SetImage@CUiImageButton@@QAEHPB_W000_N@Z | 0x77d198 |
| RCtrl.dll | ??0CUiImageButton@@QAE@XZ | 0x77d19c |
| RCtrl.dll | ??1CUiImageButton@@UAE@XZ | 0x77d1a0 |
| RCtrl.dll | ??1CSGifPicture@@UAE@XZ | 0x77d1a4 |
| RCtrl.dll | ?Load@CSGifPicture@@QAEHPB_W@Z | 0x77d1a8 |
| RCtrl.dll | ?Draw@CSGifPicture@@QAEHXZ | 0x77d1ac |
| RCtrl.dll | ?IsPlaying@CSGifPicture@@QBEHXZ | 0x77d1b0 |
| RCtrl.dll | ?Stop@CSGifPicture@@QAEXXZ | 0x77d1b4 |
| RCtrl.dll | ?CalcColsWidth@CSBaseSplitter@@MAEXXZ | 0x77d1b8 |
| RCtrl.dll | ?RemoveColumn@CSBaseTable@@UAEXH@Z | 0x77d1bc |
| RCtrl.dll | ?SetTextColor@CUiTabWnd@@QAEXK@Z | 0x77d1c0 |
| RCtrl.dll | ?CalcRowsHeightRatio@CSBaseSplitter@@MAEXXZ | 0x77d1c4 |
| RCtrl.dll | ?CalcColsWidthRatio@CSBaseSplitter@@MAEXXZ | 0x77d1c8 |
| RCtrl.dll | ?SetHoverTextColor@CUiTabWnd@@QAEXK@Z | 0x77d1cc |
| RCtrl.dll | ?RemoveGrid@CSBaseTable@@UAEXHHW4MERGE_CELL_DIR@@@Z | 0x77d1d0 |
| RCtrl.dll | ?CalcGridFixedWidth@CSBaseSplitter@@MAEHPAVCSBaseSplitterGrid@@@Z | 0x77d1d4 |
| RCtrl.dll | ?SetSelTextColor@CUiTabWnd@@QAEXK@Z | 0x77d1d8 |
| RCtrl.dll | ?Optimize@CSBaseTable@@UAEXXZ | 0x77d1dc |
| RCtrl.dll | ?SetColumnWidth@CSBaseTable@@QAEXHH@Z | 0x77d1e0 |
| RCtrl.dll | ?CalcFixedWidth@CSBaseSplitter@@MAEHH@Z | 0x77d1e4 |
| RCtrl.dll | ?Split@CSBaseTable@@UAEXHH@Z | 0x77d1e8 |
| RCtrl.dll | ?SetCloseBtnImage@CUiTabWnd@@QAEXPB_W@Z | 0x77d1ec |
| RCtrl.dll | ?CalcGridFixedHeight@CSBaseSplitter@@MAEHPAVCSBaseSplitterGrid@@@Z | 0x77d1f0 |
| RCtrl.dll | ?SetRowHeight@CSBaseTable@@QAEXHH@Z | 0x77d1f4 |
| RCtrl.dll | ?Split@CSBaseTable@@UAE_NHHHH@Z | 0x77d1f8 |
| RCtrl.dll | ?SetPopMenuBtnImage@CUiTabWnd@@QAEXPB_W@Z | 0x77d1fc |
| RCtrl.dll | ?CalcFixedHeight@CSBaseSplitter@@MAEHH@Z | 0x77d200 |
| RCtrl.dll | ??0CSSplitter@@QAE@PAVCSSplitterWnd@@PAV0@@Z | 0x77d204 |
| RCtrl.dll | ?GetGrid@CSBaseTable@@QBEPAVCSBaseTableGrid@@HH@Z | 0x77d208 |
| RCtrl.dll | ?OnSetCursor@CSSplitterWnd@@QAEHPAVCWnd@@II@Z | 0x77d20c |
| RCtrl.dll | ??1CSSplitter@@UAE@XZ | 0x77d210 |
| RCtrl.dll | ?Resize@CSBaseTable@@UAEXABVCRect@@@Z | 0x77d214 |
| RCtrl.dll | ?RecalcLayout@CSSplitter@@UAEXXZ | 0x77d218 |
| RCtrl.dll | ?RecalcLayout@CSSplitterWnd@@UAEXXZ | 0x77d21c |
| RCtrl.dll | ?OnMouseMove@CSSplitterWnd@@QAEXIVCPoint@@@Z | 0x77d220 |
| RCtrl.dll | ?GetMinSize@CSBaseTable@@UBE?AVCSize@@XZ | 0x77d224 |
| RCtrl.dll | ?ClearGrid@CSSplitter@@MAEXHH@Z | 0x77d228 |
| RCtrl.dll | ?CreateView@CSSplitterWnd@@UAEPAVCView@@PAUCRuntimeClass@@PAUCCreateContext@@@Z | 0x77d22c |
| RCtrl.dll | ?HitTest@CSBaseTable@@MAEHVCPoint@@PAPAV1@H@Z | 0x77d230 |
| RCtrl.dll | ?OnLButtonDown@CSSplitterWnd@@QAEXIVCPoint@@@Z | 0x77d234 |
| RCtrl.dll | ?SetActivePane@CSSplitterWnd@@UAEXABVCPoint@@@Z | 0x77d238 |
| RCtrl.dll | ?GetViews@CSSplitter@@QAEXAAV?$vector@PAVCView@@V?$allocator@PAVCView@@@std@@@std@@@Z | 0x77d23c |
| RCtrl.dll | ?HitTest@CSBaseTable@@MAEHVCPoint@@PAPAV1@@Z | 0x77d240 |
| RCtrl.dll | ?SetActivePane@CSSplitterWnd@@UAEXXZ | 0x77d244 |
| RCtrl.dll | ?DeleteAll@CUiTabWnd@@QAEXXZ | 0x77d248 |
| RCtrl.dll | ?HitTest@CSBaseTable@@UAEHVCPoint@@@Z | 0x77d24c |
| RCtrl.dll | ?OnLButtonUp@CSSplitterWnd@@QAEXIVCPoint@@@Z | 0x77d250 |
| RCtrl.dll | ??0CStaticEx@@QAE@XZ | 0x77d254 |
| RCtrl.dll | ?StartTracking@CSBaseTable@@UAEHVCPoint@@PAPAV1@@Z | 0x77d258 |
| RCtrl.dll | ?GetActivePane@CSSplitterWnd@@UAEPAVCView@@PAPAVCSSplitter@@AAH1@Z | 0x77d25c |
| RCtrl.dll | ?StopTracking@CSBaseTable@@UAEXVCPoint@@@Z | 0x77d260 |
| RCtrl.dll | ?ClearGrid@CSBaseTable@@MAEXHH@Z | 0x77d264 |
| RCtrl.dll | ?OnViewActive@CSSplitterWnd@@QAEJIJ@Z | 0x77d268 |
| RCtrl.dll | ?GetActivePane@CSSplitterWnd@@UAEPAVCView@@PAPAVCSSplitter@@PAPAVCSSplitterGrid@@@Z | 0x77d26c |
| RCtrl.dll | ?FoldTable@CSBaseTable@@UAEXH@Z | 0x77d270 |
| RCtrl.dll | ?GetThisClass@CSSplitterWnd@@SGPAUCRuntimeClass@@XZ | 0x77d274 |
| RCtrl.dll | ?OnSplitterFold@CSSplitterWnd@@QAEJIJ@Z | 0x77d278 |
| RCtrl.dll | ?GetChildActiveView@CSSplitterWnd@@UBEPAVCWnd@@PAV2@@Z | 0x77d27c |
| RCtrl.dll | ?UnFoldTable@CSBaseTable@@UAEXH@Z | 0x77d280 |
| RCtrl.dll | ?DrawBorder@CSSplitterWnd@@MAEXPAVCDC@@@Z | 0x77d284 |
| RCtrl.dll | ??0CSSplitterWnd@@QAE@XZ | 0x77d288 |
| RCtrl.dll | ?PreTranslateMessage@CSSplitterWnd@@UAEHPAUtagMSG@@@Z | 0x77d28c |
| RCtrl.dll | ?DrawSplitter@CSSplitterWnd@@MAEXPAVCDC@@PAVCSSplitter@@@Z | 0x77d290 |
| RCtrl.dll | ?CalcGridLimitX@CSBaseTable@@MBEXPAVCSBaseTableGrid@@HAAH@Z | 0x77d294 |
| RCtrl.dll | ??1CSSplitterWnd@@UAE@XZ | 0x77d298 |
| RCtrl.dll | ?OnInvertTracker@CSSplitterWnd@@MAEXABVCRect@@@Z | 0x77d29c |
| RCtrl.dll | ?DrawSplitterGrid@CSSplitterWnd@@MAEXPAVCDC@@PAVCSSplitterGrid@@ABVCRect@@@Z | 0x77d2a0 |
| RCtrl.dll | ?CanTrackY@CSBaseTable@@MBEHH_N@Z | 0x77d2a4 |
| RCtrl.dll | ?GetRowHeight@CSBaseTable@@QAEHH@Z | 0x77d2a8 |
| RCtrl.dll | ?CalcGridLimitY@CSBaseTable@@MBEXPAVCSBaseTableGrid@@HAAH@Z | 0x77d2ac |
| RCtrl.dll | ?HitTest@CSSplitterWnd@@MAEHVCPoint@@@Z | 0x77d2b0 |
| RCtrl.dll | ?GetColumnWidth@CSBaseTable@@QAEHH@Z | 0x77d2b4 |
| RCtrl.dll | ?CanTrackX@CSBaseTable@@MBEHH_N@Z | 0x77d2b8 |
| RCtrl.dll | ??0CUiTabWnd@@QAE@XZ | 0x77d2bc |
| RCtrl.dll | ?SetSplitCursor@CSSplitterWnd@@MAEXH@Z | 0x77d2c0 |
| RCtrl.dll | ??1CUiTabWnd@@UAE@XZ | 0x77d2c4 |
| RCtrl.dll | ?StartTracking@CSSplitterWnd@@MAEXH@Z | 0x77d2c8 |
| RCtrl.dll | ?GetTabID@CUiTabWnd@@QBEIH@Z | 0x77d2cc |
| RCtrl.dll | ?StopTracking@CSSplitterWnd@@MAEXH@Z | 0x77d2d0 |
| RCtrl.dll | ?SetActivePane@CSSplitter@@QAEXPAVCSSplitterGrid@@@Z | 0x77d2d4 |
| RCtrl.dll | ?GetHitRect@CSSplitterWnd@@MAE?AVCRect@@HVCPoint@@@Z | 0x77d2d8 |
| RCtrl.dll | ?GetRect@CSBaseTable@@QBEHHHAAVCRect@@@Z | 0x77d2dc |
| RCtrl.dll | ?GetThisMessageMap@CSSplitterWnd@@KGPBUAFX_MSGMAP@@XZ | 0x77d2e0 |
| RCtrl.dll | ?PreDestroyView@CSSplitterWnd@@MAEXPAVCView@@@Z | 0x77d2e4 |
| RCtrl.dll | ?InsertRowBefore@CSBaseSplitter@@UAEHH@Z | 0x77d2e8 |
| RCtrl.dll | ?GetTrackBegin@CSBaseTable@@UBE?AVCPoint@@XZ | 0x77d2ec |
| RCtrl.dll | ?InsertColumnBefore@CSBaseSplitter@@UAEHH@Z | 0x77d2f0 |
| RCtrl.dll | ?Create@CUiTabWnd@@QAEHPAVCWnd@@IABUtagRECT@@K@Z | 0x77d2f4 |
| RCtrl.dll | ?GetTrackLimitRect@CSBaseTable@@UBE?AVCRect@@XZ | 0x77d2f8 |
| RCtrl.dll | ?Create@CSSplitterWnd@@UAE_NPAVCWnd@@AAVCRect@@PAUCCreateContext@@K@Z | 0x77d2fc |
| RCtrl.dll | ?RemoveAll@CSBaseSplitter@@UAEXXZ | 0x77d300 |
| RCtrl.dll | ?SetBkColor@CUiTabWnd@@QAEXK@Z | 0x77d304 |
| RCtrl.dll | ?AdjustLayout@CSBaseSplitter@@UAEXXZ | 0x77d308 |
| RCtrl.dll | ?InsertRowAfter@CSBaseTable@@UAEHH@Z | 0x77d30c |
| RCtrl.dll | ?SetNormalBkColor@CUiTabWnd@@QAEXK@Z | 0x77d310 |
| RCtrl.dll | ?NewChildTable@CSSplitter@@MAEPAVCSBaseTable@@XZ | 0x77d314 |
| RCtrl.dll | ?GetColumns@CSBaseTable@@QBEHXZ | 0x77d318 |
| RCtrl.dll | ?Init@CSBaseSplitter@@MAEXXZ | 0x77d31c |
| RCtrl.dll | ?SetSelBkColor@CUiTabWnd@@QAEXK@Z | 0x77d320 |
| RCtrl.dll | ?InsertColumnAfter@CSBaseTable@@UAEHH@Z | 0x77d324 |
| RCtrl.dll | ?NewGrid@CSSplitter@@MAEPAVCSBaseTableGrid@@XZ | 0x77d328 |
| RCtrl.dll | ?CalcRowsHeight@CSBaseSplitter@@MAEXXZ | 0x77d32c |
| RCtrl.dll | ?GetRows@CSBaseTable@@QBEHXZ | 0x77d330 |
| RCtrl.dll | ?AddTab@CUiTabWnd@@QAEHIABV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@_N1PB_W@Z | 0x77d334 |
| RCtrl.dll | ?SetBorderColor@CUiTabWnd@@QAEXK@Z | 0x77d338 |
| RCtrl.dll | ?RemoveRow@CSBaseTable@@UAEXH@Z | 0x77d33c |
| RCtrl.dll | ?GetMessageMap@CSTabbedPanel@@MBEPBUAFX_MSGMAP@@XZ | 0x77d340 |
| RCtrl.dll | ?SetBorderWidth@CSTabbedPanel@@QAEXH@Z | 0x77d344 |
| RCtrl.dll | ?PreSubclassWindow@CSTabbedPanel@@MAEXXZ | 0x77d348 |
| RCtrl.dll | ?SetDividerWidth@CSTabbedPanel@@QAEXH@Z | 0x77d34c |
| RCtrl.dll | ?GetItemText@CGridCtrl@@QBE?AV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@HH@Z | 0x77d350 |
| RCtrl.dll | ?SetColumnWidth@CGridCtrl@@QAEHHH@Z | 0x77d354 |
| RCtrl.dll | ?SetRowHeight@CGridCtrl@@QAEHHH@Z | 0x77d358 |
| RCtrl.dll | ?SetItemText@CGridCtrl@@QAEHHHPB_W@Z | 0x77d35c |
| RCtrl.dll | ?SetFixedColumnCount@CGridCtrl@@QAEHH@Z | 0x77d360 |
| RCtrl.dll | ?SetFixedRowCount@CGridCtrl@@QAEHH@Z | 0x77d364 |
| RCtrl.dll | ?SetRowCount@CGridCtrl@@QAEHH@Z | 0x77d368 |
| RCtrl.dll | ?SetColumnCount@CGridCtrl@@QAEHH@Z | 0x77d36c |
| RCtrl.dll | ?Create@CGridCtrl@@QAEHABUtagRECT@@PAVCWnd@@IK@Z | 0x77d370 |
| RCtrl.dll | ??1CGridCtrl@@UAE@XZ | 0x77d374 |
| RCtrl.dll | ??0CGridCtrl@@QAE@HHHH@Z | 0x77d378 |
| RCtrl.dll | ?SetActivePane@CSSplitterWnd@@UAEXPAVCView@@@Z | 0x77d37c |
| RCtrl.dll | ??0CSGifPicture@@QAE@XZ | 0x77d380 |
| RCtrl.dll | ?DrawItem@CSSheetWnd@@MAEXPAUtagSHEETITEMDRAWSTR@@@Z | 0x77d384 |
| RCtrl.dll | ?GetColumnParam@CSHeader@@QBEKH@Z | 0x77d388 |
| RCtrl.dll | ?SetVScrollPos@CSSheetWnd@@IAEXH@Z | 0x77d38c |
| RCtrl.dll | ?DrawHeader@CSSheetWnd@@MAEXPAVCDC@@ABVCRect@@@Z | 0x77d390 |
| RCtrl.dll | ?ItemIsSelected@CSSheetWnd@@IBEHH@Z | 0x77d394 |
| RCtrl.dll | ?GetDrawTextFormat@CSSheetWnd@@IBEIH@Z | 0x77d398 |
| RCtrl.dll | ??1CUiTipCtrl@@UAE@XZ | 0x77d39c |
| RCtrl.dll | ??0CUiTipCtrl@@QAE@XZ | 0x77d3a0 |
| RCtrl.dll | ?SetFont@CUiTipCtrl@@QAEXPAVCFont@@@Z | 0x77d3a4 |
| RCtrl.dll | ?Create@CUiTipCtrl@@QAEHPAVCWnd@@@Z | 0x77d3a8 |
| RCtrl.dll | ?GetRuntimeClass@CSRollSubtitlesWnd@@UBEPAUCRuntimeClass@@XZ | 0x77d3ac |
| RCtrl.dll | ??0CSRollSubtitlesWnd@@QAE@XZ | 0x77d3b0 |
| RCtrl.dll | ??1CSBitmapButton@@UAE@XZ | 0x77d3b4 |
| RCtrl.dll | ?CalcSize@CSTextSubtitlesItem@@UAEXPAVCDC@@@Z | 0x77d3b8 |
| RCtrl.dll | ??0CSBitmapButton@@QAE@XZ | 0x77d3bc |
| RCtrl.dll | ?Draw@CSTextSubtitlesItem@@UAEXPAUtagSSubtitlesItemDrawStr@@@Z | 0x77d3c0 |
| RCtrl.dll | ??1CSTextSubtitlesItem@@UAE@XZ | 0x77d3c4 |
| RCtrl.dll | ?AddItem@CSRollSubtitlesWnd@@QAEXPAVCSBaseSubtitlesItem@@@Z | 0x77d3c8 |
| RCtrl.dll | ?SetString@CSTextSubtitlesItem@@QAEXABV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@KK@Z | 0x77d3cc |
| RCtrl.dll | ??0CSTextSubtitlesItem@@QAE@XZ | 0x77d3d0 |
| RCtrl.dll | ?Start@CSRollSubtitlesWnd@@QAEXXZ | 0x77d3d4 |
| RCtrl.dll | ?SetTextColor@CSBitmapButton@@QAEXKKKK@Z | 0x77d3d8 |
| RCtrl.dll | ?Create@CSRollSubtitlesWnd@@QAEHKABUtagRECT@@PAVCWnd@@I@Z | 0x77d3dc |
| RCtrl.dll | ?SetBkColor@CSBitmapButton@@QAEXKKKK@Z | 0x77d3e0 |
| RCtrl.dll | ?SetTip@CSBitmapButton@@QAEXABV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@@Z | 0x77d3e4 |
| RCtrl.dll | ?SetItemsColor@CSRollSubtitlesWnd@@QAEXKK@Z | 0x77d3e8 |
| RCtrl.dll | ?Draw@CSRollSubtitlesWnd@@MAEXPAVCDC@@@Z | 0x77d3ec |
| RCtrl.dll | ??1CSRollSubtitlesWnd@@UAE@XZ | 0x77d3f0 |
| RCtrl.dll | ?GetMessageMap@CSRollSubtitlesWnd@@MBEPBUAFX_MSGMAP@@XZ | 0x77d3f4 |
| RCtrl.dll | ?PreCreateWindow@CSSheetWnd@@MAEHAAUtagCREATESTRUCTW@@@Z | 0x77d3f8 |
| RCtrl.dll | ?ProcessVScrollPrior@CSSheetWnd@@MAEXXZ | 0x77d3fc |
| RCtrl.dll | ??0CSSheetWnd@@QAE@XZ | 0x77d400 |
| RCtrl.dll | ?GetGridObject@CSSheetWnd@@QAEPAUtagSSBaseItemGrid@@HH@Z | 0x77d404 |
| RCtrl.dll | ?ProcessVScrollEnd@CSSheetWnd@@MAEXXZ | 0x77d408 |
| RCtrl.dll | ?OptimizeColumn@CSSheetWnd@@IAEXH_N@Z | 0x77d40c |
| RCtrl.dll | ?GetItemTextColor@CSSheetWnd@@QBEKH@Z | 0x77d410 |
| RCtrl.dll | ?ProcessVScrollHome@CSSheetWnd@@MAEXXZ | 0x77d414 |
| RCtrl.dll | ?GetThisClass@CSSheetWnd@@SGPAUCRuntimeClass@@XZ | 0x77d418 |
| RCtrl.dll | ?GetItemBkColor@CSSheetWnd@@QBEKH@Z | 0x77d41c |
| RCtrl.dll | ?SetCursor@CSSheetWnd@@MAEXH@Z | 0x77d420 |
| RCtrl.dll | ?GetItemState@CSSheetWnd@@QBEEH@Z | 0x77d424 |
| RCtrl.dll | ?ShowScrollBar@CSSheetWnd@@MAEXHH@Z | 0x77d428 |
| RCtrl.dll | ?PtInSubItem@CSSheetWnd@@IBEHVCPoint@@@Z | 0x77d42c |
| RCtrl.dll | ?GetItemVisibleRect@CSSheetWnd@@MBEHHAAVCRect@@@Z | 0x77d430 |
| RCtrl.dll | ?ClearAllSelectedItems@CSSheetWnd@@IAEXXZ | 0x77d434 |
| RCtrl.dll | ?GetVisibleItemCount@CSSheetWnd@@MBEHH_N00@Z | 0x77d438 |
| RCtrl.dll | ?CalcItemsHeight@CSSheetWnd@@MBEHHH@Z | 0x77d43c |
| RCtrl.dll | ?GetColumnVisibleRect@CSSheetWnd@@IBEHHAAVCRect@@@Z | 0x77d440 |
| RCtrl.dll | ?OnItemInvertTracker@CSSheetWnd@@MAEXABVCRect@@@Z | 0x77d444 |
| RCtrl.dll | ?DrawIcon@CSSheetWnd@@MAEXPAUtagSHEETITEMDRAWSTR@@@Z | 0x77d448 |
| RCtrl.dll | ?DrawClient@CSSheetWnd@@MAEXPAVCDC@@ABVCRect@@@Z | 0x77d44c |
| RCtrl.dll | ?HitTest@CSSheetWnd@@IBEHVCPoint@@AAH@Z | 0x77d450 |
| RCtrl.dll | ?DrawColumnInvertTrack@CSSheetWnd@@MAEXPAVCDC@@@Z | 0x77d454 |
| RCtrl.dll | ?OnCreate@CSSheetWnd@@IAEHPAUtagCREATESTRUCTW@@@Z | 0x77d458 |
| RCtrl.dll | ?InitHeader@CSSheetWnd@@MAEXXZ | 0x77d45c |
| RCtrl.dll | ?GetItemIcon@CSSheetWnd@@UBEHH@Z | 0x77d460 |
| RCtrl.dll | ?UnSelectItem@CSSheetWnd@@UAEXH@Z | 0x77d464 |
| RCtrl.dll | ?UnSelectItem@CSSheetWnd@@UAEXXZ | 0x77d468 |
| RCtrl.dll | ?GetColumnTextColor@CSSheetWnd@@QBEKH@Z | 0x77d46c |
| RCtrl.dll | ?SelectItem@CSSheetWnd@@UAEXH@Z | 0x77d470 |
| RCtrl.dll | ?GetColumnBkColor@CSSheetWnd@@QBEKH@Z | 0x77d474 |
| RCtrl.dll | ?MoveItem@CSSheetWnd@@UAEHHH@Z | 0x77d478 |
| RCtrl.dll | ?DeleteAllItems@CSSheetWnd@@UAEHXZ | 0x77d47c |
| RCtrl.dll | ?IsValidItem@CSSheetWnd@@IBE_NH@Z | 0x77d480 |
| RCtrl.dll | ?DeleteItem@CSSheetWnd@@UAEHH@Z | 0x77d484 |
| RCtrl.dll | ?InsertItem@CSSheetWnd@@UAEHHABV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@GEHKK@Z | 0x77d488 |
| RCtrl.dll | ?InsertItem@CSSheetWnd@@UAEHHPAVCSItem@@@Z | 0x77d48c |
| RCtrl.dll | ?ItemIsVisible@CSSheetWnd@@UBEHH@Z | 0x77d490 |
| RCtrl.dll | ?ItemIsVisible@CSSheetWnd@@UBEHPAVCSItem@@@Z | 0x77d494 |
| RCtrl.dll | ?CalcColumnWidth@CSSheetWnd@@IBEHH@Z | 0x77d498 |
| RCtrl.dll | ?ReleaseMemDC@CSSheetWnd@@MAEXXZ | 0x77d49c |
| RCtrl.dll | ?GetItemText@CSSheetWnd@@UBE?AV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@HH@Z | 0x77d4a0 |
| RCtrl.dll | ?CalcVisibleColumnsWidth@CSSheetWnd@@IBEH_N@Z | 0x77d4a4 |
| RCtrl.dll | ?InitMemDC@CSSheetWnd@@MAEXPAVCDC@@ABVCRect@@@Z | 0x77d4a8 |
| RCtrl.dll | ?MoveColumn@CSSheetWnd@@UAEHHH@Z | 0x77d4ac |
| RCtrl.dll | ?__Destroy@CSSheetWnd@@MAEXXZ | 0x77d4b0 |
| RCtrl.dll | ?SwapColumn@CSSheetWnd@@UAEHHH@Z | 0x77d4b4 |
| RCtrl.dll | ?GetItemTextColor@CSSheetWnd@@QBEKHH@Z | 0x77d4b8 |
| RCtrl.dll | ?ProcessHScrollRight@CSSheetWnd@@MAEXXZ | 0x77d4bc |
| RCtrl.dll | ?DeleteAllColumns@CSSheetWnd@@UAEHH@Z | 0x77d4c0 |
| RCtrl.dll | ?GetThisMessageMap@CSSheetWnd@@KGPBUAFX_MSGMAP@@XZ | 0x77d4c4 |
| RCtrl.dll | ?GetItemBkColor@CSSheetWnd@@QBEKHH@Z | 0x77d4c8 |
| RCtrl.dll | ?ProcessHScrollLeft@CSSheetWnd@@MAEXXZ | 0x77d4cc |
| RCtrl.dll | ?DeleteColumn@CSSheetWnd@@UAEHH@Z | 0x77d4d0 |
| RCtrl.dll | ?DrawGrid@CSSheetWnd@@MAEXPAUtagSHEETITEMDRAWSTR@@@Z | 0x77d4d4 |
| RCtrl.dll | ?ProcessVScrollDown@CSSheetWnd@@MAEXXZ | 0x77d4d8 |
| RCtrl.dll | ?SetColumnFormat@CSSheetWnd@@UAEHHG@Z | 0x77d4dc |
| RCtrl.dll | ?ProcessVScrollUp@CSSheetWnd@@MAEXXZ | 0x77d4e0 |
| RCtrl.dll | ?GetScrollBarCtrl@CSSheetWnd@@MBEPAVCScrollBar@@H@Z | 0x77d4e4 |
| RCtrl.dll | ?ProcessVScrollNext@CSSheetWnd@@MAEXXZ | 0x77d4e8 |
| RCtrl.dll | ??1CSSheetWnd@@UAE@XZ | 0x77d4ec |
| RCtrl.dll | ?DeleteButton@CSTabbedPanel@@QAEXH@Z | 0x77d4f0 |
| RCtrl.dll | ?FindButtonIndex@CSTabbedPanel@@QAEHH@Z | 0x77d4f4 |
| RCtrl.dll | ?GetButtonCount@CSTabbedPanel@@QAEHXZ | 0x77d4f8 |
| RCtrl.dll | ?GetColumnText@CSSheetWnd@@QBE?AV?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@H@Z | 0x77d4fc |

1,407 imports not shown; the table lists the first entries.

## Exports

| Export | Address |
| --- | --- |
| ??_B?1??get_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@CAAAVCComboSymbolTask@@XZ@51 | 0x875d3c |
| ??_B?1??get_instance@?$singleton@VCConfig@@@serialization@boost@@CAAAVCConfig@@XZ@51 | 0x875eb4 |
| ??_B?1??get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ@51 | 0x875f3c |
| ??_B?1??get_instance@?$singleton@VCFrameManager@@@serialization@boost@@CAAAVCFrameManager@@XZ@51 | 0x875a48 |
| ??_B?1??get_instance@?$singleton@VCHotKey@@@serialization@boost@@CAAAVCHotKey@@XZ@51 | 0x876548 |
| ??_B?1??get_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@CAAAVCSigNoConfig@@XZ@51 | 0x875eb0 |
| ??_B?1??get_instance@?$singleton@VCSymbolManager@@@serialization@boost@@CAAAVCSymbolManager@@XZ@51 | 0x876544 |
| ??_B?1??get_instance@?$singleton@VCTaskProc@@@serialization@boost@@CAAAVCTaskProc@@XZ@51 | 0x875d48 |
| ??_B?1??get_instance@?$singleton@VCViewManager@@@serialization@boost@@CAAAVCViewManager@@XZ@51 | 0x875dec |
| ??_B?1??get_instance@?$singleton@VChromeBrowser@@@serialization@boost@@CAAAVChromeBrowser@@XZ@51 | 0x874d50 |
| ??_B?1??get_instance@?$singleton@VColorScheme@@@serialization@boost@@CAAAVColorScheme@@XZ@51 | 0x875eb8 |
| ??_B?1??get_instance@?$singleton@VComboSymbol@@@serialization@boost@@CAAAVComboSymbol@@XZ@51 | 0x875f34 |
| ??_B?1??get_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@CAAAVTAF_AsynCalcMatrix@@XZ@51 | 0x87654c |
| ??_B?1??get_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@CAAAVTAF_AsynCalcTagging@@XZ@51 | 0x876550 |
| ??_B?1??get_instance@?$singleton@VTAF_Manager@@@serialization@boost@@CAAAVTAF_Manager@@XZ@51 | 0x876370 |
| ??_B?1??get_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@CAAAVTAF_TemplateManager@@XZ@51 | 0x875db0 |
| ??_B?1??get_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@CAAAVTAS_Alerter@@XZ@51 | 0x876420 |
| ??_B?1??get_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@CAAAVTAS_SelectorPlan@@XZ@51 | 0x875ebc |
| ??_B?1??get_instance@?$singleton@VXDrawManager@@@serialization@boost@@CAAAVXDrawManager@@XZ@51 | 0x875f30 |
| ??_B?1??get_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@CAAAV_DownloadInfo@@XZ@51 | 0x875d40 |
| ?get_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@CAAAVCComboSymbolTask@@XZ | 0x5c6ba0 |
| ?get_instance@?$singleton@VCConfig@@@serialization@boost@@CAAAVCConfig@@XZ | 0x611bc0 |
| ?get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ | 0x4dd270 |
| ?get_instance@?$singleton@VCFrameManager@@@serialization@boost@@CAAAVCFrameManager@@XZ | 0x608330 |
| ?get_instance@?$singleton@VCHotKey@@@serialization@boost@@CAAAVCHotKey@@XZ | 0x5f8970 |
| ?get_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@CAAAVCSigNoConfig@@XZ | 0x627890 |
| ?get_instance@?$singleton@VCSymbolManager@@@serialization@boost@@CAAAVCSymbolManager@@XZ | 0x584f80 |
| ?get_instance@?$singleton@VCTaskProc@@@serialization@boost@@CAAAVCTaskProc@@XZ | 0x63d2e0 |
| ?get_instance@?$singleton@VCViewManager@@@serialization@boost@@CAAAVCViewManager@@XZ | 0x573450 |
| ?get_instance@?$singleton@VChromeBrowser@@@serialization@boost@@CAAAVChromeBrowser@@XZ | 0x63d7c0 |
| ?get_instance@?$singleton@VColorScheme@@@serialization@boost@@CAAAVColorScheme@@XZ | 0x60f4b0 |
| ?get_instance@?$singleton@VComboSymbol@@@serialization@boost@@CAAAVComboSymbol@@XZ | 0x5c51d0 |
| ?get_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@CAAAVTAF_AsynCalcMatrix@@XZ | 0x5d9550 |
| ?get_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@CAAAVTAF_AsynCalcTagging@@XZ | 0x5d94d0 |
| ?get_instance@?$singleton@VTAF_Manager@@@serialization@boost@@CAAAVTAF_Manager@@XZ | 0x5e5580 |
| ?get_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@CAAAVTAF_TemplateManager@@XZ | 0x5ea080 |
| ?get_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@CAAAVTAS_Alerter@@XZ | 0x5f0130 |
| ?get_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@CAAAVTAS_SelectorPlan@@XZ | 0x5f3980 |
| ?get_instance@?$singleton@VXDrawManager@@@serialization@boost@@CAAAVXDrawManager@@XZ | 0x5d3860 |
| ?get_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@CAAAV_DownloadInfo@@XZ | 0x466280 |
| ?get_mutable_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@SAAAVCComboSymbolTask@@XZ | 0x5c6980 |
| ?get_mutable_instance@?$singleton@VCConfig@@@serialization@boost@@SAAAVCConfig@@XZ | 0x611bb0 |
| ?get_mutable_instance@?$singleton@VCEventMan@@@serialization@boost@@SAAAVCEventMan@@XZ | 0x4dcf80 |
| ?get_mutable_instance@?$singleton@VCFrameManager@@@serialization@boost@@SAAAVCFrameManager@@XZ | 0x608320 |
| ?get_mutable_instance@?$singleton@VCHotKey@@@serialization@boost@@SAAAVCHotKey@@XZ | 0x5f83a0 |
| ?get_mutable_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@SAAAVCSigNoConfig@@XZ | 0x6273a0 |
| ?get_mutable_instance@?$singleton@VCSymbolManager@@@serialization@boost@@SAAAVCSymbolManager@@XZ | 0x584cf0 |
| ?get_mutable_instance@?$singleton@VCTaskProc@@@serialization@boost@@SAAAVCTaskProc@@XZ | 0x63d2b0 |
| ?get_mutable_instance@?$singleton@VCViewManager@@@serialization@boost@@SAAAVCViewManager@@XZ | 0x573390 |
| ?get_mutable_instance@?$singleton@VChromeBrowser@@@serialization@boost@@SAAAVChromeBrowser@@XZ | 0x63d7c0 |
| ?get_mutable_instance@?$singleton@VColorScheme@@@serialization@boost@@SAAAVColorScheme@@XZ | 0x60eef0 |
| ?get_mutable_instance@?$singleton@VComboSymbol@@@serialization@boost@@SAAAVComboSymbol@@XZ | 0x5c4e00 |
| ?get_mutable_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@SAAAVTAF_AsynCalcMatrix@@XZ | 0x5d9140 |
| ?get_mutable_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@SAAAVTAF_AsynCalcTagging@@XZ | 0x5d9130 |
| ?get_mutable_instance@?$singleton@VTAF_Manager@@@serialization@boost@@SAAAVTAF_Manager@@XZ | 0x5e47e0 |
| ?get_mutable_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@SAAAVTAF_TemplateManager@@XZ | 0x5e9fe0 |
| ?get_mutable_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@SAAAVTAS_Alerter@@XZ | 0x5efa50 |
| ?get_mutable_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@SAAAVTAS_SelectorPlan@@XZ | 0x5f3800 |
| ?get_mutable_instance@?$singleton@VXDrawManager@@@serialization@boost@@SAAAVXDrawManager@@XZ | 0x5d3850 |
| ?get_mutable_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@SAAAV_DownloadInfo@@XZ | 0x465d40 |
| ?instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@0AAVCComboSymbolTask@@A | 0x876574 |
| ?instance@?$singleton@VCConfig@@@serialization@boost@@0AAVCConfig@@A | 0x8765a0 |
| ?instance@?$singleton@VCEventMan@@@serialization@boost@@0AAVCEventMan@@A | 0x876564 |
| ?instance@?$singleton@VCFrameManager@@@serialization@boost@@0AAVCFrameManager@@A | 0x876598 |
| ?instance@?$singleton@VCHotKey@@@serialization@boost@@0AAVCHotKey@@A | 0x876594 |
| ?instance@?$singleton@VCSigNoConfig@@@serialization@boost@@0AAVCSigNoConfig@@A | 0x8765a4 |
| ?instance@?$singleton@VCSymbolManager@@@serialization@boost@@0AAVCSymbolManager@@A | 0x87656c |
| ?instance@?$singleton@VCTaskProc@@@serialization@boost@@0AAVCTaskProc@@A | 0x8765a8 |
| ?instance@?$singleton@VCViewManager@@@serialization@boost@@0AAVCViewManager@@A | 0x876568 |
| ?instance@?$singleton@VChromeBrowser@@@serialization@boost@@0AAVChromeBrowser@@A | 0x8765ac |
| ?instance@?$singleton@VColorScheme@@@serialization@boost@@0AAVColorScheme@@A | 0x87659c |
| ?instance@?$singleton@VComboSymbol@@@serialization@boost@@0AAVComboSymbol@@A | 0x876570 |
| ?instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@0AAVTAF_AsynCalcMatrix@@A | 0x87657c |
| ?instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@0AAVTAF_AsynCalcTagging@@A | 0x876580 |
| ?instance@?$singleton@VTAF_Manager@@@serialization@boost@@0AAVTAF_Manager@@A | 0x876584 |
| ?instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@0AAVTAF_TemplateManager@@A | 0x876588 |
| ?instance@?$singleton@VTAS_Alerter@@@serialization@boost@@0AAVTAS_Alerter@@A | 0x87658c |
| ?instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@0AAVTAS_SelectorPlan@@A | 0x876590 |
| ?instance@?$singleton@VXDrawManager@@@serialization@boost@@0AAVXDrawManager@@A | 0x876578 |
| ?instance@?$singleton@V_DownloadInfo@@@serialization@boost@@0AAV_DownloadInfo@@A | 0x876558 |
| ?t@?1??get_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@CAAAVCComboSymbolTask@@XZ@4V?$singleton_wrapper@VCComboSymbolTask@@@detail@34@A | 0x874968 |
| ?t@?1??get_instance@?$singleton@VCConfig@@@serialization@boost@@CAAAVCConfig@@XZ@4V?$singleton_wrapper@VCConfig@@@detail@34@A | 0x874e80 |
| ?t@?1??get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ@4V?$singleton_wrapper@VCEventMan@@@detail@34@A | 0x874e54 |
| ?t@?1??get_instance@?$singleton@VCFrameManager@@@serialization@boost@@CAAAVCFrameManager@@XZ@4V?$singleton_wrapper@VCFrameManager@@@detail@34@A | 0x874934 |
| ?t@?1??get_instance@?$singleton@VCHotKey@@@serialization@boost@@CAAAVCHotKey@@XZ@4V?$singleton_wrapper@VCHotKey@@@detail@34@A | 0x875f40 |
| ?t@?1??get_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@CAAAVCSigNoConfig@@XZ@4V?$singleton_wrapper@VCSigNoConfig@@@detail@34@A | 0x875df0 |
| ?t@?1??get_instance@?$singleton@VCSymbolManager@@@serialization@boost@@CAAAVCSymbolManager@@XZ@4V?$singleton_wrapper@VCSymbolManager@@@detail@34@A | 0x876378 |
| ?t@?1??get_instance@?$singleton@VCTaskProc@@@serialization@boost@@CAAAVCTaskProc@@XZ@4V?$singleton_wrapper@VCTaskProc@@@detail@34@A | 0x874d54 |
| ?t@?1??get_instance@?$singleton@VCViewManager@@@serialization@boost@@CAAAVCViewManager@@XZ@4V?$singleton_wrapper@VCViewManager@@@detail@34@A | 0x875a4c |
| ?t@?1??get_instance@?$singleton@VChromeBrowser@@@serialization@boost@@CAAAVChromeBrowser@@XZ@4V?$singleton_wrapper@VChromeBrowser@@@detail@34@A | 0x8748fc |
| ?t@?1??get_instance@?$singleton@VColorScheme@@@serialization@boost@@CAAAVColorScheme@@XZ@4V?$singleton_wrapper@VColorScheme@@@detail@34@A | 0x875d50 |
| ?t@?1??get_instance@?$singleton@VComboSymbol@@@serialization@boost@@CAAAVComboSymbol@@XZ@4V?$singleton_wrapper@VComboSymbol@@@detail@34@A | 0x8749b0 |
| ?t@?1??get_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@CAAAVTAF_AsynCalcMatrix@@XZ@4V?$singleton_wrapper@VTAF_AsynCalcMatrix@@@detail@34@A | 0x876428 |
| ?t@?1??get_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@CAAAVTAF_AsynCalcTagging@@XZ@4V?$singleton_wrapper@VTAF_AsynCalcTagging@@@detail@34@A | 0x8764b8 |
| ?t@?1??get_instance@?$singleton@VTAF_Manager@@@serialization@boost@@CAAAVTAF_Manager@@XZ@4V?$singleton_wrapper@VTAF_Manager@@@detail@34@A | 0x875ec0 |
| ?t@?1??get_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@CAAAVTAF_TemplateManager@@XZ@4V?$singleton_wrapper@VTAF_TemplateManager@@@detail@34@A | 0x875d24 |
| ?t@?1??get_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@CAAAVTAS_Alerter@@XZ@4V?$singleton_wrapper@VTAS_Alerter@@@detail@34@A | 0x874d80 |
| ?t@?1??get_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@CAAAVTAS_SelectorPlan@@XZ@4V?$singleton_wrapper@VTAS_SelectorPlan@@@detail@34@A | 0x875d94 |
| ?t@?1??get_instance@?$singleton@VXDrawManager@@@serialization@boost@@CAAAVXDrawManager@@XZ@4V?$singleton_wrapper@VXDrawManager@@@detail@34@A | 0x875db4 |
| ?t@?1??get_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@CAAAV_DownloadInfo@@XZ@4V?$singleton_wrapper@V_DownloadInfo@@@detail@34@A | 0x875984 |

## Strings and Indicators

Observed: 15,234 printable strings (14669 ASCII, 565 UTF-16LE).

### Indicators

| Type | Value | File offset |
| --- | --- | --- |
| Windows path | D:\boost_1_55_0\boost/property_tree/detail/ptree_implementation.hpp | 0x3c3e10 |
| Windows path | D:\boost_1_55_0\boost/property_tree/xml_parser.hpp | 0x3c4230 |
| Windows path | D:\boost_1_55_0\boost/property_tree/detail/xml_parser_read_rapidxml.hpp | 0x3c45d8 |
| Windows path | D:\boost_1_55_0\boost/property_tree/string_path.hpp | 0x3c49a0 |
| Windows path | C:\Program Files (x86)\Microsoft Visual Studio 8\VC\atlmfc\include\afxwin1.inl | 0x3c59b0 |
| Windows path | D:\boost_1_55_0\boost/property_tree/detail/xml_parser_write.hpp | 0x3c9c50 |
| Windows path | ljm:\ | 0x3cd001 |
| Windows path | D:\boost_1_55_0\boost/property_tree/detail/json_parser_read.hpp | 0x3d0c50 |
| URL | https://www.baidu.com/ | 0x3d6e64 |
| Windows path | d:\RLD\pro\RNF_X\release\MainApp.pdb | 0x3f71b8 |
| URL | http://www.iec.ch | 0x45a360 |

### String Sample

````text
0038fc20  CXIMAGE_MAX_MEMORY exceeded
0038fd20  null file handler
0038fd34  Decode: Unknown or wrong format
003900d8  Unable to allocate TIFF palette
003900f8  Too big palette to handle
0039012c  No space for raster buffer
00390168  Cancelled
0039019c  Error: page not present in TIFF file
003901c4  Error encountered while opening TIFF file
003901f4  error: too many components
00390220  error: cannot allocate memory
00390288  error: cannot load image data
003902a8  error: unknowm format
003902c0  error: cannot open standard input
003902e4  cannot initialize jasper
00390300  CxImagePSD: psd_main_loop failed
00390324  CxImagePSD: psd_status_malloc_failed
0039034c  CxImageRAW: missing raw decoder
0039036c  CxImageRAW: not a raw image
00390388  CxImageRAW: unknown option
003903a4  CxImageRAW
003903bc  corrupted WMF
00390418  PCX_PlanesToPixels: more than 4 planes or more than 1 bit per pixel
003904a4  bad color map signature
003904bc  corrupted PCX
003904cc  repeat count spans end of image
00390518  PCX file has unknown encoding scheme
00390540  Error: Not a PCX file
00390570  Unknown TGA image type
00390588  corrupted TGA
00390598  TGA Create failed
003905ac  bad TGA header
003905bc  Not a TGA
003905d0  CxImageMNG::Decode cannot create image
003905f8  Error: frame not present in MNG file
00390620  Error in MNG file
0039065c  unknown PNG color type
00390674  Failed to initialize PNG info structure
0039069c  Failed to create PNG structure
00390768  unknown compression
0039077c  Error reading BMP info
00390794  Not a BMP
003907a0  TIFF IMAGE
003907e0  Illegal subdirectory link
003907fc  Illegal pointer offset value in EXIF.
00390824  Illegal format code in EXIF dir
00390874  Illegally sized directory
003908cc  Invalid Exif alignment marker.
00390904  Incorrect Exif header
00390938  could not read the rest of the image
00390960  could not allocate data for entire image
0039098c  Premature end of file?
003909a4  Could not allocate memory
003909c0  invalid marker
003909d0  too many padding bytes
003909e8  Too many sections in jpg file
00390a58  windows936
00390a64  windows932
00390a70  windows874
00390a7c  windows1257
00390a88  windows1256
00390a94  windows1255
00390aa0  windows1254
00390aac  windows1253
00390ab8  windows1252
00390ac4  windows1251
00390ad0  windows1250
00390af4  shiftjis
00390b18  iso88599
00390b24  iso88598
00390b30  iso88597
00390b3c  iso88596
00390b48  iso88595
00390b54  iso88594
00390b60  iso88593
00390b6c  iso88592
00390b78  iso885915
00390b84  iso885913
00390b90  iso88591
00390b9c  iso2022kr
00390ba8  iso2022jp
00390c50  Conversion failed
00390c70  Invalid or unsupported charset:
00390e78  CreateHardLinkW
00390ec0  unknown error
00390f34  Unknown error
00391038    The error occurred while parsing the regular expression fragment: '
00391080    The error occurred while parsing the regular expression: '
0039117c  Unterminated \Q...\E sequence.
003911a8  Encountered a forward reference to a marked sub-expression that does not exist.
003911f8  Encountered a forward reference to a recursive sub-expression that does not exist.
003913d0  Nothing to repeat.
003913e4  Missing } in quantified repetition.
00391460  Encountered an infinite recursion.
00391484  Octal escape sequence is invalid.
003914a8  Invalid octal escape sequence.
003914c8  Escape sequence did not encode a valid character.
003914fc  Hexadecimal escape sequence was invalid.
00391528  Missing } in hexadecimal escape sequence.
00391554  Hexadecimal escape sequence terminated prematurely.
00391588  ASCII escape sequence terminated prematurely.
003915b8  Escape sequence terminated prematurely.
00391620  Invalid regular expression object
00391660  Escape sequence was neither a valid property nor a valid character class name.
003916b0  Closing } missing from property escape sequence.
003916e4  Incomplete property escape found.
00391708  Incomplete escape sequence found.
0039172c  Incomplete \g escape found.
00391748  Character class declaration starting with [ terminated prematurely - either no ] was found or the set had no c...
003917c8  Character set declaration starting with [ terminated prematurely - either no ] was found or the set had no con...
0039183c  Alternation operators are not allowed inside a DEFINE block.
003918d8  A repetition operator cannot be applied to a zero-width assertion.
00391978  Unterminated named capture.
0039199c  An invalid or unterminated recursive sub-expression.
003919d8  The recursive sub-expression refers to an invalid marking group, or is unterminated.
00391aa4  Found a closing repetition operator } with no corresponding {.
00391b1c  Unable to open message catalog: 
00391bf8  Invalid lookbehind assertion encountered in the regular expression.
00391d10  Error in thread safety code: could not acquire a lock
00391eec  vertical-line
00391efc  left-curly-bracket
00391f74  grave-accent
00391f84  underscore
00391f90  circumflex
00391f9c  right-square-bracket
00391fc0  left-square-bracket
0039202c  commercial-at
0039203c  question-mark
0039204c  greater-than-sign
00392060  equals-sign
0039206c  less-than-sign
0039207c  semicolon
003920f4  plus-sign
00392100  asterisk
0039210c  right-parenthesis
00392120  left-parenthesis
00392134  apostrophe
00392140  ampersand
0039214c  percent-sign
0039215c  dollar-sign
00392168  number-sign
00392174  quotation-mark
00392184  exclamation-mark
003921e8  carriage-return
003921f8  form-feed
00392204  vertical-tab
003922e0  Unknown error.
003922f8  No match
00392304  Invalid regular expression.
00392320  Invalid collation character.
````

## Code Analysis

Derived: 32-bit recursive descent recovered 583 functions and 27,215 instructions.

### Largest Functions

| Function | Address | Instructions | Callers | Callees | Imports used |
| --- | --- | --- | --- | --- | --- |
| sub_60b550 | 0x60b550 | 2550 | 1 | 5 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ, ??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV01@PBD@Z, _invalid_parameter_noinfo |
| sub_584970 | 0x584970 | 263 | 1 | 7 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_5e42e0 | 0x5e42e0 | 257 | 1 | 7 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ, ORDINAL 764, _CxxThrowException |
| sub_5069d0 | 0x5069d0 | 254 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_5b0180 | 0x5b0180 | 254 | 1 | 7 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_573040 | 0x573040 | 252 | 1 | 7 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ, ORDINAL 764, _CxxThrowException |
| sub_627940 | 0x627940 | 251 | 1 | 9 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_4dd6d0 | 0x4dd6d0 | 247 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_5e3990 | 0x5e3990 | 247 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_5e3ee0 | 0x5e3ee0 | 247 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_5e6990 | 0x5e6990 | 247 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_5ef4e0 | 0x5ef4e0 | 247 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_5f9360 | 0x5f9360 | 247 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_633610 | 0x633610 | 247 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_466a30 | 0x466a30 | 246 | 1 | 7 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ, ORDINAL 764, _CxxThrowException |
| sub_4b5ab0 | 0x4b5ab0 | 246 | 1 | 7 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ, ORDINAL 764, _CxxThrowException |
| sub_6229f0 | 0x6229f0 | 246 | 1 | 7 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ, ORDINAL 764, _CxxThrowException |
| sub_60fe40 | 0x60fe40 | 244 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ, ORDINAL 764, _CxxThrowException |
| sub_6102c0 | 0x6102c0 | 244 | 1 | 9 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_62a0c0 | 0x62a0c0 | 239 | 1 | 9 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_6339e0 | 0x6339e0 | 239 | 1 | 9 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_506d20 | 0x506d20 | 238 | 1 | 9 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |
| sub_4655a0 | 0x4655a0 | 237 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ, ORDINAL 764, _CxxThrowException |
| sub_4b57e0 | 0x4b57e0 | 237 | 1 | 8 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ, ORDINAL 764, _CxxThrowException |
| sub_5f08a0 | 0x5f08a0 | 236 | 1 | 7 | ??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z, ORDINAL 764, _CxxThrowException |

## Key Functions

Inferred: functions are ranked by the capability-relevant APIs they call and the indicators they reference. Listings use Intel syntax with imports, functions, and strings resolved in comments.

### sub_60b550 at 0x60b550

- References text "Default"
- References text "ViewBorder"
- References text "FloatBk"
- References text "FloatText"
- References text "FloatBar"
- References text "White"
- References text "Green"
- References text "Title"

````text
0060b550  push 0xffffffff
0060b552  push 0x74f4dc
0060b557  mov eax, fs:[0]
0060b55d  push eax
0060b55e  sub esp, 0x40
0060b561  push ebx
0060b562  push ebp
0060b563  push esi
0060b564  push edi
0060b565  mov eax, [0x858220]
0060b56a  xor eax, esp
0060b56c  push eax
0060b56d  lea eax, [esp+0x54]
0060b571  mov fs:[0], eax
0060b577  mov edi, [esp+0x64]
0060b57b  push 0x7c31c7
0060b580  mov ecx, edi
0060b582  call dword ptr [0x77cd7c]  ; MSVCP80.dll!??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z
0060b588  xor eax, eax
0060b58a  lea esi, [edi+0x1c]
0060b58d  mov [esp+0x5c], eax
0060b591  mov [esi+4], eax
0060b594  mov [esi+8], eax
0060b597  mov [esi+0xc], eax
0060b59a  lea ebp, [edi+0x2c]
0060b59d  mov ebx, 1
0060b5a2  mov ecx, ebp
0060b5a4  mov [esp+0x5c], bl
0060b5a8  call 0x006101d0
0060b5ad  mov [ebp+4], eax
0060b5b0  mov [eax+0x2d], bl
0060b5b3  mov eax, [ebp+4]
0060b5b6  mov [eax+4], eax
0060b5b9  mov eax, [ebp+4]
0060b5bc  mov [eax], eax
0060b5be  mov eax, [ebp+4]
0060b5c1  mov [eax+8], eax
0060b5c4  mov dword ptr [ebp+8], 0
0060b5cb  lea ebp, [edi+0x38]
0060b5ce  mov ecx, ebp
0060b5d0  mov byte ptr [esp+0x5c], 2
0060b5d5  call 0x00610650
0060b5da  mov [ebp+4], eax
0060b5dd  mov [eax+0x45], bl
0060b5e0  mov eax, [ebp+4]
0060b5e3  mov [eax+4], eax
0060b5e6  mov eax, [ebp+4]
0060b5e9  mov [eax], eax
0060b5eb  mov eax, [ebp+4]
0060b5ee  mov [eax+8], eax
0060b5f1  mov dword ptr [ebp+8], 0
0060b5f8  mov eax, esi
0060b5fa  mov byte ptr [esp+0x5c], 3
0060b5ff  call 0x0060ef60
0060b604  mov eax, [esi+4]
0060b607  test eax, eax
0060b609  je short 0x0060b618
0060b60b  mov ecx, [esi+8]
0060b60e  sub ecx, eax
0060b610  sar ecx, 2
````

### sub_460da0 at 0x460da0

- Calls fopen (File system)
- References text "%s\DownloadInfo.dn"

````text
00460da0  push ebp
00460da1  mov ebp, esp
00460da3  and esp, 0xfffffff8
00460da6  push 0xffffffff
00460da8  push 0x7421c9
00460dad  mov eax, fs:[0]
00460db3  push eax
00460db4  sub esp, 0x80
00460dba  mov eax, [0x858220]
00460dbf  xor eax, esp
00460dc1  mov [esp+0x78], eax
00460dc5  push ebx
00460dc6  push esi
00460dc7  push edi
00460dc8  mov eax, [0x858220]
00460dcd  xor eax, esp
00460dcf  push eax
00460dd0  lea eax, [esp+0x90]
00460dd7  mov fs:[0], eax
00460ddd  mov eax, [0x875984]
00460de2  mov edx, [eax+4]
00460de5  mov ecx, 0x875984
00460dea  mov dword ptr [esp+0x2c], 0x875984
00460df2  call edx
00460df4  xor edi, edi
00460df6  mov [esp+0x98], edi
00460dfd  cmp byte ptr [0x87598c], 0
00460e04  je short 0x00460e25
00460e06  mov dword ptr [esp+0x98], 0xffffffff
00460e11  mov eax, [0x875984]
00460e16  mov edx, [eax+0xc]
00460e19  mov ecx, 0x875984
00460e1e  call edx
00460e20  jmp 0x004610bc
00460e25  mov eax, [0x875994]
00460e2a  mov bl, 1
00460e2c  mov [0x87598c], bl
00460e32  mov ecx, [eax+4]
00460e35  push ecx
00460e36  mov ecx, 0x875990
00460e3b  call 0x00466200
00460e40  mov eax, [0x875994]
00460e45  mov [eax+4], eax
00460e48  mov eax, [0x875994]
00460e4d  mov [0x875998], edi
00460e53  mov [eax], eax
00460e55  mov eax, [0x875994]
00460e5a  lea edx, [esp+0x30]
00460e5e  push edx
00460e5f  mov [eax+8], eax
00460e62  call dword ptr [0x77d144]  ; RCommon.dll!?GetUserPath@XPath@@SA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
00460e68  add esp, 4
00460e6b  mov esi, 0x10
00460e70  mov [esp+0x98], bl
00460e77  cmp [eax+0x18], esi
00460e7a  jb short 0x00460e81
00460e7c  mov eax, [eax+4]
00460e7f  jmp short 0x00460e84
00460e81  add eax, 4
00460e84  push eax
````

### sub_461120 at 0x461120

- Calls fopen (File system)
- References text "%s\DownloadInfo.dn"

````text
00461120  push ebp
00461121  mov ebp, esp
00461123  and esp, 0xfffffff8
00461126  push 0xffffffff
00461128  push 0x73d713
0046112d  mov eax, fs:[0]
00461133  push eax
00461134  sub esp, 0x64
00461137  mov eax, [0x858220]
0046113c  xor eax, esp
0046113e  mov [esp+0x5c], eax
00461142  push ebx
00461143  push esi
00461144  mov eax, [0x858220]
00461149  xor eax, esp
0046114b  push eax
0046114c  lea eax, [esp+0x70]
00461150  mov fs:[0], eax
00461156  mov eax, [edi]
00461158  mov edx, [eax+4]
0046115b  mov ecx, edi
0046115d  mov [esp+0x2c], edi
00461161  call edx
00461163  push 0
00461165  lea ecx, [esp+0x10]
00461169  mov dword ptr [esp+0x7c], 0
00461171  call dword ptr [0x77de3c]  ; rld_lib.dll!??0binwriter@rld@@QAE@I@Z
00461177  mov byte ptr [esp+0x78], 1
0046117c  cmp byte ptr [edi+8], 0
00461180  lea ecx, [esp+0xc]
00461184  jne short 0x004611a9
00461186  mov byte ptr [esp+0x78], 0
0046118b  call dword ptr [0x77de38]  ; rld_lib.dll!??1binwriter@rld@@UAE@XZ
00461191  mov dword ptr [esp+0x78], 0xffffffff
00461199  mov eax, [edi]
0046119b  mov edx, [eax+0xc]
0046119e  mov ecx, edi
004611a0  call edx
004611a2  xor al, al
004611a4  jmp 0x0046133e
004611a9  mov ebx, [0x77de34]  ; rld_lib.dll!?write@binwriter@rld@@QAE_NI@Z
004611af  mov esi, [edi+0x14]
004611b2  push 0xe870001
004611b7  call ebx
004611b9  test al, al
004611bb  lea ecx, [esp+0xc]
004611bf  je short 0x00461186
004611c1  push esi
004611c2  call ebx
004611c4  test al, al
004611c6  jne short 0x004611ce
004611c8  lea ecx, [esp+0xc]
004611cc  jmp short 0x00461186
004611ce  mov eax, [edi+0x10]
004611d1  mov ebx, [eax]
004611d3  lea esi, [edi+0xc]
004611d6  mov [esp+0x20], ebx
004611da  mov [esp+0x1c], esi
004611de  mov edi, edi
004611e0  test esi, esi
````

### sub_637190 at 0x637190

- Calls fopen (File system)
- References text "\user.bin"

````text
00637190  push ebp
00637191  mov ebp, esp
00637193  and esp, 0xfffffff8
00637196  push 0xffffffff
00637198  push 0x73e606
0063719d  mov eax, fs:[0]
006371a3  push eax
006371a4  sub esp, 0x90
006371aa  mov eax, [0x858220]
006371af  xor eax, esp
006371b1  mov [esp+0x88], eax
006371b8  push ebx
006371b9  push esi
006371ba  push edi
006371bb  mov eax, [0x858220]
006371c0  xor eax, esp
006371c2  push eax
006371c3  lea eax, [esp+0xa0]
006371ca  mov fs:[0], eax
006371d0  mov esi, ecx
006371d2  push 0
006371d4  lea ecx, [esp+0x1c]
006371d8  call dword ptr [0x77de3c]  ; rld_lib.dll!??0binwriter@rld@@QAE@I@Z
006371de  mov dword ptr [esp+0xa8], 0
006371e9  mov edi, [0x77de2c]  ; rld_lib.dll!?write@binwriter@rld@@QAE_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
006371ef  push esi
006371f0  lea ecx, [esp+0x1c]
006371f4  call edi
006371f6  test al, al
006371f8  lea ecx, [esp+0x18]
006371fc  jne short 0x00637216
006371fe  mov dword ptr [esp+0xa8], 0xffffffff
00637209  call dword ptr [0x77de38]  ; rld_lib.dll!??1binwriter@rld@@UAE@XZ
0063720f  xor al, al
00637211  jmp 0x006374e7
00637216  lea eax, [esi+0x1c]
00637219  push eax
0063721a  call edi
0063721c  test al, al
0063721e  je 0x00637452
00637224  mov ecx, [esi+0x38]
00637227  mov edi, [0x77de1c]  ; rld_lib.dll!?write@binwriter@rld@@QAE_NH@Z
0063722d  push ecx
0063722e  lea ecx, [esp+0x1c]
00637232  call edi
00637234  test al, al
00637236  lea ecx, [esp+0x18]
0063723a  je short 0x006371fe
0063723c  mov edx, [esi+0x3c]
0063723f  push edx
00637240  call edi
00637242  test al, al
00637244  je 0x00637452
0063724a  mov ecx, [esi+0x44]
0063724d  test ecx, ecx
0063724f  jne short 0x00637255
00637251  xor eax, eax
00637253  jmp short 0x0063725a
00637255  mov eax, [esi+0x48]
00637258  sub eax, ecx
````

### entry at 0x65272f

- Program entry point

````text
0065272f  call 0x00652da0
00652734  jmp 0x00652473
````

### sub_652739 at 0x652739

- Calls IsDebuggerPresent (Anti-analysis)

````text
00652739  cmp ecx, [0x858220]
0065273f  jne short 0x00652743
00652741  rep ret
00652743  jmp 0x00652e34
00652748  push 0x14
0065274a  push 0x807630
0065274f  call 0x00652cf8
00652754  push dword ptr [0x87c678]
0065275a  mov esi, [0x77ceac]  ; MSVCR80.dll!_decode_pointer
00652760  call esi
00652762  pop ecx
00652763  mov [ebp-0x1c], eax
00652766  cmp eax, 0xffffffff
00652769  jne short 0x00652777
0065276b  push dword ptr [ebp+8]
0065276e  call dword ptr [0x77ceb0]  ; MSVCR80.dll!_onexit
00652774  pop ecx
00652775  jmp short 0x006527de
00652777  push 8
00652779  call 0x00652f44  ; j__lock
0065277e  pop ecx
0065277f  and dword ptr [ebp-4], 0
00652783  push dword ptr [0x87c678]
00652789  call esi
0065278b  mov [ebp-0x1c], eax
0065278e  push dword ptr [0x87c674]
00652794  call esi
00652796  pop ecx
00652797  pop ecx
00652798  mov [ebp-0x20], eax
0065279b  lea eax, [ebp-0x20]
0065279e  push eax
0065279f  lea eax, [ebp-0x1c]
006527a2  push eax
006527a3  push dword ptr [ebp+8]
006527a6  mov esi, [0x77cec4]  ; MSVCR80.dll!_encode_pointer
006527ac  call esi
006527ae  pop ecx
006527af  push eax
006527b0  call 0x00652f3e  ; j___dllonexit
006527b5  mov [ebp-0x24], eax
006527b8  push dword ptr [ebp-0x1c]
006527bb  call esi
006527bd  mov [0x87c678], eax
006527c2  push dword ptr [ebp-0x20]
006527c5  call esi
006527c7  add esp, 0x14
006527ca  mov [0x87c674], eax
006527cf  mov dword ptr [ebp-4], 0xfffffffe
006527d6  call 0x006527e4
006527db  mov eax, [ebp-0x24]
006527de  call 0x00652d3d
006527e3  ret
006527e4  push 8
006527e6  call 0x00652f38  ; j__unlock
006527eb  pop ecx
006527ec  ret
006527ed  push dword ptr [esp+4]
006527f1  call 0x00652748
006527f6  neg eax
````

## Assembly Walkthrough & Instruction Analysis

Observed: complete disassembly of every recovered function. Each function shows the full raw assembler listing first, followed by a plain-language summary of what the function actually does, and dual code/data analysis of any embedded literal pools.

### sub_401080 at 0x401080 (35 instructions)

````text
0x401080: cmp dword ptr [esi+4],0
0x401084: je short 004010EBh
0x401086: mov eax,[esi+10h]
0x401089: push eax
0x40108a: call dword ptr ds:[77C228h]
0x401090: cmp byte ptr [esi+18h],0
0x401094: jne short 004010EBh
0x401096: mov ecx,[esi+4]
0x401099: push 2710h
0x40109e: push ecx
0x40109f: call dword ptr ds:[77C220h]
0x4010a5: cmp eax,102h
0x4010aa: jne short 004010B8h
0x4010ac: mov edx,[esi+4]
0x4010af: push 0FFFFFF9Ch
0x4010b1: push edx
0x4010b2: call dword ptr ds:[77C224h]
0x4010b8: mov eax,[esi+4]
0x4010bb: test eax,eax
0x4010bd: je short 004010EBh
0x4010bf: push edi
0x4010c0: mov edi,ds:[77C234h]
0x4010c6: push eax
0x4010c7: call edi
0x4010c9: mov eax,[esi+10h]
0x4010cc: push eax
0x4010cd: mov dword ptr [esi+4],0
0x4010d4: call edi
0x4010d6: mov ecx,[esi+14h]
0x4010d9: push ecx
0x4010da: call edi
0x4010dc: mov dword ptr [esi+14h],0
0x4010e3: mov dword ptr [esi+10h],0
0x4010ea: pop edi
0x4010eb: ret
````

`sub_401080` is called by sub_4dc5a0, sub_585a40, sub_5ea9c0, sub_77b400, sub_77b420. It calls nothing else.

### sub_401230 at 0x401230 (27 instructions)

````text
0x401230: push 0FFFFFFFFh
0x401232: push 73A809h
0x401237: mov eax,fs:[0]
0x40123d: push eax
0x40123e: push ecx
0x40123f: push esi
0x401240: mov eax,ds:[858220h]
0x401245: xor eax,esp
0x401247: push eax
0x401248: lea eax,[esp+0Ch]
0x40124c: mov fs:[0],eax
0x401252: mov esi,ecx
0x401254: mov [esp+8],esi
0x401258: call dword ptr ds:[77D114h]
0x40125e: mov eax,[esp+1Ch]
0x401262: mov dword ptr [esp+14h],0
0x40126a: push eax
0x40126b: lea ecx,[esi+0Ch]
0x40126e: mov dword ptr [esi],78FFE0h
0x401274: call dword ptr ds:[77CD78h]
0x40127a: mov eax,esi
0x40127c: mov ecx,[esp+0Ch]
0x401280: mov fs:[0],ecx
0x401287: pop ecx
0x401288: pop esi
0x401289: add esp,10h
0x40128c: ret 4
````

`sub_401230` is called by sub_42d310, sub_4655a0, sub_466710, sub_466a30, sub_4b4b50, sub_4b5020, sub_4b57e0, sub_4b5ab0, sub_4dd6d0, sub_5069d0, sub_506d20, sub_573040, sub_584970, sub_5b0180, sub_5c5310, sub_5e3990, sub_5e3ee0, sub_5e42e0, sub_5e6990, sub_5ef4e0, sub_5f08a0, sub_5f9360, sub_60b1c0, sub_60f810, sub_60fc20, sub_60fe40, sub_6102c0, sub_6229f0, sub_627940, sub_62a0c0, sub_633610, sub_6339e0, sub_639ff0, sub_63a1a0. It calls nothing else.

### sub_401f60 at 0x401f60 (23 instructions)

````text
0x401f60: push esi
0x401f61: mov esi,[ebx+4]
0x401f64: test esi,esi
0x401f66: je short 00401F8Dh
0x401f68: push edi
0x401f69: mov edi,[ebx+8]
0x401f6c: cmp esi,edi
0x401f6e: je short 00401F80h
0x401f70: lea ecx,[esi+0Ch]
0x401f73: call dword ptr ds:[77CD74h]
0x401f79: add esi,28h
0x401f7c: cmp esi,edi
0x401f7e: jne short 00401F70h
0x401f80: mov eax,[ebx+4]
0x401f83: push eax
0x401f84: call 006516BAh
0x401f89: add esp,4
0x401f8c: pop edi
0x401f8d: mov dword ptr [ebx+4],0
0x401f94: mov dword ptr [ebx+8],0
0x401f9b: mov dword ptr [ebx+0Ch],0
0x401fa2: pop esi
0x401fa3: ret
````

`sub_401f60` is called by sub_620570. It delegates to j_ORDINAL 764 (1 callees).

### sub_403510 at 0x403510 (33 instructions)

````text
0x403510: push 0FFFFFFFFh
0x403512: push 73A76Ch
0x403517: mov eax,fs:[0]
0x40351d: push eax
0x40351e: push ebx
0x40351f: push esi
0x403520: push edi
0x403521: mov eax,ds:[858220h]
0x403526: xor eax,esp
0x403528: push eax
0x403529: lea eax,[esp+10h]
0x40352d: mov fs:[0],eax
0x403533: mov ebx,ecx
0x403535: mov esi,[esp+20h]
0x403539: lea edi,[esi+4]
0x40353c: mov ecx,edi
0x40353e: call dword ptr ds:[77CD80h]
0x403544: mov dword ptr [esp+18h],0
0x40354c: mov al,[ebx]
0x40354e: add ebx,4
0x403551: push ebx
0x403552: mov ecx,edi
0x403554: mov [esi],al
0x403556: call dword ptr ds:[77CD70h]
0x40355c: mov eax,esi
0x40355e: mov ecx,[esp+10h]
0x403562: mov fs:[0],ecx
0x403569: pop ecx
0x40356a: pop edi
0x40356b: pop esi
0x40356c: pop ebx
0x40356d: add esp,0Ch
0x403570: ret 4
````

`sub_403510` is called by sub_465c30, sub_466d20. It calls nothing else.

### sub_407c40 at 0x407c40 (26 instructions)

````text
0x407c40: push 0FFFFFFFFh
0x407c42: push 73A3C5h
0x407c47: mov eax,fs:[0]
0x407c4d: push eax
0x407c4e: push esi
0x407c4f: mov eax,ds:[858220h]
0x407c54: xor eax,esp
0x407c56: push eax
0x407c57: lea eax,[esp+8]
0x407c5b: mov fs:[0],eax
0x407c61: mov esi,[esp+18h]
0x407c65: lea ecx,[esi+38h]
0x407c68: mov dword ptr [esp+10h],1
0x407c70: call dword ptr ds:[77CD74h]
0x407c76: lea ecx,[esi+1Ch]
0x407c79: mov byte ptr [esp+10h],0
0x407c7e: call dword ptr ds:[77CD74h]
0x407c84: mov ecx,esi
0x407c86: mov dword ptr [esp+10h],0FFFFFFFFh
0x407c8e: call dword ptr ds:[77CD74h]
0x407c94: mov ecx,[esp+8]
0x407c98: mov fs:[0],ecx
0x407c9f: pop ecx
0x407ca0: pop esi
0x407ca1: add esp,0Ch
0x407ca4: ret 4
````

`sub_407c40` is called by sub_5c4e10, sub_5c6b00. It calls nothing else.

### sub_40c260 at 0x40c260 (7 instructions)

````text
0x40c260: mov eax,[esp+8]
0x40c264: mov ecx,[esp+4]
0x40c268: push eax
0x40c269: push ecx
0x40c26a: call dword ptr ds:[77CDA0h]
0x40c270: add esp,8
0x40c273: ret 8
````

`sub_40c260` is called by sub_60f020, sub_60f280. It calls nothing else.

### sub_40d150 at 0x40d150 (45 instructions)

````text
0x40d150: push 0FFFFFFFFh
0x40d152: push 73E344h
0x40d157: mov eax,fs:[0]
0x40d15d: push eax
0x40d15e: sub esp,8
0x40d161: push ebp
0x40d162: push esi
0x40d163: push edi
0x40d164: mov eax,ds:[858220h]
0x40d169: xor eax,esp
0x40d16b: push eax
0x40d16c: lea eax,[esp+18h]
0x40d170: mov fs:[0],eax
0x40d176: mov ebp,[esp+28h]
0x40d17a: mov ecx,ebp
0x40d17c: call dword ptr ds:[77CD80h]
0x40d182: push 10h
0x40d184: mov dword ptr [esp+24h],0
0x40d18c: call 006516C0h
0x40d191: mov edi,eax
0x40d193: add esp,4
0x40d196: mov [esp+14h],edi
0x40d19a: test edi,edi
0x40d19c: mov ecx,1
0x40d1a1: mov [esp+20h],cl
0x40d1a5: je short 0040D1C8h
0x40d1a7: mov byte ptr [esp+11h],0
0x40d1ac: call 0040F000h
0x40d1b1: lea esi,[edi+9]
0x40d1b4: mov [edi+4],eax
0x40d1b7: call 0040E2C0h
0x40d1bc: mov dword ptr [edi+0Ch],0
0x40d1c3: mov [ebp+1Ch],edi
0x40d1c6: jmp short 0040D1CDh
0x40d1c8: xor eax,eax
0x40d1ca: mov [ebp+1Ch],eax
0x40d1cd: mov eax,ebp
0x40d1cf: mov ecx,[esp+18h]
0x40d1d3: mov fs:[0],ecx
0x40d1da: pop ecx
0x40d1db: pop edi
0x40d1dc: pop esi
0x40d1dd: pop ebp
0x40d1de: add esp,14h
0x40d1e1: ret 4
````

`sub_40d150` is called by sub_610980. It delegates to sub_40e2c0, sub_40f000, j_ORDINAL 762 (3 callees).

### sub_40d1f0 at 0x40d1f0 (33 instructions)

````text
0x40d1f0: push 0FFFFFFFFh
0x40d1f2: push 73E289h
0x40d1f7: mov eax,fs:[0]
0x40d1fd: push eax
0x40d1fe: push ecx
0x40d1ff: push esi
0x40d200: push edi
0x40d201: mov eax,ds:[858220h]
0x40d206: xor eax,esp
0x40d208: push eax
0x40d209: lea eax,[esp+10h]
0x40d20d: mov fs:[0],eax
0x40d213: mov edi,ecx
0x40d215: mov [esp+0Ch],edi
0x40d219: mov dword ptr [esp+18h],0
0x40d221: mov esi,[edi+1Ch]
0x40d224: test esi,esi
0x40d226: je short 0040D237h
0x40d228: push esi
0x40d229: call 0040E150h
0x40d22e: push esi
0x40d22f: call 006516BAh
0x40d234: add esp,4
0x40d237: mov ecx,edi
0x40d239: mov dword ptr [esp+18h],0FFFFFFFFh
0x40d241: call dword ptr ds:[77CD74h]
0x40d247: mov ecx,[esp+10h]
0x40d24b: mov fs:[0],ecx
0x40d252: pop ecx
0x40d253: pop edi
0x40d254: pop esi
0x40d255: add esp,10h
0x40d258: ret
````

`sub_40d1f0` is called by sub_40e310, sub_610c30. It delegates to sub_40e150, j_ORDINAL 764 (2 callees).

### sub_40e150 at 0x40e150 (32 instructions)

````text
0x40e150: push 0FFFFFFFFh
0x40e152: push 73E2D7h
0x40e157: mov eax,fs:[0]
0x40e15d: push eax
0x40e15e: push ecx
0x40e15f: push ebx
0x40e160: push esi
0x40e161: mov eax,ds:[858220h]
0x40e166: xor eax,esp
0x40e168: push eax
0x40e169: lea eax,[esp+10h]
0x40e16d: mov fs:[0],eax
0x40e173: mov esi,[esp+20h]
0x40e177: lea ebx,[esi+9]
0x40e17a: mov dword ptr [esp+18h],0
0x40e182: call 0040E310h
0x40e187: test esi,esi
0x40e189: je short 0040E190h
0x40e18b: lea eax,[esi+4]
0x40e18e: jmp short 0040E192h
0x40e190: xor eax,eax
0x40e192: mov eax,[eax]
0x40e194: push eax
0x40e195: call 006516BAh
0x40e19a: add esp,4
0x40e19d: mov ecx,[esp+10h]
0x40e1a1: mov fs:[0],ecx
0x40e1a8: pop ecx
0x40e1a9: pop esi
0x40e1aa: pop ebx
0x40e1ab: add esp,10h
0x40e1ae: ret 4
````

`sub_40e150` is called by sub_40d1f0. It delegates to sub_40e310, j_ORDINAL 764 (2 callees).

### sub_40e2c0 at 0x40e2c0 (33 instructions)

````text
0x40e2c0: mov ecx,esi
0x40e2c2: call 0040E3D0h
0x40e2c7: test esi,esi
0x40e2c9: je short 0040E2D0h
0x40e2cb: lea eax,[esi-9]
0x40e2ce: jmp short 0040E2D2h
0x40e2d0: xor eax,eax
0x40e2d2: mov eax,[eax+4]
0x40e2d5: add eax,4Ch
0x40e2d8: test esi,esi
0x40e2da: je short 0040E2E1h
0x40e2dc: lea ecx,[esi-9]
0x40e2df: jmp short 0040E2E3h
0x40e2e1: xor ecx,ecx
0x40e2e3: mov ecx,[ecx+4]
0x40e2e6: test ecx,ecx
0x40e2e8: je short 0040E2EFh
0x40e2ea: add ecx,48h
0x40e2ed: jmp short 0040E2F1h
0x40e2ef: xor ecx,ecx
0x40e2f1: test esi,esi
0x40e2f3: mov [eax],ecx
0x40e2f5: je short 0040E303h
0x40e2f7: lea eax,[esi-9]
0x40e2fa: mov eax,[eax+4]
0x40e2fd: mov [eax+48h],ecx
0x40e300: mov eax,esi
0x40e302: ret
0x40e303: xor eax,eax
0x40e305: mov eax,[eax+4]
0x40e308: mov [eax+48h],ecx
0x40e30b: mov eax,esi
0x40e30d: ret
````

`sub_40e2c0` is called by sub_40d150. It delegates to sub_40e3d0 (1 callees).

### sub_40e310 at 0x40e310 (58 instructions)

````text
0x40e310: push 0FFFFFFFFh
0x40e312: push 73E289h
0x40e317: mov eax,fs:[0]
0x40e31d: push eax
0x40e31e: push ecx
0x40e31f: push esi
0x40e320: push edi
0x40e321: mov eax,ds:[858220h]
0x40e326: xor eax,esp
0x40e328: push eax
0x40e329: lea eax,[esp+10h]
0x40e32d: mov fs:[0],eax
0x40e333: test ebx,ebx
0x40e335: je short 0040E33Ch
0x40e337: lea eax,[ebx-9]
0x40e33a: jmp short 0040E33Eh
0x40e33c: xor eax,eax
0x40e33e: mov eax,[eax+4]
0x40e341: mov eax,[eax+4Ch]
0x40e344: test eax,eax
0x40e346: je short 0040E34Dh
0x40e348: lea esi,[eax-48h]
0x40e34b: jmp short 0040E34Fh
0x40e34d: xor esi,esi
0x40e34f: mov eax,ebx
0x40e351: mov [esp+0Ch],esi
0x40e355: call 0040E3C0h
0x40e35a: cmp esi,eax
0x40e35c: je short 0040E3A8h
0x40e35e: mov edi,edi
0x40e360: mov eax,[esi+4Ch]
0x40e363: test eax,eax
0x40e365: je short 0040E36Ch
0x40e367: lea edi,[eax-48h]
0x40e36a: jmp short 0040E36Eh
0x40e36c: xor edi,edi
0x40e36e: lea ecx,[esi+1Ch]
0x40e371: mov dword ptr [esp+18h],0
0x40e379: call 0040D1F0h
0x40e37e: mov ecx,esi
0x40e380: mov dword ptr [esp+18h],0FFFFFFFFh
0x40e388: call dword ptr ds:[77CD74h]
0x40e38e: push esi
0x40e38f: call 006516BAh
0x40e394: mov esi,edi
0x40e396: add esp,4
0x40e399: mov eax,ebx
0x40e39b: mov [esp+0Ch],esi
0x40e39f: call 0040E3C0h
0x40e3a4: cmp edi,eax
0x40e3a6: jne short 0040E360h
0x40e3a8: mov ecx,[esp+10h]
0x40e3ac: mov fs:[0],ecx
0x40e3b3: pop ecx
0x40e3b4: pop edi
0x40e3b5: pop esi
0x40e3b6: add esp,10h
0x40e3b9: ret
````

`sub_40e310` is called by sub_40e150. It delegates to sub_40d1f0, sub_40e3c0, j_ORDINAL 764 (3 callees).

### sub_40e3c0 at 0x40e3c0 (7 instructions)

````text
0x40e3c0: test eax,eax
0x40e3c2: je short 0040E3C8h
0x40e3c4: mov eax,[eax-5]
0x40e3c7: ret
0x40e3c8: xor eax,eax
0x40e3ca: mov eax,[eax+4]
0x40e3cd: ret
````

`sub_40e3c0` is called by sub_40e310. It calls nothing else.

### sub_40e3d0 at 0x40e3d0 (54 instructions)

````text
0x40e3d0: test ecx,ecx
0x40e3d2: je short 0040E3D9h
0x40e3d4: lea eax,[ecx-9]
0x40e3d7: jmp short 0040E3DBh
0x40e3d9: xor eax,eax
0x40e3db: mov eax,[eax+4]
0x40e3de: and dword ptr [eax+3Ch],0FFFFFFFEh
0x40e3e2: add eax,3Ch
0x40e3e5: test ecx,ecx
0x40e3e7: je short 0040E3EEh
0x40e3e9: lea eax,[ecx-9]
0x40e3ec: jmp short 0040E3F0h
0x40e3ee: xor eax,eax
0x40e3f0: mov eax,[eax+4]
0x40e3f3: and dword ptr [eax+3Ch],1
0x40e3f7: add eax,3Ch
0x40e3fa: test ecx,ecx
0x40e3fc: je short 0040E403h
0x40e3fe: lea eax,[ecx-9]
0x40e401: jmp short 0040E405h
0x40e403: xor eax,eax
0x40e405: mov eax,[eax+4]
0x40e408: test eax,eax
0x40e40a: je short 0040E411h
0x40e40c: lea edx,[eax+3Ch]
0x40e40f: jmp short 0040E413h
0x40e411: xor edx,edx
0x40e413: test ecx,ecx
0x40e415: je short 0040E41Ch
0x40e417: lea eax,[ecx-9]
0x40e41a: jmp short 0040E41Eh
0x40e41c: xor eax,eax
0x40e41e: test ecx,ecx
0x40e420: mov eax,[eax+4]
0x40e423: mov [eax+40h],edx
0x40e426: je short 0040E42Dh
0x40e428: lea eax,[ecx-9]
0x40e42b: jmp short 0040E42Fh
0x40e42d: xor eax,eax
0x40e42f: mov eax,[eax+4]
0x40e432: test eax,eax
0x40e434: je short 0040E43Bh
0x40e436: add eax,3Ch
0x40e439: jmp short 0040E43Dh
0x40e43b: xor eax,eax
0x40e43d: test ecx,ecx
0x40e43f: je short 0040E448h
0x40e441: mov ecx,[ecx-5]
0x40e444: mov [ecx+44h],eax
0x40e447: ret
0x40e448: xor ecx,ecx
0x40e44a: mov edx,[ecx+4]
0x40e44d: mov [edx+44h],eax
0x40e450: ret
````

`sub_40e3d0` is called by sub_40e2c0. It calls nothing else.

### sub_40f000 at 0x40f000 (23 instructions)

````text
0x40f000: or eax,0FFFFFFFFh
0x40f003: xor edx,edx
0x40f005: div ecx
0x40f007: sub esp,10h
0x40f00a: cmp eax,50h
0x40f00d: jae short 0040F03Ch
0x40f00f: lea eax,[esp]
0x40f012: push eax
0x40f013: lea ecx,[esp+8]
0x40f017: mov dword ptr [esp+4],0
0x40f01f: call dword ptr ds:[77D0DCh]
0x40f025: push 80A2ACh
0x40f02a: lea ecx,[esp+8]
0x40f02e: push ecx
0x40f02f: mov dword ptr [esp+0Ch],78FFD4h
0x40f037: call 00652AC4h
0x40f03c: lea edx,[ecx+ecx*4]
0x40f03f: shl edx,4
0x40f042: push edx
0x40f043: call 006516C0h
0x40f048: add esp,4
0x40f04b: add esp,10h
0x40f04e: ret
````

`sub_40f000` is called by sub_40d150. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_415e60 at 0x415e60 (39 instructions)

````text
0x415e60: cmp dword ptr [esi],0
0x415e63: push edi
0x415e64: mov edi,ds:[77D0E4h]
0x415e6a: jne short 00415E6Eh
0x415e6c: call edi
0x415e6e: mov eax,[esi+4]
0x415e71: cmp byte ptr [eax+21h],0
0x415e75: je short 00415E7Bh
0x415e77: call edi
0x415e79: pop edi
0x415e7a: ret
0x415e7b: mov ecx,[eax+8]
0x415e7e: cmp byte ptr [ecx+21h],0
0x415e82: jne short 00415E9Fh
0x415e84: mov eax,[ecx]
0x415e86: cmp byte ptr [eax+21h],0
0x415e8a: jne short 00415E9Ah
0x415e8c: lea esp,[esp]
0x415e90: mov ecx,eax
0x415e92: mov eax,[ecx]
0x415e94: cmp byte ptr [eax+21h],0
0x415e98: je short 00415E90h
0x415e9a: mov [esi+4],ecx
0x415e9d: pop edi
0x415e9e: ret
0x415e9f: mov eax,[eax+4]
0x415ea2: cmp byte ptr [eax+21h],0
0x415ea6: jne short 00415EBEh
0x415ea8: mov ecx,[esi+4]
0x415eab: cmp ecx,[eax+8]
0x415eae: jne short 00415EBEh
0x415eb0: mov [esi+4],eax
0x415eb3: mov edx,eax
0x415eb5: mov eax,[edx+4]
0x415eb8: cmp byte ptr [eax+21h],0
0x415ebc: je short 00415EA8h
0x415ebe: mov [esi+4],eax
0x415ec1: pop edi
0x415ec2: ret
````

`sub_415e60` is called by sub_5afd00, sub_5b0180, sub_6273d0, sub_627940. It calls nothing else.

### sub_41fb70 at 0x41fb70 (36 instructions)

````text
0x41fb70: push ebp
0x41fb71: mov ebp,[esp+8]
0x41fb75: push esi
0x41fb76: push edi
0x41fb77: mov edi,[esp+14h]
0x41fb7b: test edi,edi
0x41fb7d: je short 0041FB85h
0x41fb7f: cmp edi,[esp+1Ch]
0x41fb83: je short 0041FB8Bh
0x41fb85: call dword ptr ds:[77D0E4h]
0x41fb8b: mov esi,[esp+18h]
0x41fb8f: mov edx,[esp+20h]
0x41fb93: cmp esi,edx
0x41fb95: je short 0041FBC1h
0x41fb97: mov eax,[ebx+8]
0x41fb9a: sub eax,edx
0x41fb9c: sar eax,2
0x41fb9f: test eax,eax
0x41fba1: lea ecx,[eax*4]
0x41fba8: lea edi,[ecx+esi]
0x41fbab: jle short 0041FBBAh
0x41fbad: push ecx
0x41fbae: push edx
0x41fbaf: push ecx
0x41fbb0: push esi
0x41fbb1: call dword ptr ds:[77D0C0h]
0x41fbb7: add esp,10h
0x41fbba: mov [ebx+8],edi
0x41fbbd: mov edi,[esp+14h]
0x41fbc1: mov [ebp],edi
0x41fbc4: pop edi
0x41fbc5: mov [ebp+4],esi
0x41fbc8: pop esi
0x41fbc9: mov eax,ebp
0x41fbcb: pop ebp
0x41fbcc: ret 14h
````

`sub_41fb70` is called by sub_52c150, sub_60ef60. It calls nothing else.

### sub_425810 at 0x425810 (208 instructions)

````text
0x425810: sub esp,8
0x425813: push ebx
0x425814: push ebp
0x425815: mov ebp,[esp+14h]
0x425819: push esi
0x42581a: mov esi,ecx
0x42581c: mov ecx,[eax]
0x42581e: mov eax,[ebp+4]
0x425821: test eax,eax
0x425823: push edi
0x425824: mov [esp+10h],ecx
0x425828: jne short 0042582Eh
0x42582a: xor ecx,ecx
0x42582c: jmp short 00425836h
0x42582e: mov ecx,[ebp+0Ch]
0x425831: sub ecx,eax
0x425833: sar ecx,2
0x425836: test esi,esi
0x425838: je near ptr 00425A23h
0x42583e: test eax,eax
0x425840: jne short 00425846h
0x425842: xor edx,edx
0x425844: jmp short 0042584Eh
0x425846: mov edx,[ebp+8]
0x425849: sub edx,eax
0x42584b: sar edx,2
0x42584e: mov edi,3FFFFFFFh
0x425853: sub edi,edx
0x425855: cmp edi,esi
0x425857: jae short 0042585Eh
0x425859: call 0042D310h
0x42585e: test eax,eax
0x425860: jne short 00425866h
0x425862: xor edx,edx
0x425864: jmp short 0042586Eh
0x425866: mov edx,[ebp+8]
0x425869: sub edx,eax
0x42586b: sar edx,2
0x42586e: add edx,esi
0x425870: cmp ecx,edx
0x425872: jae near ptr 00425976h
0x425878: mov edx,ecx
0x42587a: shr edx,1
0x42587c: mov edi,3FFFFFFFh
0x425881: sub edi,edx
0x425883: cmp edi,ecx
0x425885: jae short 00425895h
0x425887: mov dword ptr [esp+1Ch],0
0x42588f: mov ecx,[esp+1Ch]
0x425893: jmp short 0042589Bh
0x425895: add ecx,edx
0x425897: mov [esp+1Ch],ecx
0x42589b: test eax,eax
0x42589d: jne short 004258A3h
0x42589f: xor edx,edx
0x4258a1: jmp short 004258ABh
0x4258a3: mov edx,[ebp+8]
0x4258a6: sub edx,eax
0x4258a8: sar edx,2
0x4258ab: add edx,esi
0x4258ad: cmp ecx,edx
0x4258af: jae short 004258C7h
0x4258b1: test eax,eax
0x4258b3: jne short 004258B9h
0x4258b5: xor ecx,ecx
0x4258b7: jmp short 004258C1h
0x4258b9: mov ecx,[ebp+8]
0x4258bc: sub ecx,eax
0x4258be: sar ecx,2
0x4258c1: add ecx,esi
0x4258c3: mov [esp+1Ch],ecx
0x4258c7: test ecx,ecx
0x4258c9: ja short 004258DDh
0x4258cb: push 0
0x4258cd: call 006516C0h
0x4258d2: mov edx,eax
0x4258d4: add esp,4
0x4258d7: mov [esp+14h],edx
0x4258db: jmp short 004258E8h
0x4258dd: call 00488A40h
0x4258e2: mov [esp+14h],eax
0x4258e6: mov edx,eax
0x4258e8: mov ebx,[esp+24h]
0x4258ec: mov ecx,[ebp+4]
0x4258ef: mov eax,ebx
0x4258f1: sub eax,ecx
0x4258f3: sar eax,2
0x4258f6: lea eax,[eax*4]
0x4258fd: lea edi,[eax+edx]
0x425900: je short 0042590Fh
0x425902: push eax
0x425903: push ecx
0x425904: push eax
0x425905: push edx
0x425906: call dword ptr ds:[77D0C0h]
0x42590c: add esp,10h
0x42590f: lea edx,[esp+10h]
0x425913: call 00506440h
0x425918: mov ecx,[ebp+8]
0x42591b: sub ecx,ebx
0x42591d: sar ecx,2
0x425920: je short 00425933h
0x425922: add ecx,ecx
0x425924: add ecx,ecx
0x425926: push ecx
0x425927: push ebx
0x425928: push ecx
0x425929: push eax
0x42592a: call dword ptr ds:[77D0C0h]
0x425930: add esp,10h
0x425933: mov ecx,[ebp+4]
0x425936: test ecx,ecx
0x425938: jne short 0042593Eh
0x42593a: xor eax,eax
0x42593c: jmp short 00425946h
0x42593e: mov eax,[ebp+8]
0x425941: sub eax,ecx
0x425943: sar eax,2
0x425946: add esi,eax
0x425948: test ecx,ecx
0x42594a: je short 00425955h
0x42594c: push ecx
0x42594d: call 006516BAh
0x425952: add esp,4
0x425955: mov eax,[esp+14h]
0x425959: mov edx,[esp+1Ch]
0x42595d: lea ecx,[eax+edx*4]
0x425960: lea edx,[eax+esi*4]
0x425963: mov [ebp+0Ch],ecx
0x425966: mov [ebp+8],edx
0x425969: mov [ebp+4],eax
0x42596c: pop edi
0x42596d: pop esi
0x42596e: pop ebp
0x42596f: pop ebx
0x425970: add esp,8
0x425973: ret 0Ch
0x425976: mov edi,[ebp+8]
0x425979: mov ebx,[esp+24h]
0x42597d: mov eax,edi
0x42597f: sub eax,ebx
0x425981: sar eax,2
0x425984: cmp eax,esi
0x425986: lea eax,[esi*4]
0x42598d: mov [esp+1Ch],eax
0x425991: jae short 004259DBh
0x425993: lea ecx,[eax+ebx]
0x425996: mov eax,edi
0x425998: mov edx,ebx
0x42599a: call 004FF900h
0x42599f: mov edi,[ebp+8]
0x4259a2: mov ecx,edi
0x4259a4: sub ecx,ebx
0x4259a6: sar ecx,2
0x4259a9: sub esi,ecx
0x4259ab: lea edx,[esp+10h]
0x4259af: call 00506440h
0x4259b4: mov eax,[esp+1Ch]
0x4259b8: add [ebp+8],eax
0x4259bb: mov ebp,[ebp+8]
0x4259be: sub ebp,eax
0x4259c0: cmp ebx,ebp
0x4259c2: je short 00425A23h
0x4259c4: mov edx,[esp+10h]
0x4259c8: mov [ebx],edx
0x4259ca: add ebx,4
0x4259cd: cmp ebx,ebp
0x4259cf: jne short 004259C4h
0x4259d1: pop edi
0x4259d2: pop esi
0x4259d3: pop ebp
0x4259d4: pop ebx
0x4259d5: add esp,8
0x4259d8: ret 0Ch
0x4259db: mov esi,edi
0x4259dd: sub esi,eax
0x4259df: mov ecx,edi
0x4259e1: mov eax,edi
0x4259e3: mov edx,esi
0x4259e5: call 004FF900h
0x4259ea: sub esi,ebx
0x4259ec: sar esi,2
0x4259ef: test esi,esi
0x4259f1: mov [ebp+8],eax
0x4259f4: jle short 00425A0Ch
0x4259f6: lea eax,[esi*4]
0x4259fd: push eax
0x4259fe: push ebx
0x4259ff: push eax
0x425a00: sub edi,eax
0x425a02: push edi
0x425a03: call dword ptr ds:[77D0C0h]
0x425a09: add esp,10h
0x425a0c: mov eax,[esp+1Ch]
0x425a10: add eax,ebx
0x425a12: cmp ebx,eax
0x425a14: je short 00425A23h
0x425a16: mov ecx,[esp+10h]
0x425a1a: mov [ebx],ecx
0x425a1c: add ebx,4
0x425a1f: cmp ebx,eax
0x425a21: jne short 00425A16h
0x425a23: pop edi
0x425a24: pop esi
0x425a25: pop ebp
0x425a26: pop ebx
0x425a27: add esp,8
0x425a2a: ret 0Ch
````

`sub_425810` is called by sub_60ef60. It delegates to sub_42d310, sub_488a40, sub_4ff900 (6 callees).

### sub_42d310 at 0x42d310 (27 instructions)

````text
0x42d310: push ebp
0x42d311: mov ebp,esp
0x42d313: and esp,0FFFFFFF8h
0x42d316: push 0FFFFFFFFh
0x42d318: push 741199h
0x42d31d: mov eax,fs:[0]
0x42d323: push eax
0x42d324: sub esp,4Ch
0x42d327: mov eax,ds:[858220h]
0x42d32c: xor eax,esp
0x42d32e: push eax
0x42d32f: lea eax,[esp+50h]
0x42d333: mov fs:[0],eax
0x42d339: push 7BFB3Ch
0x42d33e: lea ecx,[esp+0Ch]
0x42d342: call dword ptr ds:[77CD7Ch]
0x42d348: lea eax,[esp+8]
0x42d34c: push eax
0x42d34d: lea ecx,[esp+28h]
0x42d351: mov dword ptr [esp+5Ch],0
0x42d359: call 00401230h
0x42d35e: push 80A274h
0x42d363: lea ecx,[esp+28h]
0x42d367: push ecx
0x42d368: mov dword ptr [esp+2Ch],78FFECh
0x42d370: call 00652AC4h
0x42d375: int 3
````

`sub_42d310` is called by sub_425810. It delegates to sub_401230, j__CxxThrowException (2 callees).

### sub_42d470 at 0x42d470 (25 instructions)

````text
0x42d470: or eax,0FFFFFFFFh
0x42d473: xor edx,edx
0x42d475: div ecx
0x42d477: sub esp,10h
0x42d47a: cmp eax,1Ch
0x42d47d: jae short 0042D4ACh
0x42d47f: lea eax,[esp]
0x42d482: push eax
0x42d483: lea ecx,[esp+8]
0x42d487: mov dword ptr [esp+4],0
0x42d48f: call dword ptr ds:[77D0DCh]
0x42d495: push 80A2ACh
0x42d49a: lea ecx,[esp+8]
0x42d49e: push ecx
0x42d49f: mov dword ptr [esp+0Ch],78FFD4h
0x42d4a7: call 00652AC4h
0x42d4ac: lea edx,[ecx*8]
0x42d4b3: sub edx,ecx
0x42d4b5: add edx,edx
0x42d4b7: add edx,edx
0x42d4b9: push edx
0x42d4ba: call 006516C0h
0x42d4bf: add esp,4
0x42d4c2: add esp,10h
0x42d4c5: ret
````

`sub_42d470` is called by sub_585350. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_433080 at 0x433080 (23 instructions)

````text
0x433080: push esi
0x433081: mov esi,[ebx+4]
0x433084: test esi,esi
0x433086: je short 004330ACh
0x433088: push edi
0x433089: mov edi,[ebx+8]
0x43308c: cmp esi,edi
0x43308e: je short 0043309Fh
0x433090: mov ecx,esi
0x433092: call dword ptr ds:[77CD74h]
0x433098: add esi,1Ch
0x43309b: cmp esi,edi
0x43309d: jne short 00433090h
0x43309f: mov eax,[ebx+4]
0x4330a2: push eax
0x4330a3: call 006516BAh
0x4330a8: add esp,4
0x4330ab: pop edi
0x4330ac: mov dword ptr [ebx+4],0
0x4330b3: mov dword ptr [ebx+8],0
0x4330ba: mov dword ptr [ebx+0Ch],0
0x4330c1: pop esi
0x4330c2: ret
````

`sub_433080` is called by sub_5ea9c0, sub_615070, sub_61da40. It delegates to j_ORDINAL 764 (1 callees).

### sub_43a360 at 0x43a360 (39 instructions)

````text
0x43a360: cmp dword ptr [esi],0
0x43a363: push edi
0x43a364: mov edi,ds:[77D0E4h]
0x43a36a: jne short 0043A36Eh
0x43a36c: call edi
0x43a36e: mov eax,[esi+4]
0x43a371: cmp byte ptr [eax+2Dh],0
0x43a375: je short 0043A37Bh
0x43a377: call edi
0x43a379: pop edi
0x43a37a: ret
0x43a37b: mov ecx,[eax+8]
0x43a37e: cmp byte ptr [ecx+2Dh],0
0x43a382: jne short 0043A39Fh
0x43a384: mov eax,[ecx]
0x43a386: cmp byte ptr [eax+2Dh],0
0x43a38a: jne short 0043A39Ah
0x43a38c: lea esp,[esp]
0x43a390: mov ecx,eax
0x43a392: mov eax,[ecx]
0x43a394: cmp byte ptr [eax+2Dh],0
0x43a398: je short 0043A390h
0x43a39a: mov [esi+4],ecx
0x43a39d: pop edi
0x43a39e: ret
0x43a39f: mov eax,[eax+4]
0x43a3a2: cmp byte ptr [eax+2Dh],0
0x43a3a6: jne short 0043A3BEh
0x43a3a8: mov ecx,[esi+4]
0x43a3ab: cmp ecx,[eax+8]
0x43a3ae: jne short 0043A3BEh
0x43a3b0: mov [esi+4],eax
0x43a3b3: mov edx,eax
0x43a3b5: mov eax,[edx+4]
0x43a3b8: cmp byte ptr [eax+2Dh],0
0x43a3bc: je short 0043A3A8h
0x43a3be: mov [esi+4],eax
0x43a3c1: pop edi
0x43a3c2: ret
````

`sub_43a360` is called by sub_4655a0, sub_4662f0, sub_4b4590, sub_4b57e0, sub_573040, sub_573500. It calls nothing else.

### sub_445d90 at 0x445d90 (23 instructions)

````text
0x445d90: push esi
0x445d91: mov esi,[ebx+4]
0x445d94: test esi,esi
0x445d96: je short 00445DBAh
0x445d98: push edi
0x445d99: mov edi,[ebx+8]
0x445d9c: cmp esi,edi
0x445d9e: je short 00445DADh
0x445da0: push esi
0x445da1: call 00448F40h
0x445da6: add esi,5Ch
0x445da9: cmp esi,edi
0x445dab: jne short 00445DA0h
0x445dad: mov eax,[ebx+4]
0x445db0: push eax
0x445db1: call 006516BAh
0x445db6: add esp,4
0x445db9: pop edi
0x445dba: mov dword ptr [ebx+4],0
0x445dc1: mov dword ptr [ebx+8],0
0x445dc8: mov dword ptr [ebx+0Ch],0
0x445dcf: pop esi
0x445dd0: ret
````

`sub_445d90` is called by sub_610c30. It delegates to sub_448f40, j_ORDINAL 764 (2 callees).

### sub_448f40 at 0x448f40 (26 instructions)

````text
0x448f40: push 0FFFFFFFFh
0x448f42: push 73A498h
0x448f47: mov eax,fs:[0]
0x448f4d: push eax
0x448f4e: push esi
0x448f4f: mov eax,ds:[858220h]
0x448f54: xor eax,esp
0x448f56: push eax
0x448f57: lea eax,[esp+8]
0x448f5b: mov fs:[0],eax
0x448f61: mov esi,[esp+18h]
0x448f65: lea ecx,[esi+40h]
0x448f68: mov dword ptr [esp+10h],1
0x448f70: call dword ptr ds:[77CD74h]
0x448f76: lea ecx,[esi+24h]
0x448f79: mov byte ptr [esp+10h],0
0x448f7e: call dword ptr ds:[77CD74h]
0x448f84: lea ecx,[esi+8]
0x448f87: mov dword ptr [esp+10h],0FFFFFFFFh
0x448f8f: call dword ptr ds:[77CD74h]
0x448f95: mov ecx,[esp+8]
0x448f99: mov fs:[0],ecx
0x448fa0: pop ecx
0x448fa1: pop esi
0x448fa2: add esp,0Ch
0x448fa5: ret 4
````

`sub_448f40` is called by sub_445d90. It calls nothing else.

### sub_44be60 at 0x44be60 (37 instructions)

````text
0x44be60: sub esp,10h
0x44be63: push esi
0x44be64: mov esi,eax
0x44be66: lea eax,[esp+8]
0x44be6a: push eax
0x44be6b: call 0044BF20h
0x44be70: mov ecx,[eax]
0x44be72: mov edx,[esi]
0x44be74: mov [eax],edx
0x44be76: mov [esi],ecx
0x44be78: mov edx,[eax+4]
0x44be7b: mov ecx,[esi+4]
0x44be7e: mov [esi+4],edx
0x44be81: mov [eax+4],ecx
0x44be84: mov eax,[esp+0Ch]
0x44be88: test eax,eax
0x44be8a: je short 0044BEB8h
0x44be8c: mov esi,eax
0x44be8e: add eax,4
0x44be91: or ecx,0FFFFFFFFh
0x44be94: lock xadd [eax],ecx
0x44be98: jne short 0044BEB8h
0x44be9a: mov edx,[esi]
0x44be9c: mov eax,[edx+4]
0x44be9f: mov ecx,esi
0x44bea1: call eax
0x44bea3: lea ecx,[esi+8]
0x44bea6: or edx,0FFFFFFFFh
0x44bea9: lock xadd [ecx],edx
0x44bead: jne short 0044BEB8h
0x44beaf: mov eax,[esi]
0x44beb1: mov edx,[eax+8]
0x44beb4: mov ecx,esi
0x44beb6: call edx
0x44beb8: pop esi
0x44beb9: add esp,10h
0x44bebc: ret
````

`sub_44be60` is called by sub_5ea5d0. It delegates to sub_44bf20 (1 callees).

### sub_44bf20 at 0x44bf20 (28 instructions)

````text
0x44bf20: push 0FFFFFFFFh
0x44bf22: push 73F2EBh
0x44bf27: mov eax,fs:[0]
0x44bf2d: push eax
0x44bf2e: push esi
0x44bf2f: push edi
0x44bf30: mov eax,ds:[858220h]
0x44bf35: xor eax,esp
0x44bf37: push eax
0x44bf38: lea eax,[esp+0Ch]
0x44bf3c: mov fs:[0],eax
0x44bf42: mov edi,ecx
0x44bf44: mov esi,[esp+1Ch]
0x44bf48: lea eax,[esi+4]
0x44bf4b: mov [esi],edi
0x44bf4d: mov dword ptr [eax],0
0x44bf53: push esi
0x44bf54: mov dword ptr [esp+18h],0
0x44bf5c: call 0044BFE0h
0x44bf61: add esp,4
0x44bf64: mov eax,esi
0x44bf66: mov ecx,[esp+0Ch]
0x44bf6a: mov fs:[0],ecx
0x44bf71: pop ecx
0x44bf72: pop edi
0x44bf73: pop esi
0x44bf74: add esp,0Ch
0x44bf77: ret 4
````

`sub_44bf20` is called by sub_44be60. It delegates to sub_44bfe0 (1 callees).

### sub_44bfe0 at 0x44bfe0 (39 instructions)

````text
0x44bfe0: push ecx
0x44bfe1: push esi
0x44bfe2: push edi
0x44bfe3: lea ecx,[esp+8]
0x44bfe7: mov esi,eax
0x44bfe9: call 0044C0A0h
0x44bfee: mov edx,[eax]
0x44bff0: mov ecx,[esi]
0x44bff2: mov [esi],edx
0x44bff4: mov [eax],ecx
0x44bff6: mov eax,[esp+4]
0x44bffa: test eax,eax
0x44bffc: je short 0044C02Ah
0x44bffe: mov esi,eax
0x44c000: add eax,4
0x44c003: or ecx,0FFFFFFFFh
0x44c006: lock xadd [eax],ecx
0x44c00a: jne short 0044C02Ah
0x44c00c: mov edx,[esi]
0x44c00e: mov eax,[edx+4]
0x44c011: mov ecx,esi
0x44c013: call eax
0x44c015: lea ecx,[esi+8]
0x44c018: or edx,0FFFFFFFFh
0x44c01b: lock xadd [ecx],edx
0x44c01f: jne short 0044C02Ah
0x44c021: mov eax,[esi]
0x44c023: mov edx,[eax+8]
0x44c026: mov ecx,esi
0x44c028: call edx
0x44c02a: mov eax,[esp+0Ch]
0x44c02e: push edi
0x44c02f: push edi
0x44c030: push eax
0x44c031: call 004A5750h
0x44c036: add esp,0Ch
0x44c039: pop esi
0x44c03a: pop ecx
0x44c03b: ret
````

`sub_44bfe0` is called by sub_44bf20. It delegates to sub_44c0a0, sub_4a5750 (2 callees).

### sub_44c0a0 at 0x44c0a0 (43 instructions)

````text
0x44c0a0: push ebp
0x44c0a1: mov ebp,esp
0x44c0a3: push 0FFFFFFFFh
0x44c0a5: push 73DBD0h
0x44c0aa: mov eax,fs:[0]
0x44c0b0: push eax
0x44c0b1: push ecx
0x44c0b2: push ebx
0x44c0b3: push esi
0x44c0b4: push edi
0x44c0b5: mov eax,ds:[858220h]
0x44c0ba: xor eax,ebp
0x44c0bc: push eax
0x44c0bd: lea eax,[ebp-0Ch]
0x44c0c0: mov fs:[0],eax
0x44c0c6: mov [ebp-10h],esp
0x44c0c9: mov esi,ecx
0x44c0cb: push 10h
0x44c0cd: mov dword ptr [esi],0
0x44c0d3: mov dword ptr [ebp-4],0
0x44c0da: call 006516C0h
0x44c0df: add esp,4
0x44c0e2: test eax,eax
0x44c0e4: je short 0044C0FFh
0x44c0e6: mov ecx,1
0x44c0eb: mov [eax+4],ecx
0x44c0ee: mov [eax+8],ecx
0x44c0f1: mov ecx,[ebp+8]
0x44c0f4: mov dword ptr [eax],7C7734h
0x44c0fa: mov [eax+0Ch],ecx
0x44c0fd: jmp short 0044C101h
0x44c0ff: xor eax,eax
0x44c101: mov [esi],eax
0x44c103: mov eax,esi
0x44c105: mov ecx,[ebp-0Ch]
0x44c108: mov fs:[0],ecx
0x44c10f: pop ecx
0x44c110: pop edi
0x44c111: pop esi
0x44c112: pop ebx
0x44c113: mov esp,ebp
0x44c115: pop ebp
0x44c116: ret 4
````

`sub_44c0a0` is called by sub_44bfe0. It delegates to j_ORDINAL 762 (1 callees).

### sub_44c770 at 0x44c770 (26 instructions)

````text
0x44c770: push 0FFFFFFFFh
0x44c772: push 73A3C5h
0x44c777: mov eax,fs:[0]
0x44c77d: push eax
0x44c77e: push esi
0x44c77f: mov eax,ds:[858220h]
0x44c784: xor eax,esp
0x44c786: push eax
0x44c787: lea eax,[esp+8]
0x44c78b: mov fs:[0],eax
0x44c791: mov esi,[esp+18h]
0x44c795: lea ecx,[esi+3Ch]
0x44c798: mov dword ptr [esp+10h],1
0x44c7a0: call dword ptr ds:[77CD74h]
0x44c7a6: lea ecx,[esi+1Ch]
0x44c7a9: mov byte ptr [esp+10h],0
0x44c7ae: call dword ptr ds:[77CD74h]
0x44c7b4: mov ecx,esi
0x44c7b6: mov dword ptr [esp+10h],0FFFFFFFFh
0x44c7be: call dword ptr ds:[77CD74h]
0x44c7c4: mov ecx,[esp+8]
0x44c7c8: mov fs:[0],ecx
0x44c7cf: pop ecx
0x44c7d0: pop esi
0x44c7d1: add esp,0Ch
0x44c7d4: ret 4
````

`sub_44c770` is called by sub_4ef1a0, sub_62a6e0, sub_62a960. It calls nothing else.

### sub_44d400 at 0x44d400 (30 instructions)

````text
0x44d400: push edi
0x44d401: mov edi,eax
0x44d403: cmp edi,ebx
0x44d405: je short 0044D441h
0x44d407: push esi
0x44d408: mov esi,[edi+4]
0x44d40b: test esi,esi
0x44d40d: je short 0044D439h
0x44d40f: lea eax,[esi+4]
0x44d412: or ecx,0FFFFFFFFh
0x44d415: lock xadd [eax],ecx
0x44d419: jne short 0044D439h
0x44d41b: mov edx,[esi]
0x44d41d: mov eax,[edx+4]
0x44d420: mov ecx,esi
0x44d422: call eax
0x44d424: lea ecx,[esi+8]
0x44d427: or edx,0FFFFFFFFh
0x44d42a: lock xadd [ecx],edx
0x44d42e: jne short 0044D439h
0x44d430: mov eax,[esi]
0x44d432: mov edx,[eax+8]
0x44d435: mov ecx,esi
0x44d437: call edx
0x44d439: add edi,8
0x44d43c: cmp edi,ebx
0x44d43e: jne short 0044D408h
0x44d440: pop esi
0x44d441: pop edi
0x44d442: ret
````

`sub_44d400` is called by sub_4a3aa0, sub_585a40, sub_5dfe00, sub_5ea9c0, sub_5efa60, sub_619ee0, sub_77b450. It calls nothing else.

### sub_44f820 at 0x44f820 (21 instructions)

````text
0x44f820: mov cl,[edx]
0x44f822: push esi
0x44f823: mov esi,eax
0x44f825: mov al,[esi]
0x44f827: cmp al,cl
0x44f829: jae short 0044F82Fh
0x44f82b: mov al,1
0x44f82d: pop esi
0x44f82e: ret
0x44f82f: jbe short 0044F835h
0x44f831: xor al,al
0x44f833: pop esi
0x44f834: ret
0x44f835: add edx,4
0x44f838: push edx
0x44f839: add esi,4
0x44f83c: push esi
0x44f83d: call dword ptr ds:[77CDA0h]
0x44f843: add esp,8
0x44f846: pop esi
0x44f847: ret
````

`sub_44f820` is called by sub_465ff0. It calls nothing else.

### sub_44fad0 at 0x44fad0 (28 instructions)

````text
0x44fad0: mov eax,[ecx+8]
0x44fad3: mov edx,[eax]
0x44fad5: mov [ecx+8],edx
0x44fad8: mov edx,[eax]
0x44fada: cmp byte ptr [edx+49h],0
0x44fade: jne short 0044FAE3h
0x44fae0: mov [edx+4],ecx
0x44fae3: mov edx,[ecx+4]
0x44fae6: mov [eax+4],edx
0x44fae9: mov edx,[esp+4]
0x44faed: mov edx,[edx+4]
0x44faf0: cmp ecx,[edx+4]
0x44faf3: jne short 0044FB00h
0x44faf5: mov [edx+4],eax
0x44faf8: mov [eax],ecx
0x44fafa: mov [ecx+4],eax
0x44fafd: ret 4
0x44fb00: mov edx,[ecx+4]
0x44fb03: cmp ecx,[edx]
0x44fb05: jne short 0044FB11h
0x44fb07: mov [edx],eax
0x44fb09: mov [eax],ecx
0x44fb0b: mov [ecx+4],eax
0x44fb0e: ret 4
0x44fb11: mov [edx+8],eax
0x44fb14: mov [eax],ecx
0x44fb16: mov [ecx+4],eax
0x44fb19: ret 4
````

`sub_44fad0` is called by sub_466710, sub_466a30. It calls nothing else.

### sub_44fb20 at 0x44fb20 (28 instructions)

````text
0x44fb20: mov eax,[ecx]
0x44fb22: mov edx,[eax+8]
0x44fb25: mov [ecx],edx
0x44fb27: mov edx,[eax+8]
0x44fb2a: cmp byte ptr [edx+49h],0
0x44fb2e: jne short 0044FB33h
0x44fb30: mov [edx+4],ecx
0x44fb33: mov edx,[ecx+4]
0x44fb36: mov [eax+4],edx
0x44fb39: mov edx,[esp+4]
0x44fb3d: mov edx,[edx+4]
0x44fb40: cmp ecx,[edx+4]
0x44fb43: jne short 0044FB51h
0x44fb45: mov [edx+4],eax
0x44fb48: mov [eax+8],ecx
0x44fb4b: mov [ecx+4],eax
0x44fb4e: ret 4
0x44fb51: mov edx,[ecx+4]
0x44fb54: cmp ecx,[edx+8]
0x44fb57: jne short 0044FB65h
0x44fb59: mov [edx+8],eax
0x44fb5c: mov [eax+8],ecx
0x44fb5f: mov [ecx+4],eax
0x44fb62: ret 4
0x44fb65: mov [edx],eax
0x44fb67: mov [eax+8],ecx
0x44fb6a: mov [ecx+4],eax
0x44fb6d: ret 4
````

`sub_44fb20` is called by sub_466710, sub_466a30. It calls nothing else.

### sub_44ff00 at 0x44ff00 (16 instructions)

````text
0x44ff00: mov ecx,1
0x44ff05: call 00450370h
0x44ff0a: test eax,eax
0x44ff0c: je short 0044FF14h
0x44ff0e: mov dword ptr [eax],0
0x44ff14: lea ecx,[eax+4]
0x44ff17: test ecx,ecx
0x44ff19: je short 0044FF21h
0x44ff1b: mov dword ptr [ecx],0
0x44ff21: lea ecx,[eax+8]
0x44ff24: test ecx,ecx
0x44ff26: je short 0044FF2Eh
0x44ff28: mov dword ptr [ecx],0
0x44ff2e: mov byte ptr [eax+48h],1
0x44ff32: mov byte ptr [eax+49h],0
0x44ff36: ret
````

`sub_44ff00` is called by sub_4609d0. It delegates to sub_450370 (1 callees).

### sub_450370 at 0x450370 (22 instructions)

````text
0x450370: or eax,0FFFFFFFFh
0x450373: xor edx,edx
0x450375: div ecx
0x450377: sub esp,10h
0x45037a: cmp eax,4Ch
0x45037d: jae short 004503ACh
0x45037f: lea eax,[esp]
0x450382: push eax
0x450383: lea ecx,[esp+8]
0x450387: mov dword ptr [esp+4],0
0x45038f: call dword ptr ds:[77D0DCh]
0x450395: push 80A2ACh
0x45039a: lea ecx,[esp+8]
0x45039e: push ecx
0x45039f: mov dword ptr [esp+0Ch],78FFD4h
0x4503a7: call 00652AC4h
0x4503ac: imul ecx,4Ch
0x4503af: push ecx
0x4503b0: call 006516C0h
0x4503b5: add esp,4
0x4503b8: add esp,10h
0x4503bb: ret
````

`sub_450370` is called by sub_44ff00, sub_466d20. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_458540 at 0x458540 (9 instructions)

````text
0x458540: mov ecx,[eax+8]
0x458543: cmp byte ptr [ecx+39h],0
0x458547: jne short 0045855Bh
0x458549: lea esp,[esp]
0x458550: mov eax,ecx
0x458552: mov ecx,[eax+8]
0x458555: cmp byte ptr [ecx+39h],0
0x458559: je short 00458550h
0x45855b: ret
````

`sub_458540` is called by sub_4dd6d0, sub_506d20, sub_5e3ee0, sub_5e42e0, sub_5e6990, sub_5ef4e0, sub_5f9360, sub_6229f0, sub_633610. It calls nothing else.

### sub_4608f0 at 0x4608f0 (33 instructions)

````text
0x4608f0: push esi
0x4608f1: push 0Ch
0x4608f3: call 006516C0h
0x4608f8: mov esi,eax
0x4608fa: add esp,4
0x4608fd: test esi,esi
0x4608ff: je short 0046093Bh
0x460901: test edi,edi
0x460903: mov dword ptr [esi],1
0x460909: mov dword ptr [esi+4],0
0x460910: mov [esi+8],edi
0x460913: jbe short 00460935h
0x460915: push edi
0x460916: call dword ptr ds:[77D0D0h]
0x46091c: add esp,4
0x46091f: test eax,eax
0x460921: mov [esi+4],eax
0x460924: je short 00460935h
0x460926: mov ecx,[esi+8]
0x460929: push ecx
0x46092a: push 0
0x46092c: push eax
0x46092d: call 00652A94h
0x460932: add esp,0Ch
0x460935: mov [ebx],esi
0x460937: mov eax,ebx
0x460939: pop esi
0x46093a: ret
0x46093b: xor eax,eax
0x46093d: mov [ebx],eax
0x46093f: mov eax,ebx
0x460941: pop esi
0x460942: ret
````

`sub_4608f0` is called by sub_460da0, sub_637190. It delegates to j_ORDINAL 762, j_memset (2 callees).

### sub_460950 at 0x460950 (23 instructions)

````text
0x460950: push esi
0x460951: mov esi,[edi]
0x460953: test esi,esi
0x460955: je short 00460989h
0x460957: mov eax,esi
0x460959: or ecx,0FFFFFFFFh
0x46095c: lock xadd [eax],ecx
0x460960: jne short 00460981h
0x460962: test esi,esi
0x460964: je short 00460983h
0x460966: mov edx,[esi+4]
0x460969: push edx
0x46096a: call dword ptr ds:[77D0E8h]
0x460970: push esi
0x460971: call 006516BAh
0x460976: add esp,8
0x460979: mov dword ptr [edi],0
0x46097f: pop esi
0x460980: ret
0x460981: mov eax,[esi]
0x460983: mov dword ptr [edi],0
0x460989: pop esi
0x46098a: ret
````

`sub_460950` is called by sub_460da0, sub_637190. It delegates to j_ORDINAL 764 (1 callees).

### sub_4609d0 at 0x4609d0 (34 instructions)

````text
0x4609d0: push 0FFFFFFFFh
0x4609d2: push 7484F4h
0x4609d7: mov eax,fs:[0]
0x4609dd: push eax
0x4609de: push ecx
0x4609df: mov eax,ds:[858220h]
0x4609e4: xor eax,esp
0x4609e6: push eax
0x4609e7: lea eax,[esp+8]
0x4609eb: mov fs:[0],eax
0x4609f1: mov ecx,875984h
0x4609f6: mov dword ptr [esp+4],875984h
0x4609fe: call dword ptr ds:[77DF80h]
0x460a04: mov dword ptr [esp+10h],0
0x460a0c: mov byte ptr ds:[87598Ch],0
0x460a13: call 0044FF00h
0x460a18: mov ds:[875994h],eax
0x460a1d: mov cl,1
0x460a1f: mov [eax+49h],cl
0x460a22: mov eax,ds:[875994h]
0x460a27: mov [eax+4],eax
0x460a2a: mov eax,ds:[875994h]
0x460a2f: mov [eax],eax
0x460a31: mov eax,ds:[875994h]
0x460a36: mov [eax+8],eax
0x460a39: mov dword ptr ds:[875998h],0
0x460a43: mov [esp+10h],cl
0x460a47: call 00460DA0h
0x460a4c: mov eax,875984h
0x460a51: mov ecx,[esp+8]
0x460a55: mov fs:[0],ecx
0x460a5c: pop ecx
0x460a5d: add esp,10h
0x460a60: ret
````

`sub_4609d0` is called by ?get_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@CAAAV_DownloadInfo@@XZ. It delegates to sub_44ff00, sub_460da0 (2 callees).

### sub_460a70 at 0x460a70 (27 instructions)

````text
0x460a70: push 0FFFFFFFFh
0x460a72: push 7484C4h
0x460a77: mov eax,fs:[0]
0x460a7d: push eax
0x460a7e: sub esp,8
0x460a81: push edi
0x460a82: mov eax,ds:[858220h]
0x460a87: xor eax,esp
0x460a89: push eax
0x460a8a: lea eax,[esp+10h]
0x460a8e: mov fs:[0],eax
0x460a94: mov edi,875984h
0x460a99: mov [esp+0Ch],edi
0x460a9d: mov dword ptr [esp+18h],1
0x460aa5: call 00461120h
0x460aaa: mov eax,875990h
0x460aaf: mov byte ptr [esp+18h],0
0x460ab4: call 00466240h
0x460ab9: mov ecx,edi
0x460abb: mov dword ptr [esp+18h],0FFFFFFFFh
0x460ac3: call dword ptr ds:[77DF7Ch]
0x460ac9: mov ecx,[esp+10h]
0x460acd: mov fs:[0],ecx
0x460ad4: pop ecx
0x460ad5: pop edi
0x460ad6: add esp,14h
0x460ad9: ret
````

`sub_460a70` is called by sub_77af50. It delegates to sub_461120, sub_466240 (2 callees).

### sub_460da0 at 0x460da0 (230 instructions)

````text
0x460da0: push ebp
0x460da1: mov ebp,esp
0x460da3: and esp,0FFFFFFF8h
0x460da6: push 0FFFFFFFFh
0x460da8: push 7421C9h
0x460dad: mov eax,fs:[0]
0x460db3: push eax
0x460db4: sub esp,80h
0x460dba: mov eax,ds:[858220h]
0x460dbf: xor eax,esp
0x460dc1: mov [esp+78h],eax
0x460dc5: push ebx
0x460dc6: push esi
0x460dc7: push edi
0x460dc8: mov eax,ds:[858220h]
0x460dcd: xor eax,esp
0x460dcf: push eax
0x460dd0: lea eax,[esp+90h]
0x460dd7: mov fs:[0],eax
0x460ddd: mov eax,ds:[875984h]
0x460de2: mov edx,[eax+4]
0x460de5: mov ecx,875984h
0x460dea: mov dword ptr [esp+2Ch],875984h
0x460df2: call edx
0x460df4: xor edi,edi
0x460df6: mov [esp+98h],edi
0x460dfd: cmp byte ptr ds:[87598Ch],0
0x460e04: je short 00460E25h
0x460e06: mov dword ptr [esp+98h],0FFFFFFFFh
0x460e11: mov eax,ds:[875984h]
0x460e16: mov edx,[eax+0Ch]
0x460e19: mov ecx,875984h
0x460e1e: call edx
0x460e20: jmp near ptr 004610BCh
0x460e25: mov eax,ds:[875994h]
0x460e2a: mov bl,1
0x460e2c: mov ds:[87598Ch],bl
0x460e32: mov ecx,[eax+4]
0x460e35: push ecx
0x460e36: mov ecx,875990h
0x460e3b: call 00466200h
0x460e40: mov eax,ds:[875994h]
0x460e45: mov [eax+4],eax
0x460e48: mov eax,ds:[875994h]
0x460e4d: mov ds:[875998h],edi
0x460e53: mov [eax],eax
0x460e55: mov eax,ds:[875994h]
0x460e5a: lea edx,[esp+30h]
0x460e5e: push edx
0x460e5f: mov [eax+8],eax
0x460e62: call dword ptr ds:[77D144h]
0x460e68: add esp,4
0x460e6b: mov esi,10h
0x460e70: mov [esp+98h],bl
0x460e77: cmp [eax+18h],esi
0x460e7a: jb short 00460E81h
0x460e7c: mov eax,[eax+4]
0x460e7f: jmp short 00460E84h
0x460e81: add eax,4
0x460e84: push eax
0x460e85: lea eax,[esp+50h]
0x460e89: push 7CC4A8h
0x460e8e: push eax
0x460e8f: call dword ptr ds:[77DF24h]
0x460e95: add esp,0Ch
0x460e98: lea ecx,[esp+30h]
0x460e9c: mov byte ptr [esp+98h],3
0x460ea4: call dword ptr ds:[77CD74h]
0x460eaa: cmp [esp+64h],esi
0x460eae: mov eax,[esp+50h]
0x460eb2: jae short 00460EB8h
0x460eb4: lea eax,[esp+50h]
0x460eb8: push 7CC4BCh
0x460ebd: push eax
0x460ebe: call dword ptr ds:[77D088h]
0x460ec4: mov esi,eax
0x460ec6: add esp,8
0x460ec9: cmp esi,edi
0x460ecb: je short 00460F01h
0x460ecd: mov ebx,ds:[77D084h]
0x460ed3: push 2
0x460ed5: push edi
0x460ed6: push esi
0x460ed7: call ebx
0x460ed9: add esp,0Ch
0x460edc: push esi
0x460edd: call dword ptr ds:[77D080h]
0x460ee3: add esp,4
0x460ee6: push 0
0x460ee8: push 0
0x460eea: push esi
0x460eeb: mov edi,eax
0x460eed: call ebx
0x460eef: add esp,0Ch
0x460ef2: cmp edi,8
0x460ef5: jae short 00460F35h
0x460ef7: push esi
0x460ef8: call dword ptr ds:[77D0F0h]
0x460efe: add esp,4
0x460f01: lea ecx,[esp+4Ch]
0x460f05: mov byte ptr [esp+98h],0
0x460f0d: call dword ptr ds:[77CD74h]
0x460f13: mov dword ptr [esp+98h],0FFFFFFFFh
0x460f1e: mov edx,ds:[875984h]
0x460f24: mov eax,[edx+0Ch]
0x460f27: mov ecx,875984h
0x460f2c: call eax
0x460f2e: xor al,al
0x460f30: jmp near ptr 004610BEh
0x460f35: lea ebx,[esp+10h]
0x460f39: call 004608F0h
0x460f3e: mov byte ptr [esp+98h],4
0x460f46: mov ebx,[esp+10h]
0x460f4a: test ebx,ebx
0x460f4c: jne short 00460F52h
0x460f4e: xor eax,eax
0x460f50: jmp short 00460F55h
0x460f52: mov eax,[ebx+4]
0x460f55: push esi
0x460f56: push edi
0x460f57: push 1
0x460f59: push eax
0x460f5a: call dword ptr ds:[77D07Ch]
0x460f60: push esi
0x460f61: call dword ptr ds:[77D0F0h]
0x460f67: xor edi,edi
0x460f69: add esp,14h
0x460f6c: cmp ebx,edi
0x460f6e: je near ptr 004610DFh
0x460f74: mov eax,[ebx+8]
0x460f77: mov ebx,[ebx+4]
0x460f7a: push eax
0x460f7b: push ebx
0x460f7c: lea ecx,[esp+20h]
0x460f80: call dword ptr ds:[77DFB0h]
0x460f86: mov byte ptr [esp+98h],5
0x460f8e: mov esi,ds:[77DE4Ch]
0x460f94: lea ecx,[esp+28h]
0x460f98: push ecx
0x460f99: lea ecx,[esp+1Ch]
0x460f9d: mov [esp+2Ch],edi
0x460fa1: mov [esp+18h],edi
0x460fa5: call esi
0x460fa7: test al,al
0x460fa9: je near ptr 004610FAh
0x460faf: lea ecx,[esp+14h]
0x460fb3: push ecx
0x460fb4: lea ecx,[esp+1Ch]
0x460fb8: call esi
0x460fba: test al,al
0x460fbc: je near ptr 004610FAh
0x460fc2: cmp dword ptr [esp+28h],0E870001h
0x460fca: jne near ptr 004610FAh
0x460fd0: xor ebx,ebx
0x460fd2: cmp [esp+14h],ebx
0x460fd6: jbe near ptr 00461074h
0x460fdc: lea ecx,[esp+6Ch]
0x460fe0: mov byte ptr [esp+68h],0
0x460fe5: call dword ptr ds:[77CD80h]
0x460feb: lea ecx,[esp+68h]
0x460fef: push ecx
0x460ff0: lea ecx,[esp+1Ch]
0x460ff4: mov byte ptr [esp+9Ch],6
0x460ffc: call dword ptr ds:[77DE48h]
0x461002: test al,al
0x461004: je near ptr 004610E8h
0x46100a: lea edx,[esp+6Ch]
0x46100e: push edx
0x46100f: lea ecx,[esp+1Ch]
0x461013: call dword ptr ds:[77DE44h]
0x461019: test al,al
0x46101b: je near ptr 004610E8h
0x461021: push 1Ch
0x461023: lea eax,[esp+34h]
0x461027: push eax
0x461028: lea ecx,[esp+20h]
0x46102c: call dword ptr ds:[77DE40h]
0x461032: test al,al
0x461034: je near ptr 004610E8h
0x46103a: push 875990h
0x46103f: lea ecx,[esp+6Ch]
0x461043: call 00465C30h
0x461048: mov edi,eax
0x46104a: mov ecx,7
0x46104f: lea esi,[esp+30h]
0x461053: rep movsd
0x461055: lea ecx,[esp+6Ch]
0x461059: mov byte ptr [esp+98h],5
0x461061: call dword ptr ds:[77CD74h]
0x461067: add ebx,1
0x46106a: cmp ebx,[esp+14h]
0x46106e: jb near ptr 00460FDCh
0x461074: lea ecx,[esp+18h]
0x461078: mov byte ptr [esp+98h],4
0x461080: call dword ptr ds:[77DE50h]
0x461086: lea edi,[esp+10h]
0x46108a: call 00460950h
0x46108f: lea ecx,[esp+4Ch]
0x461093: mov byte ptr [esp+98h],0
0x46109b: call dword ptr ds:[77CD74h]
0x4610a1: mov dword ptr [esp+98h],0FFFFFFFFh
0x4610ac: mov edx,ds:[875984h]
0x4610b2: mov eax,[edx+0Ch]
0x4610b5: mov ecx,875984h
0x4610ba: call eax
0x4610bc: mov al,1
0x4610be: mov ecx,[esp+90h]
0x4610c5: mov fs:[0],ecx
0x4610cc: pop ecx
0x4610cd: pop edi
0x4610ce: pop esi
0x4610cf: pop ebx
0x4610d0: mov ecx,[esp+78h]
0x4610d4: xor ecx,esp
0x4610d6: call 00652739h
0x4610db: mov esp,ebp
0x4610dd: pop ebp
0x4610de: ret
0x4610df: xor eax,eax
0x4610e1: xor ebx,ebx
0x4610e3: jmp near ptr 00460F7Ah
0x4610e8: lea ecx,[esp+6Ch]
0x4610ec: mov byte ptr [esp+98h],5
0x4610f4: call dword ptr ds:[77CD74h]
0x4610fa: lea ecx,[esp+18h]
0x4610fe: mov byte ptr [esp+98h],4
0x461106: call dword ptr ds:[77DE50h]
0x46110c: lea edi,[esp+10h]
0x461110: call 00460950h
0x461115: jmp near ptr 00460F01h
````

`sub_460da0` is called by sub_4609d0. It works with the text "%s\DownloadInfo.dn". It delegates to sub_4608f0, sub_460950, sub_465c30 (5 callees).

### sub_461120 at 0x461120 (168 instructions)

````text
0x461120: push ebp
0x461121: mov ebp,esp
0x461123: and esp,0FFFFFFF8h
0x461126: push 0FFFFFFFFh
0x461128: push 73D713h
0x46112d: mov eax,fs:[0]
0x461133: push eax
0x461134: sub esp,64h
0x461137: mov eax,ds:[858220h]
0x46113c: xor eax,esp
0x46113e: mov [esp+5Ch],eax
0x461142: push ebx
0x461143: push esi
0x461144: mov eax,ds:[858220h]
0x461149: xor eax,esp
0x46114b: push eax
0x46114c: lea eax,[esp+70h]
0x461150: mov fs:[0],eax
0x461156: mov eax,[edi]
0x461158: mov edx,[eax+4]
0x46115b: mov ecx,edi
0x46115d: mov [esp+2Ch],edi
0x461161: call edx
0x461163: push 0
0x461165: lea ecx,[esp+10h]
0x461169: mov dword ptr [esp+7Ch],0
0x461171: call dword ptr ds:[77DE3Ch]
0x461177: mov byte ptr [esp+78h],1
0x46117c: cmp byte ptr [edi+8],0
0x461180: lea ecx,[esp+0Ch]
0x461184: jne short 004611A9h
0x461186: mov byte ptr [esp+78h],0
0x46118b: call dword ptr ds:[77DE38h]
0x461191: mov dword ptr [esp+78h],0FFFFFFFFh
0x461199: mov eax,[edi]
0x46119b: mov edx,[eax+0Ch]
0x46119e: mov ecx,edi
0x4611a0: call edx
0x4611a2: xor al,al
0x4611a4: jmp near ptr 0046133Eh
0x4611a9: mov ebx,ds:[77DE34h]
0x4611af: mov esi,[edi+14h]
0x4611b2: push 0E870001h
0x4611b7: call ebx
0x4611b9: test al,al
0x4611bb: lea ecx,[esp+0Ch]
0x4611bf: je short 00461186h
0x4611c1: push esi
0x4611c2: call ebx
0x4611c4: test al,al
0x4611c6: jne short 004611CEh
0x4611c8: lea ecx,[esp+0Ch]
0x4611cc: jmp short 00461186h
0x4611ce: mov eax,[edi+10h]
0x4611d1: mov ebx,[eax]
0x4611d3: lea esi,[edi+0Ch]
0x4611d6: mov [esp+20h],ebx
0x4611da: mov [esp+1Ch],esi
0x4611de: mov edi,edi
0x4611e0: test esi,esi
0x4611e2: mov ecx,[edi+10h]
0x4611e5: lea eax,[edi+0Ch]
0x4611e8: mov [esp+28h],ecx
0x4611ec: je short 004611F2h
0x4611ee: cmp esi,eax
0x4611f0: je short 004611F8h
0x4611f2: call dword ptr ds:[77D0E4h]
0x4611f8: cmp ebx,[esp+28h]
0x4611fc: je short 00461279h
0x4611fe: test esi,esi
0x461200: jne short 00461208h
0x461202: call dword ptr ds:[77D0E4h]
0x461208: cmp ebx,[esi+4]
0x46120b: jne short 0046121Eh
0x46120d: call dword ptr ds:[77D0E4h]
0x461213: cmp ebx,[esi+4]
0x461216: jne short 0046121Eh
0x461218: call dword ptr ds:[77D0E4h]
0x46121e: movzx edx,byte ptr [ebx+0Ch]
0x461222: push edx
0x461223: lea ecx,[esp+10h]
0x461227: lea esi,[ebx+2Ch]
0x46122a: call dword ptr ds:[77DE30h]
0x461230: test al,al
0x461232: lea ecx,[esp+0Ch]
0x461236: je near ptr 00461186h
0x46123c: add ebx,10h
0x46123f: push ebx
0x461240: call dword ptr ds:[77DE2Ch]
0x461246: test al,al
0x461248: lea ecx,[esp+0Ch]
0x46124c: je near ptr 00461186h
0x461252: push 1Ch
0x461254: push esi
0x461255: call dword ptr ds:[77DE28h]
0x46125b: test al,al
0x46125d: je near ptr 004611C8h
0x461263: lea esi,[esp+1Ch]
0x461267: call 00466900h
0x46126c: mov ebx,[esp+20h]
0x461270: mov esi,[esp+1Ch]
0x461274: jmp near ptr 004611E0h
0x461279: lea eax,[esp+30h]
0x46127d: push eax
0x46127e: call dword ptr ds:[77D144h]
0x461284: add esp,4
0x461287: mov esi,10h
0x46128c: mov byte ptr [esp+78h],2
0x461291: cmp [eax+18h],esi
0x461294: jb short 0046129Bh
0x461296: mov eax,[eax+4]
0x461299: jmp short 0046129Eh
0x46129b: add eax,4
0x46129e: push eax
0x46129f: lea ecx,[esp+50h]
0x4612a3: push 7CC4A8h
0x4612a8: push ecx
0x4612a9: call dword ptr ds:[77DF24h]
0x4612af: add esp,0Ch
0x4612b2: lea ecx,[esp+30h]
0x4612b6: mov byte ptr [esp+78h],4
0x4612bb: call dword ptr ds:[77CD74h]
0x4612c1: cmp [esp+64h],esi
0x4612c5: mov eax,[esp+50h]
0x4612c9: jae short 004612CFh
0x4612cb: lea eax,[esp+50h]
0x4612cf: push 7CC4C0h
0x4612d4: push eax
0x4612d5: call dword ptr ds:[77D088h]
0x4612db: mov esi,eax
0x4612dd: add esp,8
0x4612e0: test esi,esi
0x4612e2: je short 0046130Dh
0x4612e4: push esi
0x4612e5: lea ecx,[esp+10h]
0x4612e9: call dword ptr ds:[77DE20h]
0x4612ef: push eax
0x4612f0: push 1
0x4612f2: lea ecx,[esp+18h]
0x4612f6: call dword ptr ds:[77DE18h]
0x4612fc: push eax
0x4612fd: call dword ptr ds:[77D074h]
0x461303: push esi
0x461304: call dword ptr ds:[77D0F0h]
0x46130a: add esp,14h
0x46130d: lea ecx,[esp+4Ch]
0x461311: mov byte ptr [esp+78h],1
0x461316: call dword ptr ds:[77CD74h]
0x46131c: lea ecx,[esp+0Ch]
0x461320: mov byte ptr [esp+78h],0
0x461325: call dword ptr ds:[77DE38h]
0x46132b: mov dword ptr [esp+78h],0FFFFFFFFh
0x461333: mov edx,[edi]
0x461335: mov eax,[edx+0Ch]
0x461338: mov ecx,edi
0x46133a: call eax
0x46133c: mov al,1
0x46133e: mov ecx,[esp+70h]
0x461342: mov fs:[0],ecx
0x461349: pop ecx
0x46134a: pop esi
0x46134b: pop ebx
0x46134c: mov ecx,[esp+5Ch]
0x461350: xor ecx,esp
0x461352: call 00652739h
0x461357: mov esp,ebp
0x461359: pop ebp
0x46135a: ret
````

`sub_461120` is called by sub_460a70. It works with the text "%s\DownloadInfo.dn". It delegates to sub_466900, sub_652739 (2 callees).

### sub_4655a0 at 0x4655a0 (237 instructions)

````text
0x4655a0: push 0FFFFFFFFh
0x4655a2: push 7410D9h
0x4655a7: mov eax,fs:[0]
0x4655ad: push eax
0x4655ae: sub esp,44h
0x4655b1: push ebx
0x4655b2: push ebp
0x4655b3: push esi
0x4655b4: push edi
0x4655b5: mov eax,ds:[858220h]
0x4655ba: xor eax,esp
0x4655bc: push eax
0x4655bd: lea eax,[esp+58h]
0x4655c1: mov fs:[0],eax
0x4655c7: mov eax,[esp+74h]
0x4655cb: cmp byte ptr [eax+2Dh],0
0x4655cf: je short 0046560Dh
0x4655d1: push 7C5AECh
0x4655d6: lea ecx,[esp+18h]
0x4655da: call dword ptr ds:[77CD7Ch]
0x4655e0: lea eax,[esp+14h]
0x4655e4: push eax
0x4655e5: lea ecx,[esp+34h]
0x4655e9: mov dword ptr [esp+64h],0
0x4655f1: call 00401230h
0x4655f6: push 80A4F8h
0x4655fb: lea ecx,[esp+34h]
0x4655ff: push ecx
0x465600: mov dword ptr [esp+38h],790F90h
0x465608: call 00652AC4h
0x46560d: lea esi,[esp+70h]
0x465611: mov ebp,eax
0x465613: call 0043A360h
0x465618: mov eax,[ebp]
0x46561b: cmp byte ptr [eax+2Dh],0
0x46561f: je short 00465626h
0x465621: mov edi,[ebp+8]
0x465624: jmp short 0046563Eh
0x465626: mov edx,[ebp+8]
0x465629: cmp byte ptr [edx+2Dh],0
0x46562d: je short 00465633h
0x46562f: mov edi,eax
0x465631: jmp short 0046563Eh
0x465633: mov ecx,[esp+74h]
0x465637: cmp ecx,ebp
0x465639: mov edi,[ecx+8]
0x46563c: jne short 004656A9h
0x46563e: cmp byte ptr [edi+2Dh],0
0x465642: mov esi,[ebp+4]
0x465645: jne short 0046564Ah
0x465647: mov [edi+4],esi
0x46564a: mov edx,[esp+68h]
0x46564e: mov eax,[edx+4]
0x465651: cmp [eax+4],ebp
0x465654: jne short 0046565Bh
0x465656: mov [eax+4],edi
0x465659: jmp short 00465666h
0x46565b: cmp [esi],ebp
0x46565d: jne short 00465663h
0x46565f: mov [esi],edi
0x465661: jmp short 00465666h
0x465663: mov [esi+8],edi
0x465666: mov ebx,[edx+4]
0x465669: cmp [ebx],ebp
0x46566b: jne short 00465684h
0x46566d: cmp byte ptr [edi+2Dh],0
0x465671: je short 00465677h
0x465673: mov eax,esi
0x465675: jmp short 00465682h
0x465677: mov eax,edi
0x465679: call 004B4760h
0x46567e: mov edx,[esp+68h]
0x465682: mov [ebx],eax
0x465684: mov ebx,[edx+4]
0x465687: cmp [ebx+8],ebp
0x46568a: jne short 00465709h
0x46568c: cmp byte ptr [edi+2Dh],0
0x465690: je short 00465699h
0x465692: mov eax,esi
0x465694: mov [ebx+8],eax
0x465697: jmp short 00465709h
0x465699: mov eax,edi
0x46569b: call 005733F0h
0x4656a0: mov edx,[esp+68h]
0x4656a4: mov [ebx+8],eax
0x4656a7: jmp short 00465709h
0x4656a9: mov [eax+4],ecx
0x4656ac: mov eax,[ebp]
0x4656af: mov [ecx],eax
0x4656b1: cmp ecx,[ebp+8]
0x4656b4: jne short 004656BAh
0x4656b6: mov esi,ecx
0x4656b8: jmp short 004656D4h
0x4656ba: cmp byte ptr [edi+2Dh],0
0x4656be: mov esi,[ecx+4]
0x4656c1: jne short 004656C6h
0x4656c3: mov [edi+4],esi
0x4656c6: mov [esi],edi
0x4656c8: mov edx,[ebp+8]
0x4656cb: mov [ecx+8],edx
0x4656ce: mov eax,[ebp+8]
0x4656d1: mov [eax+4],ecx
0x4656d4: mov edx,[esp+68h]
0x4656d8: mov eax,[edx+4]
0x4656db: cmp [eax+4],ebp
0x4656de: jne short 004656E5h
0x4656e0: mov [eax+4],ecx
0x4656e3: jmp short 004656F3h
0x4656e5: mov eax,[ebp+4]
0x4656e8: cmp [eax],ebp
0x4656ea: jne short 004656F0h
0x4656ec: mov [eax],ecx
0x4656ee: jmp short 004656F3h
0x4656f0: mov [eax+8],ecx
0x4656f3: mov eax,[ebp+4]
0x4656f6: mov [ecx+4],eax
0x4656f9: mov dl,[ebp+2Ch]
0x4656fc: mov al,[ecx+2Ch]
0x4656ff: mov [ecx+2Ch],dl
0x465702: mov edx,[esp+68h]
0x465706: mov [ebp+2Ch],al
0x465709: mov bl,1
0x46570b: cmp [ebp+2Ch],bl
0x46570e: jne near ptr 00465817h
0x465714: mov eax,[edx+4]
0x465717: cmp edi,[eax+4]
0x46571a: je near ptr 00465814h
0x465720: cmp [edi+2Ch],bl
0x465723: jne near ptr 00465814h
0x465729: mov ecx,[esi]
0x46572b: cmp edi,ecx
0x46572d: jne short 0046579Ah
0x46572f: mov ecx,[esi+8]
0x465732: cmp byte ptr [ecx+2Ch],0
0x465736: jne short 0046574Eh
0x465738: mov [ecx+2Ch],bl
0x46573b: push edx
0x46573c: mov ecx,esi
0x46573e: mov byte ptr [esi+2Ch],0
0x465742: call 005733A0h
0x465747: mov ecx,[esi+8]
0x46574a: mov edx,[esp+68h]
0x46574e: cmp byte ptr [ecx+2Dh],0
0x465752: jne short 004657CEh
0x465754: mov eax,[ecx]
0x465756: cmp [eax+2Ch],bl
0x465759: jne short 00465763h
0x46575b: mov eax,[ecx+8]
0x46575e: cmp [eax+2Ch],bl
0x465761: je short 004657CAh
0x465763: mov eax,[ecx+8]
0x465766: cmp [eax+2Ch],bl
0x465769: jne short 00465781h
0x46576b: mov eax,[ecx]
0x46576d: mov [eax+2Ch],bl
0x465770: push edx
0x465771: mov byte ptr [ecx+2Ch],0
0x465775: call 00465F60h
0x46577a: mov ecx,[esi+8]
0x46577d: mov edx,[esp+68h]
0x465781: mov al,[esi+2Ch]
0x465784: mov [ecx+2Ch],al
0x465787: mov [esi+2Ch],bl
0x46578a: mov ecx,[ecx+8]
0x46578d: mov [ecx+2Ch],bl
0x465790: push edx
0x465791: mov ecx,esi
0x465793: call 005733A0h
0x465798: jmp short 00465814h
0x46579a: cmp byte ptr [ecx+2Ch],0
0x46579e: jne short 004657B5h
0x4657a0: mov [ecx+2Ch],bl
0x4657a3: push edx
0x4657a4: mov ecx,esi
0x4657a6: mov byte ptr [esi+2Ch],0
0x4657aa: call 00465F60h
0x4657af: mov ecx,[esi]
0x4657b1: mov edx,[esp+68h]
0x4657b5: cmp byte ptr [ecx+2Dh],0
0x4657b9: jne short 004657CEh
0x4657bb: mov eax,[ecx+8]
0x4657be: cmp [eax+2Ch],bl
0x4657c1: jne short 004657E1h
0x4657c3: mov eax,[ecx]
0x4657c5: cmp [eax+2Ch],bl
0x4657c8: jne short 004657E1h
0x4657ca: mov byte ptr [ecx+2Ch],0
0x4657ce: mov ecx,[edx+4]
0x4657d1: mov edi,esi
0x4657d3: cmp edi,[ecx+4]
0x4657d6: mov esi,[esi+4]
0x4657d9: jne near ptr 00465720h
0x4657df: jmp short 00465814h
0x4657e1: mov eax,[ecx]
0x4657e3: cmp [eax+2Ch],bl
0x4657e6: jne short 004657FEh
0x4657e8: mov eax,[ecx+8]
0x4657eb: mov [eax+2Ch],bl
0x4657ee: push edx
0x4657ef: mov byte ptr [ecx+2Ch],0
0x4657f3: call 005733A0h
0x4657f8: mov ecx,[esi]
0x4657fa: mov edx,[esp+68h]
0x4657fe: mov al,[esi+2Ch]
0x465801: mov [ecx+2Ch],al
0x465804: mov [esi+2Ch],bl
0x465807: mov ecx,[ecx]
0x465809: mov [ecx+2Ch],bl
0x46580c: push edx
0x46580d: mov ecx,esi
0x46580f: call 00465F60h
0x465814: mov [edi+2Ch],bl
0x465817: lea ecx,[ebp+10h]
0x46581a: call dword ptr ds:[77CD74h]
0x465820: push ebp
0x465821: call 006516BAh
0x465826: mov ecx,[esp+6Ch]
0x46582a: mov eax,[ecx+8]
0x46582d: add esp,4
0x465830: test eax,eax
0x465832: jbe short 0046583Ah
0x465834: add eax,0FFFFFFFFh
0x465837: mov [ecx+8],eax
0x46583a: mov eax,[esp+6Ch]
0x46583e: mov edx,[esp+70h]
0x465842: mov ecx,[esp+74h]
0x465846: mov [eax],edx
0x465848: mov [eax+4],ecx
0x46584b: mov ecx,[esp+58h]
0x46584f: mov fs:[0],ecx
0x465856: pop ecx
0x465857: pop edi
0x465858: pop esi
0x465859: pop ebp
0x46585a: pop ebx
0x46585b: add esp,50h
0x46585e: ret 10h
````

`sub_4655a0` is called by sub_4662f0. It delegates to sub_401230, sub_43a360, sub_465f60 (8 callees).

### sub_465c30 at 0x465c30 (83 instructions)

````text
0x465c30: push 0FFFFFFFFh
0x465c32: push 742088h
0x465c37: mov eax,fs:[0]
0x465c3d: push eax
0x465c3e: sub esp,68h
0x465c41: push ebx
0x465c42: push ebp
0x465c43: push esi
0x465c44: push edi
0x465c45: mov eax,ds:[858220h]
0x465c4a: xor eax,esp
0x465c4c: push eax
0x465c4d: lea eax,[esp+7Ch]
0x465c51: mov fs:[0],eax
0x465c57: mov edi,ecx
0x465c59: mov ebp,[esp+8Ch]
0x465c60: mov eax,ebp
0x465c62: call 004668B0h
0x465c67: test ebp,ebp
0x465c69: mov ebx,eax
0x465c6b: jne short 00465C73h
0x465c6d: call dword ptr ds:[77D0E4h]
0x465c73: cmp ebx,[ebp+4]
0x465c76: je short 00465C9Ch
0x465c78: mov al,[edi]
0x465c7a: mov cl,[ebx+0Ch]
0x465c7d: cmp al,cl
0x465c7f: jb short 00465C9Ch
0x465c81: ja near ptr 00465D0Dh
0x465c87: lea eax,[ebx+10h]
0x465c8a: push eax
0x465c8b: lea ecx,[edi+4]
0x465c8e: push ecx
0x465c8f: call dword ptr ds:[77CDA0h]
0x465c95: add esp,8
0x465c98: test al,al
0x465c9a: je short 00465D0Dh
0x465c9c: xor eax,eax
0x465c9e: lea edx,[esp+3Ch]
0x465ca2: push edx
0x465ca3: mov ecx,edi
0x465ca5: mov [esp+24h],eax
0x465ca9: mov [esp+28h],eax
0x465cad: mov [esp+2Ch],eax
0x465cb1: mov [esp+30h],eax
0x465cb5: mov [esp+34h],eax
0x465cb9: mov [esp+38h],eax
0x465cbd: mov [esp+3Ch],eax
0x465cc1: call 00403510h
0x465cc6: mov ecx,7
0x465ccb: lea esi,[esp+20h]
0x465ccf: lea edi,[esp+5Ch]
0x465cd3: rep movsd
0x465cd5: push ebx
0x465cd6: push ebp
0x465cd7: lea eax,[esp+44h]
0x465cdb: push eax
0x465cdc: lea ecx,[esp+24h]
0x465ce0: push ecx
0x465ce1: mov ebx,ebp
0x465ce3: mov dword ptr [esp+94h],0
0x465cee: call 00465FF0h
0x465cf3: mov ebp,[eax]
0x465cf5: mov ebx,[eax+4]
0x465cf8: lea ecx,[esp+40h]
0x465cfc: mov dword ptr [esp+84h],0FFFFFFFFh
0x465d07: call dword ptr ds:[77CD74h]
0x465d0d: test ebp,ebp
0x465d0f: jne short 00465D17h
0x465d11: call dword ptr ds:[77D0E4h]
0x465d17: cmp ebx,[ebp+4]
0x465d1a: jne short 00465D22h
0x465d1c: call dword ptr ds:[77D0E4h]
0x465d22: lea eax,[ebx+2Ch]
0x465d25: mov ecx,[esp+7Ch]
0x465d29: mov fs:[0],ecx
0x465d30: pop ecx
0x465d31: pop edi
0x465d32: pop esi
0x465d33: pop ebp
0x465d34: pop ebx
0x465d35: add esp,74h
0x465d38: ret 4
````

`sub_465c30` is called by sub_460da0. It delegates to sub_403510, sub_465ff0, sub_4668b0 (3 callees).

### ?get_mutable_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@SAAAV_DownloadInfo@@XZ at 0x465d40 (4 instructions)

````text
0x465d40: push ecx
0x465d41: call 00466280h
0x465d46: pop ecx
0x465d47: ret
````

`?get_mutable_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@SAAAV_DownloadInfo@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@CAAAV_DownloadInfo@@XZ (1 callees).

### sub_465d70 at 0x465d70 (25 instructions)

````text
0x465d70: push ebx
0x465d71: push esi
0x465d72: push edi
0x465d73: mov edi,[esp+10h]
0x465d77: cmp byte ptr [edi+2Dh],0
0x465d7b: mov ebx,ecx
0x465d7d: mov esi,edi
0x465d7f: jne short 00465DA8h
0x465d81: mov eax,[esi+8]
0x465d84: push eax
0x465d85: mov ecx,ebx
0x465d87: call 00465D70h
0x465d8c: mov esi,[esi]
0x465d8e: lea ecx,[edi+10h]
0x465d91: call dword ptr ds:[77CD74h]
0x465d97: push edi
0x465d98: call 006516BAh
0x465d9d: add esp,4
0x465da0: cmp byte ptr [esi+2Dh],0
0x465da4: mov edi,esi
0x465da6: je short 00465D81h
0x465da8: pop edi
0x465da9: pop esi
0x465daa: pop ebx
0x465dab: ret 4
````

`sub_465d70` is called by sub_465d70, sub_4662f0. It delegates to sub_465d70, j_ORDINAL 764 (2 callees).

### sub_465f60 at 0x465f60 (28 instructions)

````text
0x465f60: mov eax,[ecx]
0x465f62: mov edx,[eax+8]
0x465f65: mov [ecx],edx
0x465f67: mov edx,[eax+8]
0x465f6a: cmp byte ptr [edx+2Dh],0
0x465f6e: jne short 00465F73h
0x465f70: mov [edx+4],ecx
0x465f73: mov edx,[ecx+4]
0x465f76: mov [eax+4],edx
0x465f79: mov edx,[esp+4]
0x465f7d: mov edx,[edx+4]
0x465f80: cmp ecx,[edx+4]
0x465f83: jne short 00465F91h
0x465f85: mov [edx+4],eax
0x465f88: mov [eax+8],ecx
0x465f8b: mov [ecx+4],eax
0x465f8e: ret 4
0x465f91: mov edx,[ecx+4]
0x465f94: cmp ecx,[edx+8]
0x465f97: jne short 00465FA5h
0x465f99: mov [edx+8],eax
0x465f9c: mov [eax+8],ecx
0x465f9f: mov [ecx+4],eax
0x465fa2: ret 4
0x465fa5: mov [edx],eax
0x465fa7: mov [eax+8],ecx
0x465faa: mov [ecx+4],eax
0x465fad: ret 4
````

`sub_465f60` is called by sub_4655a0, sub_4b57e0, sub_573040. It calls nothing else.

### sub_465fb0 at 0x465fb0 (26 instructions)

````text
0x465fb0: push ebp
0x465fb1: mov ebp,esp
0x465fb3: and esp,0FFFFFFF8h
0x465fb6: sub esp,0Ch
0x465fb9: push edi
0x465fba: mov edi,eax
0x465fbc: mov eax,[edi+4]
0x465fbf: mov ecx,[eax]
0x465fc1: push eax
0x465fc2: push edi
0x465fc3: push ecx
0x465fc4: push edi
0x465fc5: lea eax,[esp+18h]
0x465fc9: push eax
0x465fca: call 004662F0h
0x465fcf: mov ecx,[edi+4]
0x465fd2: push ecx
0x465fd3: call 006516BAh
0x465fd8: add esp,4
0x465fdb: xor eax,eax
0x465fdd: mov [edi+4],eax
0x465fe0: mov [edi+8],eax
0x465fe3: pop edi
0x465fe4: mov esp,ebp
0x465fe6: pop ebp
0x465fe7: ret
````

`sub_465fb0` is called by sub_6245b0. It delegates to sub_4662f0, j_ORDINAL 764 (2 callees).

### sub_465ff0 at 0x465ff0 (191 instructions)

````text
0x465ff0: mov ecx,[ebx+4]
0x465ff3: sub esp,18h
0x465ff6: cmp dword ptr [ebx+8],0
0x465ffa: push ebp
0x465ffb: mov ebp,[esp+20h]
0x465fff: push esi
0x466000: push edi
0x466001: jne short 0046601Dh
0x466003: mov eax,[esp+2Ch]
0x466007: push eax
0x466008: push 1
0x46600a: push ebp
0x46600b: mov edi,ebx
0x46600d: call 00466710h
0x466012: mov eax,ebp
0x466014: pop edi
0x466015: pop esi
0x466016: pop ebp
0x466017: add esp,18h
0x46601a: ret 10h
0x46601d: mov edi,[esp+30h]
0x466021: test edi,edi
0x466023: mov edx,[ecx]
0x466025: mov [esp+18h],edx
0x466029: je short 0046602Fh
0x46602b: cmp edi,ebx
0x46602d: je short 00466035h
0x46602f: call dword ptr ds:[77D0E4h]
0x466035: mov esi,[esp+34h]
0x466039: cmp esi,[esp+18h]
0x46603d: jne short 0046606Dh
0x46603f: mov edi,[esp+2Ch]
0x466043: lea edx,[esi+0Ch]
0x466046: mov eax,edi
0x466048: call 0044F820h
0x46604d: test al,al
0x46604f: je near ptr 004661D8h
0x466055: push edi
0x466056: push 1
0x466058: push ebp
0x466059: mov ecx,esi
0x46605b: mov edi,ebx
0x46605d: call 00466710h
0x466062: mov eax,ebp
0x466064: pop edi
0x466065: pop esi
0x466066: pop ebp
0x466067: add esp,18h
0x46606a: ret 10h
0x46606d: test edi,edi
0x46606f: mov eax,[ebx+4]
0x466072: mov [esp+18h],eax
0x466076: je short 0046607Ch
0x466078: cmp edi,ebx
0x46607a: je short 00466082h
0x46607c: call dword ptr ds:[77D0E4h]
0x466082: cmp esi,[esp+18h]
0x466086: jne short 004660C2h
0x466088: mov ecx,[ebx+4]
0x46608b: mov eax,[ecx+8]
0x46608e: mov edx,[esp+2Ch]
0x466092: add eax,0Ch
0x466095: call 0044F820h
0x46609a: test al,al
0x46609c: je near ptr 004661D4h
0x4660a2: mov edx,[esp+2Ch]
0x4660a6: mov eax,[ebx+4]
0x4660a9: mov ecx,[eax+8]
0x4660ac: push edx
0x4660ad: push 0
0x4660af: push ebp
0x4660b0: mov edi,ebx
0x4660b2: call 00466710h
0x4660b7: mov eax,ebp
0x4660b9: pop edi
0x4660ba: pop esi
0x4660bb: pop ebp
0x4660bc: add esp,18h
0x4660bf: ret 10h
0x4660c2: mov edi,[esp+2Ch]
0x4660c6: lea edx,[esi+0Ch]
0x4660c9: mov eax,edi
0x4660cb: mov [esp+28h],edx
0x4660cf: call 0044F820h
0x4660d4: test al,al
0x4660d6: je short 0046613Bh
0x4660d8: mov ecx,[esp+30h]
0x4660dc: mov [esp+10h],esi
0x4660e0: lea esi,[esp+0Ch]
0x4660e4: mov [esp+0Ch],ecx
0x4660e8: call 00466DF0h
0x4660ed: mov esi,[esp+10h]
0x4660f1: lea eax,[esi+0Ch]
0x4660f4: mov edx,edi
0x4660f6: call 0044F820h
0x4660fb: test al,al
0x4660fd: je short 00466137h
0x4660ff: mov edx,[esi+8]
0x466102: cmp byte ptr [edx+49h],0
0x466106: push edi
0x466107: mov edi,ebx
0x466109: je short 00466120h
0x46610b: push 0
0x46610d: push ebp
0x46610e: mov ecx,esi
0x466110: call 00466710h
0x466115: mov eax,ebp
0x466117: pop edi
0x466118: pop esi
0x466119: pop ebp
0x46611a: add esp,18h
0x46611d: ret 10h
0x466120: mov ecx,[esp+38h]
0x466124: push 1
0x466126: push ebp
0x466127: call 00466710h
0x46612c: mov eax,ebp
0x46612e: pop edi
0x46612f: pop esi
0x466130: pop ebp
0x466131: add esp,18h
0x466134: ret 10h
0x466137: mov esi,[esp+34h]
0x46613b: mov eax,[esp+28h]
0x46613f: mov edx,edi
0x466141: call 0044F820h
0x466146: test al,al
0x466148: je near ptr 004661D4h
0x46614e: mov eax,[esp+30h]
0x466152: mov ecx,[ebx+4]
0x466155: mov [esp+10h],esi
0x466159: lea esi,[esp+0Ch]
0x46615d: mov [esp+0Ch],eax
0x466161: mov [esp+18h],ecx
0x466165: mov [esp+14h],ebx
0x466169: call 00466900h
0x46616e: lea esi,[esp+14h]
0x466172: lea edi,[esp+0Ch]
0x466176: call 005E56D0h
0x46617b: test al,al
0x46617d: mov esi,[esp+10h]
0x466181: jne short 00466193h
0x466183: mov eax,[esp+2Ch]
0x466187: lea edx,[esi+0Ch]
0x46618a: call 0044F820h
0x46618f: test al,al
0x466191: je short 004661D4h
0x466193: mov ecx,[esp+34h]
0x466197: mov edx,[ecx+8]
0x46619a: cmp byte ptr [edx+49h],0
0x46619e: mov edi,ebx
0x4661a0: je short 004661BAh
0x4661a2: mov eax,[esp+2Ch]
0x4661a6: push eax
0x4661a7: push 0
0x4661a9: push ebp
0x4661aa: call 00466710h
0x4661af: mov eax,ebp
0x4661b1: pop edi
0x4661b2: pop esi
0x4661b3: pop ebp
0x4661b4: add esp,18h
0x4661b7: ret 10h
0x4661ba: mov ecx,[esp+2Ch]
0x4661be: push ecx
0x4661bf: push 1
0x4661c1: push ebp
0x4661c2: mov ecx,esi
0x4661c4: call 00466710h
0x4661c9: mov eax,ebp
0x4661cb: pop edi
0x4661cc: pop esi
0x4661cd: pop ebp
0x4661ce: add esp,18h
0x4661d1: ret 10h
0x4661d4: mov edi,[esp+2Ch]
0x4661d8: lea edx,[esp+14h]
0x4661dc: push edx
0x4661dd: push ebx
0x4661de: mov eax,edi
0x4661e0: call 00466520h
0x4661e5: mov ecx,[eax]
0x4661e7: mov [ebp],ecx
0x4661ea: mov edx,[eax+4]
0x4661ed: pop edi
0x4661ee: pop esi
0x4661ef: mov [ebp+4],edx
0x4661f2: mov eax,ebp
0x4661f4: pop ebp
0x4661f5: add esp,18h
0x4661f8: ret 10h
````

`sub_465ff0` is called by sub_465c30. It delegates to sub_44f820, sub_466520, sub_466710 (6 callees).

### sub_466200 at 0x466200 (25 instructions)

````text
0x466200: push ebx
0x466201: push esi
0x466202: push edi
0x466203: mov edi,[esp+10h]
0x466207: cmp byte ptr [edi+49h],0
0x46620b: mov ebx,ecx
0x46620d: mov esi,edi
0x46620f: jne short 00466238h
0x466211: mov eax,[esi+8]
0x466214: push eax
0x466215: mov ecx,ebx
0x466217: call 00466200h
0x46621c: mov esi,[esi]
0x46621e: lea ecx,[edi+10h]
0x466221: call dword ptr ds:[77CD74h]
0x466227: push edi
0x466228: call 006516BAh
0x46622d: add esp,4
0x466230: cmp byte ptr [esi+49h],0
0x466234: mov edi,esi
0x466236: je short 00466211h
0x466238: pop edi
0x466239: pop esi
0x46623a: pop ebx
0x46623b: ret 4
````

`sub_466200` is called by sub_460da0, sub_466200, sub_466640. It delegates to sub_466200, j_ORDINAL 764 (2 callees).

### sub_466240 at 0x466240 (26 instructions)

````text
0x466240: push ebp
0x466241: mov ebp,esp
0x466243: and esp,0FFFFFFF8h
0x466246: sub esp,0Ch
0x466249: push edi
0x46624a: mov edi,eax
0x46624c: mov eax,[edi+4]
0x46624f: mov ecx,[eax]
0x466251: push eax
0x466252: push edi
0x466253: push ecx
0x466254: push edi
0x466255: lea eax,[esp+18h]
0x466259: push eax
0x46625a: call 00466640h
0x46625f: mov ecx,[edi+4]
0x466262: push ecx
0x466263: call 006516BAh
0x466268: add esp,4
0x46626b: xor eax,eax
0x46626d: mov [edi+4],eax
0x466270: mov [edi+8],eax
0x466273: pop edi
0x466274: mov esp,ebp
0x466276: pop ebp
0x466277: ret
````

`sub_466240` is called by sub_460a70. It delegates to sub_466640, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@CAAAV_DownloadInfo@@XZ at 0x466280 (25 instructions)

````text
0x466280: push 0FFFFFFFFh
0x466282: push 74E2DEh
0x466287: mov eax,fs:[0]
0x46628d: push eax
0x46628e: mov eax,ds:[858220h]
0x466293: push ecx
0x466294: xor eax,esp
0x466296: push eax
0x466297: lea eax,[esp+8]
0x46629b: mov fs:[0],eax
0x4662a1: mov eax,1
0x4662a6: test ds:[875D40h],al
0x4662ac: jne short 004662CEh
0x4662ae: or ds:[875D40h],eax
0x4662b4: mov dword ptr [esp+10h],0
0x4662bc: call 004609D0h
0x4662c1: push 77AF50h
0x4662c6: call 006527EDh
0x4662cb: add esp,4
0x4662ce: mov eax,875984h
0x4662d3: mov ecx,[esp+8]
0x4662d7: mov fs:[0],ecx
0x4662de: pop ecx
0x4662df: add esp,10h
0x4662e2: ret
````

`?get_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@CAAAV_DownloadInfo@@XZ` is called by ?get_mutable_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@SAAAV_DownloadInfo@@XZ. It delegates to sub_4609d0, sub_6527ed (2 callees).

### sub_4662f0 at 0x4662f0 (72 instructions)

````text
0x4662f0: mov eax,[edi+4]
0x4662f3: sub esp,0Ch
0x4662f6: push ebx
0x4662f7: mov ebx,[esp+18h]
0x4662fb: test ebx,ebx
0x4662fd: push ebp
0x4662fe: push esi
0x4662ff: mov esi,[eax]
0x466301: je short 00466307h
0x466303: cmp ebx,edi
0x466305: je short 0046630Dh
0x466307: call dword ptr ds:[77D0E4h]
0x46630d: mov ebp,[esp+24h]
0x466311: cmp ebp,esi
0x466313: jne short 00466370h
0x466315: mov eax,[esp+28h]
0x466319: test eax,eax
0x46631b: mov esi,[edi+4]
0x46631e: je short 00466324h
0x466320: cmp eax,edi
0x466322: je short 0046632Ah
0x466324: call dword ptr ds:[77D0E4h]
0x46632a: cmp [esp+2Ch],esi
0x46632e: jne short 00466370h
0x466330: mov ecx,[edi+4]
0x466333: mov edx,[ecx+4]
0x466336: push edx
0x466337: mov ecx,edi
0x466339: call 00465D70h
0x46633e: mov eax,[edi+4]
0x466341: mov [eax+4],eax
0x466344: mov eax,[edi+4]
0x466347: mov dword ptr [edi+8],0
0x46634e: mov [eax],eax
0x466350: mov eax,[edi+4]
0x466353: mov [eax+8],eax
0x466356: mov eax,[edi+4]
0x466359: mov ecx,[eax]
0x46635b: mov eax,[esp+1Ch]
0x46635f: mov [eax+4],ecx
0x466362: mov [eax],edi
0x466364: pop esi
0x466365: pop ebp
0x466366: pop ebx
0x466367: add esp,0Ch
0x46636a: ret 14h
0x466370: test ebx,ebx
0x466372: je short 0046637Ah
0x466374: cmp ebx,[esp+28h]
0x466378: je short 00466380h
0x46637a: call dword ptr ds:[77D0E4h]
0x466380: cmp ebp,[esp+2Ch]
0x466384: je short 004663A6h
0x466386: lea esi,[esp+20h]
0x46638a: call 0043A360h
0x46638f: push ebp
0x466390: push ebx
0x466391: lea edx,[esp+18h]
0x466395: push edx
0x466396: push edi
0x466397: call 004655A0h
0x46639c: mov ebp,[esp+24h]
0x4663a0: mov ebx,[esp+20h]
0x4663a4: jmp short 00466370h
0x4663a6: mov eax,[esp+1Ch]
0x4663aa: pop esi
0x4663ab: mov [eax+4],ebp
0x4663ae: pop ebp
0x4663af: mov [eax],ebx
0x4663b1: pop ebx
0x4663b2: add esp,0Ch
0x4663b5: ret 14h
````

`sub_4662f0` is called by sub_465fb0. It delegates to sub_43a360, sub_4655a0, sub_465d70 (3 callees).

### sub_4664c0 at 0x4664c0 (37 instructions)

````text
0x4664c0: push ebx
0x4664c1: push edi
0x4664c2: mov edi,eax
0x4664c4: xor ebx,ebx
0x4664c6: cmp [edi+10h],ebx
0x4664c9: je short 004664DAh
0x4664cb: jmp short 004664D0h
0x4664d0: call 004669C0h
0x4664d5: cmp [edi+10h],ebx
0x4664d8: jne short 004664D0h
0x4664da: push esi
0x4664db: mov esi,[edi+8]
0x4664de: cmp esi,ebx
0x4664e0: jbe short 004664FFh
0x4664e2: mov eax,[edi+4]
0x4664e5: sub esi,1
0x4664e8: cmp [eax+esi*4],ebx
0x4664eb: lea eax,[eax+esi*4]
0x4664ee: je short 004664FBh
0x4664f0: mov ecx,[eax]
0x4664f2: push ecx
0x4664f3: call 006516BAh
0x4664f8: add esp,4
0x4664fb: cmp esi,ebx
0x4664fd: ja short 004664E2h
0x4664ff: mov eax,[edi+4]
0x466502: cmp eax,ebx
0x466504: pop esi
0x466505: je short 00466510h
0x466507: push eax
0x466508: call 006516BAh
0x46650d: add esp,4
0x466510: mov [edi+4],ebx
0x466513: mov [edi+8],ebx
0x466516: pop edi
0x466517: pop ebx
0x466518: ret
````

`sub_4664c0` is called by sub_4ddb30, sub_5d8f50, sub_5ea9c0, sub_63d180. It delegates to sub_4669c0, j_ORDINAL 764 (2 callees).

### sub_466520 at 0x466520 (114 instructions)

````text
0x466520: sub esp,0Ch
0x466523: mov edx,[esp+10h]
0x466527: push ebx
0x466528: push ebp
0x466529: mov ebp,[esp+1Ch]
0x46652d: push esi
0x46652e: push edi
0x46652f: mov edi,eax
0x466531: mov eax,[edx+4]
0x466534: mov esi,[eax+4]
0x466537: cmp byte ptr [esi+49h],0
0x46653b: mov ebx,eax
0x46653d: mov al,1
0x46653f: mov [esp+24h],al
0x466543: jne short 00466584h
0x466545: mov al,[edi]
0x466547: mov cl,[esi+0Ch]
0x46654a: cmp al,cl
0x46654c: mov ebx,esi
0x46654e: jae short 00466554h
0x466550: mov al,1
0x466552: jmp short 0046656Bh
0x466554: jbe short 0046655Ah
0x466556: xor al,al
0x466558: jmp short 0046656Bh
0x46655a: lea eax,[esi+10h]
0x46655d: push eax
0x46655e: lea ecx,[edi+4]
0x466561: push ecx
0x466562: call dword ptr ds:[77CDA0h]
0x466568: add esp,8
0x46656b: test al,al
0x46656d: mov [esp+24h],al
0x466571: je short 00466577h
0x466573: mov esi,[esi]
0x466575: jmp short 0046657Ah
0x466577: mov esi,[esi+8]
0x46657a: cmp byte ptr [esi+49h],0
0x46657e: je short 00466545h
0x466580: mov edx,[esp+20h]
0x466584: test al,al
0x466586: mov esi,ebx
0x466588: mov [esp+14h],esi
0x46658c: mov [esp+10h],edx
0x466590: je short 004665D2h
0x466592: mov eax,[edx+4]
0x466595: cmp ebx,[eax]
0x466597: jne short 004665C5h
0x466599: push edi
0x46659a: push 1
0x46659c: lea ecx,[esp+18h]
0x4665a0: push ecx
0x4665a1: mov ecx,ebx
0x4665a3: mov edi,edx
0x4665a5: call 00466710h
0x4665aa: mov edx,[eax]
0x4665ac: mov eax,[eax+4]
0x4665af: mov [ebp+4],eax
0x4665b2: mov [ebp],edx
0x4665b5: mov byte ptr [ebp+8],1
0x4665b9: mov eax,ebp
0x4665bb: pop edi
0x4665bc: pop esi
0x4665bd: pop ebp
0x4665be: pop ebx
0x4665bf: add esp,0Ch
0x4665c2: ret 8
0x4665c5: lea esi,[esp+10h]
0x4665c9: call 00466DF0h
0x4665ce: mov esi,[esp+14h]
0x4665d2: mov al,[esi+0Ch]
0x4665d5: mov cl,[edi]
0x4665d7: cmp al,cl
0x4665d9: jb short 004665F2h
0x4665db: ja short 00466623h
0x4665dd: lea ecx,[edi+4]
0x4665e0: push ecx
0x4665e1: lea edx,[esi+10h]
0x4665e4: push edx
0x4665e5: call dword ptr ds:[77CDA0h]
0x4665eb: add esp,8
0x4665ee: test al,al
0x4665f0: je short 00466623h
0x4665f2: mov eax,[esp+24h]
0x4665f6: push edi
0x4665f7: mov edi,[esp+24h]
0x4665fb: push eax
0x4665fc: lea ecx,[esp+18h]
0x466600: push ecx
0x466601: mov ecx,ebx
0x466603: call 00466710h
0x466608: mov edx,[eax]
0x46660a: mov eax,[eax+4]
0x46660d: mov [ebp+4],eax
0x466610: mov [ebp],edx
0x466613: mov byte ptr [ebp+8],1
0x466617: mov eax,ebp
0x466619: pop edi
0x46661a: pop esi
0x46661b: pop ebp
0x46661c: pop ebx
0x46661d: add esp,0Ch
0x466620: ret 8
0x466623: mov ecx,[esp+10h]
0x466627: pop edi
0x466628: mov [ebp+4],esi
0x46662b: pop esi
0x46662c: mov [ebp],ecx
0x46662f: mov byte ptr [ebp+8],0
0x466633: mov eax,ebp
0x466635: pop ebp
0x466636: pop ebx
0x466637: add esp,0Ch
0x46663a: ret 8
````

`sub_466520` is called by sub_465ff0. It delegates to sub_466710, sub_466df0 (2 callees).

### sub_466640 at 0x466640 (72 instructions)

````text
0x466640: mov eax,[edi+4]
0x466643: sub esp,0Ch
0x466646: push ebx
0x466647: mov ebx,[esp+18h]
0x46664b: test ebx,ebx
0x46664d: push ebp
0x46664e: push esi
0x46664f: mov esi,[eax]
0x466651: je short 00466657h
0x466653: cmp ebx,edi
0x466655: je short 0046665Dh
0x466657: call dword ptr ds:[77D0E4h]
0x46665d: mov ebp,[esp+24h]
0x466661: cmp ebp,esi
0x466663: jne short 004666C0h
0x466665: mov eax,[esp+28h]
0x466669: test eax,eax
0x46666b: mov esi,[edi+4]
0x46666e: je short 00466674h
0x466670: cmp eax,edi
0x466672: je short 0046667Ah
0x466674: call dword ptr ds:[77D0E4h]
0x46667a: cmp [esp+2Ch],esi
0x46667e: jne short 004666C0h
0x466680: mov ecx,[edi+4]
0x466683: mov edx,[ecx+4]
0x466686: push edx
0x466687: mov ecx,edi
0x466689: call 00466200h
0x46668e: mov eax,[edi+4]
0x466691: mov [eax+4],eax
0x466694: mov eax,[edi+4]
0x466697: mov dword ptr [edi+8],0
0x46669e: mov [eax],eax
0x4666a0: mov eax,[edi+4]
0x4666a3: mov [eax+8],eax
0x4666a6: mov eax,[edi+4]
0x4666a9: mov ecx,[eax]
0x4666ab: mov eax,[esp+1Ch]
0x4666af: mov [eax+4],ecx
0x4666b2: mov [eax],edi
0x4666b4: pop esi
0x4666b5: pop ebp
0x4666b6: pop ebx
0x4666b7: add esp,0Ch
0x4666ba: ret 14h
0x4666c0: test ebx,ebx
0x4666c2: je short 004666CAh
0x4666c4: cmp ebx,[esp+28h]
0x4666c8: je short 004666D0h
0x4666ca: call dword ptr ds:[77D0E4h]
0x4666d0: cmp ebp,[esp+2Ch]
0x4666d4: je short 004666F6h
0x4666d6: lea esi,[esp+20h]
0x4666da: call 00466900h
0x4666df: push ebp
0x4666e0: push ebx
0x4666e1: lea edx,[esp+18h]
0x4666e5: push edx
0x4666e6: push edi
0x4666e7: call 00466A30h
0x4666ec: mov ebp,[esp+24h]
0x4666f0: mov ebx,[esp+20h]
0x4666f4: jmp short 004666C0h
0x4666f6: mov eax,[esp+1Ch]
0x4666fa: pop esi
0x4666fb: mov [eax+4],ebp
0x4666fe: pop ebp
0x4666ff: mov [eax],ebx
0x466701: pop ebx
0x466702: add esp,0Ch
0x466705: ret 14h
````

`sub_466640` is called by sub_466240. It delegates to sub_466200, sub_466900, sub_466a30 (3 callees).

### sub_466710 at 0x466710 (138 instructions)

````text
0x466710: push 0FFFFFFFFh
0x466712: push 740349h
0x466717: mov eax,fs:[0]
0x46671d: push eax
0x46671e: sub esp,4Ch
0x466721: push ebx
0x466722: push ebp
0x466723: push esi
0x466724: mov eax,ds:[858220h]
0x466729: xor eax,esp
0x46672b: push eax
0x46672c: lea eax,[esp+5Ch]
0x466730: mov fs:[0],eax
0x466736: mov esi,ecx
0x466738: cmp dword ptr [edi+8],4444443h
0x46673f: jb short 0046677Dh
0x466741: push 7C5AD8h
0x466746: lea ecx,[esp+18h]
0x46674a: call dword ptr ds:[77CD7Ch]
0x466750: lea eax,[esp+14h]
0x466754: push eax
0x466755: lea ecx,[esp+34h]
0x466759: mov dword ptr [esp+68h],0
0x466761: call 00401230h
0x466766: push 80A274h
0x46676b: lea ecx,[esp+34h]
0x46676f: push ecx
0x466770: mov dword ptr [esp+38h],78FFECh
0x466778: call 00652AC4h
0x46677d: mov eax,[edi+4]
0x466780: mov ecx,[esp+74h]
0x466784: push eax
0x466785: push esi
0x466786: push eax
0x466787: call 00466D20h
0x46678c: mov ebp,eax
0x46678e: mov eax,[edi+4]
0x466791: mov ebx,1
0x466796: add [edi+8],ebx
0x466799: cmp esi,eax
0x46679b: jne short 004667AAh
0x46679d: mov [eax+4],ebp
0x4667a0: mov edx,[edi+4]
0x4667a3: mov [edx],ebp
0x4667a5: mov eax,[edi+4]
0x4667a8: jmp short 004667C9h
0x4667aa: cmp byte ptr [esp+70h],0
0x4667af: je short 004667BEh
0x4667b1: mov [esi],ebp
0x4667b3: mov eax,[edi+4]
0x4667b6: cmp esi,[eax]
0x4667b8: jne short 004667CCh
0x4667ba: mov [eax],ebp
0x4667bc: jmp short 004667CCh
0x4667be: mov [esi+8],ebp
0x4667c1: mov eax,[edi+4]
0x4667c4: cmp esi,[eax+8]
0x4667c7: jne short 004667CCh
0x4667c9: mov [eax+8],ebp
0x4667cc: mov ecx,[ebp+4]
0x4667cf: cmp byte ptr [ecx+48h],0
0x4667d3: lea eax,[ebp+4]
0x4667d6: mov esi,ebp
0x4667d8: jne near ptr 00466889h
0x4667de: mov edi,edi
0x4667e0: mov ecx,[eax]
0x4667e2: mov edx,[ecx+4]
0x4667e5: cmp ecx,[edx]
0x4667e7: jne short 00466833h
0x4667e9: mov edx,[edx+8]
0x4667ec: cmp byte ptr [edx+48h],0
0x4667f0: jne short 00466808h
0x4667f2: mov [ecx+48h],bl
0x4667f5: mov [edx+48h],bl
0x4667f8: mov edx,[eax]
0x4667fa: mov ecx,[edx+4]
0x4667fd: mov byte ptr [ecx+48h],0
0x466801: mov edx,[eax]
0x466803: mov esi,[edx+4]
0x466806: jmp short 00466879h
0x466808: cmp esi,[ecx+8]
0x46680b: jne short 00466815h
0x46680d: push edi
0x46680e: mov esi,ecx
0x466810: call 0044FAD0h
0x466815: mov eax,[esi+4]
0x466818: mov [eax+48h],bl
0x46681b: mov ecx,[esi+4]
0x46681e: mov edx,[ecx+4]
0x466821: mov byte ptr [edx+48h],0
0x466825: mov eax,[esi+4]
0x466828: mov ecx,[eax+4]
0x46682b: push edi
0x46682c: call 0044FB20h
0x466831: jmp short 00466879h
0x466833: mov edx,[edx]
0x466835: cmp byte ptr [edx+48h],0
0x466839: jne short 00466851h
0x46683b: mov [ecx+48h],bl
0x46683e: mov [edx+48h],bl
0x466841: mov edx,[eax]
0x466843: mov ecx,[edx+4]
0x466846: mov byte ptr [ecx+48h],0
0x46684a: mov edx,[eax]
0x46684c: mov esi,[edx+4]
0x46684f: jmp short 00466879h
0x466851: cmp esi,[ecx]
0x466853: jne short 0046685Dh
0x466855: push edi
0x466856: mov esi,ecx
0x466858: call 0044FB20h
0x46685d: mov eax,[esi+4]
0x466860: mov [eax+48h],bl
0x466863: mov ecx,[esi+4]
0x466866: mov edx,[ecx+4]
0x466869: mov byte ptr [edx+48h],0
0x46686d: mov eax,[esi+4]
0x466870: mov ecx,[eax+4]
0x466873: push edi
0x466874: call 0044FAD0h
0x466879: mov ecx,[esi+4]
0x46687c: cmp byte ptr [ecx+48h],0
0x466880: lea eax,[esi+4]
0x466883: je near ptr 004667E0h
0x466889: mov edx,[edi+4]
0x46688c: mov eax,[edx+4]
0x46688f: mov [eax+48h],bl
0x466892: mov eax,[esp+6Ch]
0x466896: mov [eax+4],ebp
0x466899: mov [eax],edi
0x46689b: mov ecx,[esp+5Ch]
0x46689f: mov fs:[0],ecx
0x4668a6: pop ecx
0x4668a7: pop esi
0x4668a8: pop ebp
0x4668a9: pop ebx
0x4668aa: add esp,58h
0x4668ad: ret 0Ch
````

`sub_466710` is called by sub_465ff0, sub_466520. It delegates to sub_401230, sub_44fad0, sub_44fb20 (5 callees).

### sub_4668b0 at 0x4668b0 (33 instructions)

````text
0x4668b0: mov eax,[eax+4]
0x4668b3: push ebp
0x4668b4: push esi
0x4668b5: mov esi,[eax+4]
0x4668b8: cmp byte ptr [esi+49h],0
0x4668bc: mov ebp,eax
0x4668be: jne short 004668F5h
0x4668c0: push ebx
0x4668c1: mov ebx,ds:[77CDA0h]
0x4668c7: mov al,[esi+0Ch]
0x4668ca: mov cl,[edi]
0x4668cc: cmp al,cl
0x4668ce: jb short 004668E3h
0x4668d0: ja short 004668E8h
0x4668d2: lea ecx,[edi+4]
0x4668d5: push ecx
0x4668d6: lea edx,[esi+10h]
0x4668d9: push edx
0x4668da: call ebx
0x4668dc: add esp,8
0x4668df: test al,al
0x4668e1: je short 004668E8h
0x4668e3: mov esi,[esi+8]
0x4668e6: jmp short 004668ECh
0x4668e8: mov ebp,esi
0x4668ea: mov esi,[esi]
0x4668ec: cmp byte ptr [esi+49h],0
0x4668f0: je short 004668C7h
0x4668f2: mov eax,ebp
0x4668f4: pop ebx
0x4668f5: pop esi
0x4668f6: pop ebp
0x4668f7: ret
````

`sub_4668b0` is called by sub_465c30. It calls nothing else.

### sub_466900 at 0x466900 (39 instructions)

````text
0x466900: cmp dword ptr [esi],0
0x466903: push edi
0x466904: mov edi,ds:[77D0E4h]
0x46690a: jne short 0046690Eh
0x46690c: call edi
0x46690e: mov eax,[esi+4]
0x466911: cmp byte ptr [eax+49h],0
0x466915: je short 0046691Bh
0x466917: call edi
0x466919: pop edi
0x46691a: ret
0x46691b: mov ecx,[eax+8]
0x46691e: cmp byte ptr [ecx+49h],0
0x466922: jne short 0046693Fh
0x466924: mov eax,[ecx]
0x466926: cmp byte ptr [eax+49h],0
0x46692a: jne short 0046693Ah
0x46692c: lea esp,[esp]
0x466930: mov ecx,eax
0x466932: mov eax,[ecx]
0x466934: cmp byte ptr [eax+49h],0
0x466938: je short 00466930h
0x46693a: mov [esi+4],ecx
0x46693d: pop edi
0x46693e: ret
0x46693f: mov eax,[eax+4]
0x466942: cmp byte ptr [eax+49h],0
0x466946: jne short 0046695Eh
0x466948: mov ecx,[esi+4]
0x46694b: cmp ecx,[eax+8]
0x46694e: jne short 0046695Eh
0x466950: mov [esi+4],eax
0x466953: mov edx,eax
0x466955: mov eax,[edx+4]
0x466958: cmp byte ptr [eax+49h],0
0x46695c: je short 00466948h
0x46695e: mov [esi+4],eax
0x466961: pop edi
0x466962: ret
````

`sub_466900` is called by sub_461120, sub_465ff0, sub_466640, sub_466a30. It calls nothing else.

### sub_4669c0 at 0x4669c0 (40 instructions)

````text
0x4669c0: mov eax,[edi+10h]
0x4669c3: test eax,eax
0x4669c5: je short 00466A27h
0x4669c7: mov ecx,[edi+0Ch]
0x4669ca: mov edx,[edi+8]
0x4669cd: lea eax,[eax+ecx-1]
0x4669d1: mov ecx,eax
0x4669d3: shr ecx,1
0x4669d5: cmp edx,ecx
0x4669d7: ja short 004669DBh
0x4669d9: sub ecx,edx
0x4669db: mov edx,[edi+4]
0x4669de: mov ecx,[edx+ecx*4]
0x4669e1: and eax,1
0x4669e4: lea eax,[ecx+eax*8+4]
0x4669e8: push esi
0x4669e9: mov esi,[eax]
0x4669eb: test esi,esi
0x4669ed: je short 00466A19h
0x4669ef: lea edx,[esi+4]
0x4669f2: or eax,0FFFFFFFFh
0x4669f5: lock xadd [edx],eax
0x4669f9: jne short 00466A19h
0x4669fb: mov edx,[esi]
0x4669fd: mov eax,[edx+4]
0x466a00: mov ecx,esi
0x466a02: call eax
0x466a04: lea ecx,[esi+8]
0x466a07: or edx,0FFFFFFFFh
0x466a0a: lock xadd [ecx],edx
0x466a0e: jne short 00466A19h
0x466a10: mov eax,[esi]
0x466a12: mov edx,[eax+8]
0x466a15: mov ecx,esi
0x466a17: call edx
0x466a19: add dword ptr [edi+10h],0FFFFFFFFh
0x466a1d: pop esi
0x466a1e: jne short 00466A27h
0x466a20: mov dword ptr [edi+0Ch],0
0x466a27: ret
````

`sub_4669c0` is called by sub_4664c0. It calls nothing else.

### sub_466a30 at 0x466a30 (246 instructions)

````text
0x466a30: push 0FFFFFFFFh
0x466a32: push 7410D9h
0x466a37: mov eax,fs:[0]
0x466a3d: push eax
0x466a3e: sub esp,44h
0x466a41: push ebx
0x466a42: push ebp
0x466a43: push esi
0x466a44: push edi
0x466a45: mov eax,ds:[858220h]
0x466a4a: xor eax,esp
0x466a4c: push eax
0x466a4d: lea eax,[esp+58h]
0x466a51: mov fs:[0],eax
0x466a57: mov eax,[esp+74h]
0x466a5b: cmp byte ptr [eax+49h],0
0x466a5f: je short 00466A9Dh
0x466a61: push 7C5AECh
0x466a66: lea ecx,[esp+18h]
0x466a6a: call dword ptr ds:[77CD7Ch]
0x466a70: lea eax,[esp+14h]
0x466a74: push eax
0x466a75: lea ecx,[esp+34h]
0x466a79: mov dword ptr [esp+64h],0
0x466a81: call 00401230h
0x466a86: push 80A4F8h
0x466a8b: lea ecx,[esp+34h]
0x466a8f: push ecx
0x466a90: mov dword ptr [esp+38h],790F90h
0x466a98: call 00652AC4h
0x466a9d: lea esi,[esp+70h]
0x466aa1: mov ebp,eax
0x466aa3: call 00466900h
0x466aa8: mov eax,[ebp]
0x466aab: cmp byte ptr [eax+49h],0
0x466aaf: je short 00466AB6h
0x466ab1: mov edi,[ebp+8]
0x466ab4: jmp short 00466ACEh
0x466ab6: mov edx,[ebp+8]
0x466ab9: cmp byte ptr [edx+49h],0
0x466abd: je short 00466AC3h
0x466abf: mov edi,eax
0x466ac1: jmp short 00466ACEh
0x466ac3: mov ecx,[esp+74h]
0x466ac7: cmp ecx,ebp
0x466ac9: mov edi,[ecx+8]
0x466acc: jne short 00466B42h
0x466ace: cmp byte ptr [edi+49h],0
0x466ad2: mov esi,[ebp+4]
0x466ad5: jne short 00466ADAh
0x466ad7: mov [edi+4],esi
0x466ada: mov ecx,[esp+68h]
0x466ade: mov eax,[ecx+4]
0x466ae1: cmp [eax+4],ebp
0x466ae4: jne short 00466AEBh
0x466ae6: mov [eax+4],edi
0x466ae9: jmp short 00466AF6h
0x466aeb: cmp [esi],ebp
0x466aed: jne short 00466AF3h
0x466aef: mov [esi],edi
0x466af1: jmp short 00466AF6h
0x466af3: mov [esi+8],edi
0x466af6: mov edx,[ecx+4]
0x466af9: cmp [edx],ebp
0x466afb: jne short 00466B1Dh
0x466afd: cmp byte ptr [edi+49h],0
0x466b01: je short 00466B07h
0x466b03: mov ecx,esi
0x466b05: jmp short 00466B1Bh
0x466b07: mov eax,[edi]
0x466b09: cmp byte ptr [eax+49h],0
0x466b0d: mov ecx,edi
0x466b0f: jne short 00466B1Bh
0x466b11: mov ecx,eax
0x466b13: mov eax,[ecx]
0x466b15: cmp byte ptr [eax+49h],0
0x466b19: je short 00466B11h
0x466b1b: mov [edx],ecx
0x466b1d: mov eax,[esp+68h]
0x466b21: mov ebx,[eax+4]
0x466b24: cmp [ebx+8],ebp
0x466b27: jne short 00466B9Eh
0x466b29: cmp byte ptr [edi+49h],0
0x466b2d: je short 00466B36h
0x466b2f: mov eax,esi
0x466b31: mov [ebx+8],eax
0x466b34: jmp short 00466B9Eh
0x466b36: mov eax,edi
0x466b38: call 00466DD0h
0x466b3d: mov [ebx+8],eax
0x466b40: jmp short 00466B9Eh
0x466b42: mov [eax+4],ecx
0x466b45: mov edx,[ebp]
0x466b48: mov [ecx],edx
0x466b4a: cmp ecx,[ebp+8]
0x466b4d: jne short 00466B53h
0x466b4f: mov esi,ecx
0x466b51: jmp short 00466B6Dh
0x466b53: cmp byte ptr [edi+49h],0
0x466b57: mov esi,[ecx+4]
0x466b5a: jne short 00466B5Fh
0x466b5c: mov [edi+4],esi
0x466b5f: mov [esi],edi
0x466b61: mov eax,[ebp+8]
0x466b64: mov [ecx+8],eax
0x466b67: mov edx,[ebp+8]
0x466b6a: mov [edx+4],ecx
0x466b6d: mov eax,[esp+68h]
0x466b71: mov eax,[eax+4]
0x466b74: cmp [eax+4],ebp
0x466b77: jne short 00466B7Eh
0x466b79: mov [eax+4],ecx
0x466b7c: jmp short 00466B8Ch
0x466b7e: mov eax,[ebp+4]
0x466b81: cmp [eax],ebp
0x466b83: jne short 00466B89h
0x466b85: mov [eax],ecx
0x466b87: jmp short 00466B8Ch
0x466b89: mov [eax+8],ecx
0x466b8c: mov edx,[ebp+4]
0x466b8f: mov [ecx+4],edx
0x466b92: mov dl,[ebp+48h]
0x466b95: mov al,[ecx+48h]
0x466b98: mov [ecx+48h],dl
0x466b9b: mov [ebp+48h],al
0x466b9e: mov bl,1
0x466ba0: cmp [ebp+48h],bl
0x466ba3: jne near ptr 00466CCAh
0x466ba9: mov eax,[esp+68h]
0x466bad: mov ecx,[eax+4]
0x466bb0: cmp edi,[ecx+4]
0x466bb3: je near ptr 00466CC7h
0x466bb9: lea esp,[esp]
0x466bc0: cmp [edi+48h],bl
0x466bc3: jne near ptr 00466CC7h
0x466bc9: mov ecx,[esi]
0x466bcb: cmp edi,ecx
0x466bcd: jne short 00466C45h
0x466bcf: mov ecx,[esi+8]
0x466bd2: cmp byte ptr [ecx+48h],0
0x466bd6: jne short 00466BEEh
0x466bd8: mov edx,[esp+68h]
0x466bdc: mov [ecx+48h],bl
0x466bdf: push edx
0x466be0: mov ecx,esi
0x466be2: mov byte ptr [esi+48h],0
0x466be6: call 0044FAD0h
0x466beb: mov ecx,[esi+8]
0x466bee: cmp byte ptr [ecx+49h],0
0x466bf2: jne near ptr 00466C79h
0x466bf8: mov eax,[ecx]
0x466bfa: cmp [eax+48h],bl
0x466bfd: jne short 00466C07h
0x466bff: mov edx,[ecx+8]
0x466c02: cmp [edx+48h],bl
0x466c05: je short 00466C75h
0x466c07: mov eax,[ecx+8]
0x466c0a: cmp [eax+48h],bl
0x466c0d: jne short 00466C25h
0x466c0f: mov edx,[ecx]
0x466c11: mov eax,[esp+68h]
0x466c15: mov [edx+48h],bl
0x466c18: push eax
0x466c19: mov byte ptr [ecx+48h],0
0x466c1d: call 0044FB20h
0x466c22: mov ecx,[esi+8]
0x466c25: mov dl,[esi+48h]
0x466c28: mov [ecx+48h],dl
0x466c2b: mov [esi+48h],bl
0x466c2e: mov eax,[ecx+8]
0x466c31: mov ecx,[esp+68h]
0x466c35: push ecx
0x466c36: mov ecx,esi
0x466c38: mov [eax+48h],bl
0x466c3b: call 0044FAD0h
0x466c40: jmp near ptr 00466CC7h
0x466c45: cmp byte ptr [ecx+48h],0
0x466c49: jne short 00466C60h
0x466c4b: mov eax,[esp+68h]
0x466c4f: mov [ecx+48h],bl
0x466c52: push eax
0x466c53: mov ecx,esi
0x466c55: mov byte ptr [esi+48h],0
0x466c59: call 0044FB20h
0x466c5e: mov ecx,[esi]
0x466c60: cmp byte ptr [ecx+49h],0
0x466c64: jne short 00466C79h
0x466c66: mov edx,[ecx+8]
0x466c69: cmp [edx+48h],bl
0x466c6c: jne short 00466C90h
0x466c6e: mov eax,[ecx]
0x466c70: cmp [eax+48h],bl
0x466c73: jne short 00466C90h
0x466c75: mov byte ptr [ecx+48h],0
0x466c79: mov ecx,[esp+68h]
0x466c7d: mov edx,[ecx+4]
0x466c80: mov edi,esi
0x466c82: cmp edi,[edx+4]
0x466c85: mov esi,[esi+4]
0x466c88: jne near ptr 00466BC0h
0x466c8e: jmp short 00466CC7h
0x466c90: mov edx,[ecx]
0x466c92: cmp [edx+48h],bl
0x466c95: jne short 00466CADh
0x466c97: mov eax,[ecx+8]
0x466c9a: mov edx,[esp+68h]
0x466c9e: mov [eax+48h],bl
0x466ca1: push edx
0x466ca2: mov byte ptr [ecx+48h],0
0x466ca6: call 0044FAD0h
0x466cab: mov ecx,[esi]
0x466cad: mov al,[esi+48h]
0x466cb0: mov edx,[esp+68h]
0x466cb4: mov [ecx+48h],al
0x466cb7: mov [esi+48h],bl
0x466cba: mov ecx,[ecx]
0x466cbc: mov [ecx+48h],bl
0x466cbf: push edx
0x466cc0: mov ecx,esi
0x466cc2: call 0044FB20h
0x466cc7: mov [edi+48h],bl
0x466cca: lea ecx,[ebp+10h]
0x466ccd: call dword ptr ds:[77CD74h]
0x466cd3: push ebp
0x466cd4: call 006516BAh
0x466cd9: mov ecx,[esp+6Ch]
0x466cdd: mov eax,[ecx+8]
0x466ce0: add esp,4
0x466ce3: test eax,eax
0x466ce5: jbe short 00466CEDh
0x466ce7: add eax,0FFFFFFFFh
0x466cea: mov [ecx+8],eax
0x466ced: mov eax,[esp+6Ch]
0x466cf1: mov ecx,[esp+70h]
0x466cf5: mov edx,[esp+74h]
0x466cf9: mov [eax],ecx
0x466cfb: mov [eax+4],edx
0x466cfe: mov ecx,[esp+58h]
0x466d02: mov fs:[0],ecx
0x466d09: pop ecx
0x466d0a: pop edi
0x466d0b: pop esi
0x466d0c: pop ebp
0x466d0d: pop ebx
0x466d0e: add esp,50h
0x466d11: ret 10h
````

`sub_466a30` is called by sub_466640. It delegates to sub_401230, sub_44fad0, sub_44fb20 (7 callees).

### sub_466d20 at 0x466d20 (53 instructions)

````text
0x466d20: push ebp
0x466d21: mov ebp,esp
0x466d23: push 0FFFFFFFFh
0x466d25: push 742061h
0x466d2a: mov eax,fs:[0]
0x466d30: push eax
0x466d31: sub esp,10h
0x466d34: push ebx
0x466d35: push esi
0x466d36: push edi
0x466d37: mov eax,ds:[858220h]
0x466d3c: xor eax,ebp
0x466d3e: push eax
0x466d3f: lea eax,[ebp-0Ch]
0x466d42: mov fs:[0],eax
0x466d48: mov [ebp-10h],esp
0x466d4b: mov esi,ecx
0x466d4d: mov ecx,1
0x466d52: call 00450370h
0x466d57: mov ebx,eax
0x466d59: mov dword ptr [ebp-4],0
0x466d60: mov [ebp-14h],ebx
0x466d63: mov [ebp-18h],ebx
0x466d66: mov [ebp-1Ch],ebx
0x466d69: test ebx,ebx
0x466d6b: mov byte ptr [ebp-4],1
0x466d6f: je short 00466DA2h
0x466d71: mov ecx,[ebp+0Ch]
0x466d74: mov eax,[ebp+8]
0x466d77: mov edx,[ebp+10h]
0x466d7a: mov [ebx+4],ecx
0x466d7d: lea edi,[ebx+0Ch]
0x466d80: push edi
0x466d81: mov ecx,esi
0x466d83: mov [ebx],eax
0x466d85: mov [ebx+8],edx
0x466d88: call 00403510h
0x466d8d: add esi,20h
0x466d90: add edi,20h
0x466d93: mov ecx,7
0x466d98: rep movsd
0x466d9a: mov byte ptr [ebx+48h],0
0x466d9e: mov byte ptr [ebx+49h],0
0x466da2: mov eax,ebx
0x466da4: mov ecx,[ebp-0Ch]
0x466da7: mov fs:[0],ecx
0x466dae: pop ecx
0x466daf: pop edi
0x466db0: pop esi
0x466db1: pop ebx
0x466db2: mov esp,ebp
0x466db4: pop ebp
0x466db5: ret 0Ch
````

`sub_466d20` is called by sub_466710. It delegates to sub_403510, sub_450370 (2 callees).

### sub_466dd0 at 0x466dd0 (9 instructions)

````text
0x466dd0: mov ecx,[eax+8]
0x466dd3: cmp byte ptr [ecx+49h],0
0x466dd7: jne short 00466DEBh
0x466dd9: lea esp,[esp]
0x466de0: mov eax,ecx
0x466de2: mov ecx,[eax+8]
0x466de5: cmp byte ptr [ecx+49h],0
0x466de9: je short 00466DE0h
0x466deb: ret
````

`sub_466dd0` is called by sub_466a30. It calls nothing else.

### sub_466df0 at 0x466df0 (47 instructions)

````text
0x466df0: cmp dword ptr [esi],0
0x466df3: push edi
0x466df4: mov edi,ds:[77D0E4h]
0x466dfa: jne short 00466DFEh
0x466dfc: call edi
0x466dfe: mov eax,[esi+4]
0x466e01: cmp byte ptr [eax+49h],0
0x466e05: je short 00466E17h
0x466e07: mov eax,[eax+8]
0x466e0a: mov [esi+4],eax
0x466e0d: cmp byte ptr [eax+49h],0
0x466e11: je short 00466E71h
0x466e13: call edi
0x466e15: pop edi
0x466e16: ret
0x466e17: mov ecx,[eax]
0x466e19: cmp byte ptr [ecx+49h],0
0x466e1d: jne short 00466E40h
0x466e1f: mov eax,[ecx+8]
0x466e22: cmp byte ptr [eax+49h],0
0x466e26: jne short 00466E3Bh
0x466e28: jmp short 00466E30h
0x466e30: mov ecx,eax
0x466e32: mov eax,[ecx+8]
0x466e35: cmp byte ptr [eax+49h],0
0x466e39: je short 00466E30h
0x466e3b: mov [esi+4],ecx
0x466e3e: pop edi
0x466e3f: ret
0x466e40: mov eax,[eax+4]
0x466e43: cmp byte ptr [eax+49h],0
0x466e47: jne short 00466E65h
0x466e49: lea esp,[esp]
0x466e50: mov ecx,[esi+4]
0x466e53: cmp ecx,[eax]
0x466e55: jne short 00466E65h
0x466e57: mov [esi+4],eax
0x466e5a: mov edx,eax
0x466e5c: mov eax,[edx+4]
0x466e5f: cmp byte ptr [eax+49h],0
0x466e63: je short 00466E50h
0x466e65: mov ecx,[esi+4]
0x466e68: cmp byte ptr [ecx+49h],0
0x466e6c: jne short 00466E13h
0x466e6e: mov [esi+4],eax
0x466e71: pop edi
0x466e72: ret
````

`sub_466df0` is called by sub_465ff0, sub_466520. It calls nothing else.

### sub_4738d0 at 0x4738d0 (29 instructions)

````text
0x4738d0: push 0FFFFFFFFh
0x4738d2: push 738D91h
0x4738d7: mov eax,fs:[0]
0x4738dd: push eax
0x4738de: push esi
0x4738df: mov eax,ds:[858220h]
0x4738e4: xor eax,esp
0x4738e6: push eax
0x4738e7: lea eax,[esp+8]
0x4738eb: mov fs:[0],eax
0x4738f1: mov esi,[esp+18h]
0x4738f5: lea ecx,[esi+54h]
0x4738f8: mov dword ptr [esp+10h],2
0x473900: call dword ptr ds:[77CD74h]
0x473906: lea ecx,[esi+38h]
0x473909: mov byte ptr [esp+10h],1
0x47390e: call dword ptr ds:[77CD74h]
0x473914: lea ecx,[esi+1Ch]
0x473917: mov byte ptr [esp+10h],0
0x47391c: call dword ptr ds:[77CD74h]
0x473922: mov ecx,esi
0x473924: mov dword ptr [esp+10h],0FFFFFFFFh
0x47392c: call dword ptr ds:[77CD74h]
0x473932: mov ecx,[esp+8]
0x473936: mov fs:[0],ecx
0x47393d: pop ecx
0x47393e: pop esi
0x47393f: add esp,0Ch
0x473942: ret 4
````

`sub_4738d0` is called by sub_4cc190, sub_632190, sub_632570, sub_633f50. It calls nothing else.

### sub_488a40 at 0x488a40 (22 instructions)

````text
0x488a40: or eax,0FFFFFFFFh
0x488a43: xor edx,edx
0x488a45: div ecx
0x488a47: sub esp,10h
0x488a4a: cmp eax,4
0x488a4d: jae short 00488A7Ch
0x488a4f: lea eax,[esp]
0x488a52: push eax
0x488a53: lea ecx,[esp+8]
0x488a57: mov dword ptr [esp+4],0
0x488a5f: call dword ptr ds:[77D0DCh]
0x488a65: push 80A2ACh
0x488a6a: lea ecx,[esp+8]
0x488a6e: push ecx
0x488a6f: mov dword ptr [esp+0Ch],78FFD4h
0x488a77: call 00652AC4h
0x488a7c: lea edx,[ecx*4]
0x488a83: push edx
0x488a84: call 006516C0h
0x488a89: add esp,4
0x488a8c: add esp,10h
0x488a8f: ret
````

`sub_488a40` is called by sub_425810. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_497e50 at 0x497e50 (23 instructions)

````text
0x497e50: push esi
0x497e51: mov esi,[ebx+4]
0x497e54: test esi,esi
0x497e56: je short 00497E7Dh
0x497e58: push edi
0x497e59: mov edi,[ebx+8]
0x497e5c: cmp esi,edi
0x497e5e: je short 00497E70h
0x497e60: lea ecx,[esi+10h]
0x497e63: call dword ptr ds:[77CD74h]
0x497e69: add esi,2Ch
0x497e6c: cmp esi,edi
0x497e6e: jne short 00497E60h
0x497e70: mov eax,[ebx+4]
0x497e73: push eax
0x497e74: call 006516BAh
0x497e79: add esp,4
0x497e7c: pop edi
0x497e7d: mov dword ptr [ebx+4],0
0x497e84: mov dword ptr [ebx+8],0
0x497e8b: mov dword ptr [ebx+0Ch],0
0x497e92: pop esi
0x497e93: ret
````

`sub_497e50` is called by sub_612890. It delegates to j_ORDINAL 764 (1 callees).

### sub_49a870 at 0x49a870 (22 instructions)

````text
0x49a870: or eax,0FFFFFFFFh
0x49a873: xor edx,edx
0x49a875: div ecx
0x49a877: sub esp,10h
0x49a87a: cmp eax,20h
0x49a87d: jae short 0049A8ACh
0x49a87f: lea eax,[esp]
0x49a882: push eax
0x49a883: lea ecx,[esp+8]
0x49a887: mov dword ptr [esp+4],0
0x49a88f: call dword ptr ds:[77D0DCh]
0x49a895: push 80A2ACh
0x49a89a: lea ecx,[esp+8]
0x49a89e: push ecx
0x49a89f: mov dword ptr [esp+0Ch],78FFD4h
0x49a8a7: call 00652AC4h
0x49a8ac: shl ecx,5
0x49a8af: push ecx
0x49a8b0: call 006516C0h
0x49a8b5: add esp,4
0x49a8b8: add esp,10h
0x49a8bb: ret
````

`sub_49a870` is called by sub_5f0bc0. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_4a3a30 at 0x4a3a30 (23 instructions)

````text
0x4a3a30: push esi
0x4a3a31: mov esi,[ebx+4]
0x4a3a34: test esi,esi
0x4a3a36: je short 004A3A5Ah
0x4a3a38: push edi
0x4a3a39: mov edi,[ebx+8]
0x4a3a3c: cmp esi,edi
0x4a3a3e: je short 004A3A4Dh
0x4a3a40: push esi
0x4a3a41: call 004A3AA0h
0x4a3a46: add esi,3Ch
0x4a3a49: cmp esi,edi
0x4a3a4b: jne short 004A3A40h
0x4a3a4d: mov eax,[ebx+4]
0x4a3a50: push eax
0x4a3a51: call 006516BAh
0x4a3a56: add esp,4
0x4a3a59: pop edi
0x4a3a5a: mov dword ptr [ebx+4],0
0x4a3a61: mov dword ptr [ebx+8],0
0x4a3a68: mov dword ptr [ebx+0Ch],0
0x4a3a6f: pop esi
0x4a3a70: ret
````

`sub_4a3a30` is called by sub_77b480. It delegates to sub_4a3aa0, j_ORDINAL 764 (2 callees).

### sub_4a3aa0 at 0x4a3aa0 (40 instructions)

````text
0x4a3aa0: push 0FFFFFFFFh
0x4a3aa2: push 73BEE9h
0x4a3aa7: mov eax,fs:[0]
0x4a3aad: push eax
0x4a3aae: push ebx
0x4a3aaf: push esi
0x4a3ab0: push edi
0x4a3ab1: mov eax,ds:[858220h]
0x4a3ab6: xor eax,esp
0x4a3ab8: push eax
0x4a3ab9: lea eax,[esp+10h]
0x4a3abd: mov fs:[0],eax
0x4a3ac3: mov esi,[esp+20h]
0x4a3ac7: xor edi,edi
0x4a3ac9: mov [esp+18h],edi
0x4a3acd: mov eax,[esi+30h]
0x4a3ad0: cmp eax,edi
0x4a3ad2: je short 004A3AEDh
0x4a3ad4: mov ecx,[esp+20h]
0x4a3ad8: mov ebx,[esi+34h]
0x4a3adb: push ecx
0x4a3adc: call 0044D400h
0x4a3ae1: mov eax,[esi+30h]
0x4a3ae4: push eax
0x4a3ae5: call 006516BAh
0x4a3aea: add esp,8
0x4a3aed: mov ecx,esi
0x4a3aef: mov [esi+30h],edi
0x4a3af2: mov [esi+34h],edi
0x4a3af5: mov [esi+38h],edi
0x4a3af8: mov dword ptr [esp+18h],0FFFFFFFFh
0x4a3b00: call dword ptr ds:[77CD74h]
0x4a3b06: mov ecx,[esp+10h]
0x4a3b0a: mov fs:[0],ecx
0x4a3b11: pop ecx
0x4a3b12: pop edi
0x4a3b13: pop esi
0x4a3b14: pop ebx
0x4a3b15: add esp,0Ch
0x4a3b18: ret 4
````

`sub_4a3aa0` is called by sub_4a3a30. It delegates to sub_44d400, j_ORDINAL 764 (2 callees).

### sub_4a4ea0 at 0x4a4ea0 (21 instructions)

````text
0x4a4ea0: push ecx
0x4a4ea1: mov eax,[eax]
0x4a4ea3: test eax,eax
0x4a4ea5: mov dword ptr [esp],0
0x4a4eac: je short 004A4EC6h
0x4a4eae: mov ecx,[eax+8]
0x4a4eb1: test ecx,ecx
0x4a4eb3: jbe short 004A4EC6h
0x4a4eb5: push ecx
0x4a4eb6: mov ecx,[eax+4]
0x4a4eb9: push ecx
0x4a4eba: mov ecx,esi
0x4a4ebc: call dword ptr ds:[77CE00h]
0x4a4ec2: mov eax,esi
0x4a4ec4: pop ecx
0x4a4ec5: ret
0x4a4ec6: mov ecx,esi
0x4a4ec8: call dword ptr ds:[77CD80h]
0x4a4ece: mov eax,esi
0x4a4ed0: pop ecx
0x4a4ed1: ret
````

`sub_4a4ea0` is called by sub_637190. It calls nothing else.

### sub_4a5750 at 0x4a5750 (1 instructions)

````text
0x4a5750: ret
````

`sub_4a5750` is called by sub_44bfe0, sub_5f0e20. It calls nothing else.

### sub_4ab3e0 at 0x4ab3e0 (30 instructions)

````text
0x4ab3e0: push 0FFFFFFFFh
0x4ab3e2: push 73973Ch
0x4ab3e7: mov eax,fs:[0]
0x4ab3ed: push eax
0x4ab3ee: push esi
0x4ab3ef: mov eax,ds:[858220h]
0x4ab3f4: xor eax,esp
0x4ab3f6: push eax
0x4ab3f7: lea eax,[esp+8]
0x4ab3fb: mov fs:[0],eax
0x4ab401: mov esi,[esp+18h]
0x4ab405: cmp esi,edi
0x4ab407: je short 004AB43Dh
0x4ab409: lea esp,[esp]
0x4ab410: lea ecx,[esi+24h]
0x4ab413: mov dword ptr [esp+10h],0
0x4ab41b: call dword ptr ds:[77CD74h]
0x4ab421: lea ecx,[esi+8]
0x4ab424: mov dword ptr [esp+10h],0FFFFFFFFh
0x4ab42c: call dword ptr ds:[77CD74h]
0x4ab432: add esi,44h
0x4ab435: cmp esi,edi
0x4ab437: mov [esp+18h],esi
0x4ab43b: jne short 004AB410h
0x4ab43d: mov ecx,[esp+8]
0x4ab441: mov fs:[0],ecx
0x4ab448: pop ecx
0x4ab449: pop esi
0x4ab44a: add esp,0Ch
0x4ab44d: ret
````

`sub_4ab3e0` is called by sub_6245b0, sub_627510, sub_627940. It calls nothing else.

### sub_4b3ba0 at 0x4b3ba0 (26 instructions)

````text
0x4b3ba0: push ebp
0x4b3ba1: mov ebp,esp
0x4b3ba3: and esp,0FFFFFFF8h
0x4b3ba6: sub esp,0Ch
0x4b3ba9: push edi
0x4b3baa: mov edi,eax
0x4b3bac: mov eax,[edi+4]
0x4b3baf: mov ecx,[eax]
0x4b3bb1: push eax
0x4b3bb2: push edi
0x4b3bb3: push ecx
0x4b3bb4: push edi
0x4b3bb5: lea eax,[esp+18h]
0x4b3bb9: push eax
0x4b3bba: call 004B4590h
0x4b3bbf: mov ecx,[edi+4]
0x4b3bc2: push ecx
0x4b3bc3: call 006516BAh
0x4b3bc8: add esp,4
0x4b3bcb: xor eax,eax
0x4b3bcd: mov [edi+4],eax
0x4b3bd0: mov [edi+8],eax
0x4b3bd3: pop edi
0x4b3bd4: mov esp,ebp
0x4b3bd6: pop ebp
0x4b3bd7: ret
````

`sub_4b3ba0` is called by sub_6245b0. It delegates to sub_4b4590, j_ORDINAL 764 (2 callees).

### sub_4b3cc0 at 0x4b3cc0 (72 instructions)

````text
0x4b3cc0: mov eax,[edi+4]
0x4b3cc3: sub esp,0Ch
0x4b3cc6: push ebx
0x4b3cc7: mov ebx,[esp+18h]
0x4b3ccb: test ebx,ebx
0x4b3ccd: push ebp
0x4b3cce: push esi
0x4b3ccf: mov esi,[eax]
0x4b3cd1: je short 004B3CD7h
0x4b3cd3: cmp ebx,edi
0x4b3cd5: je short 004B3CDDh
0x4b3cd7: call dword ptr ds:[77D0E4h]
0x4b3cdd: mov ebp,[esp+24h]
0x4b3ce1: cmp ebp,esi
0x4b3ce3: jne short 004B3D40h
0x4b3ce5: mov eax,[esp+28h]
0x4b3ce9: test eax,eax
0x4b3ceb: mov esi,[edi+4]
0x4b3cee: je short 004B3CF4h
0x4b3cf0: cmp eax,edi
0x4b3cf2: je short 004B3CFAh
0x4b3cf4: call dword ptr ds:[77D0E4h]
0x4b3cfa: cmp [esp+2Ch],esi
0x4b3cfe: jne short 004B3D40h
0x4b3d00: mov ecx,[edi+4]
0x4b3d03: mov edx,[ecx+4]
0x4b3d06: push edx
0x4b3d07: mov ecx,edi
0x4b3d09: call 004B3E00h
0x4b3d0e: mov eax,[edi+4]
0x4b3d11: mov [eax+4],eax
0x4b3d14: mov eax,[edi+4]
0x4b3d17: mov dword ptr [edi+8],0
0x4b3d1e: mov [eax],eax
0x4b3d20: mov eax,[edi+4]
0x4b3d23: mov [eax+8],eax
0x4b3d26: mov eax,[edi+4]
0x4b3d29: mov ecx,[eax]
0x4b3d2b: mov eax,[esp+1Ch]
0x4b3d2f: mov [eax+4],ecx
0x4b3d32: mov [eax],edi
0x4b3d34: pop esi
0x4b3d35: pop ebp
0x4b3d36: pop ebx
0x4b3d37: add esp,0Ch
0x4b3d3a: ret 14h
0x4b3d40: test ebx,ebx
0x4b3d42: je short 004B3D4Ah
0x4b3d44: cmp ebx,[esp+28h]
0x4b3d48: je short 004B3D50h
0x4b3d4a: call dword ptr ds:[77D0E4h]
0x4b3d50: cmp ebp,[esp+2Ch]
0x4b3d54: je short 004B3D76h
0x4b3d56: lea esi,[esp+20h]
0x4b3d5a: call 004B6500h
0x4b3d5f: push ebp
0x4b3d60: push ebx
0x4b3d61: lea edx,[esp+18h]
0x4b3d65: push edx
0x4b3d66: push edi
0x4b3d67: call 004B4B50h
0x4b3d6c: mov ebp,[esp+24h]
0x4b3d70: mov ebx,[esp+20h]
0x4b3d74: jmp short 004B3D40h
0x4b3d76: mov eax,[esp+1Ch]
0x4b3d7a: pop esi
0x4b3d7b: mov [eax+4],ebp
0x4b3d7e: pop ebp
0x4b3d7f: mov [eax],ebx
0x4b3d81: pop ebx
0x4b3d82: add esp,0Ch
0x4b3d85: ret 14h
````

`sub_4b3cc0` is called by sub_4b3ff0. It delegates to sub_4b3e00, sub_4b4b50, sub_4b6500 (3 callees).

### sub_4b3e00 at 0x4b3e00 (23 instructions)

````text
0x4b3e00: push ebx
0x4b3e01: push esi
0x4b3e02: push edi
0x4b3e03: mov edi,[esp+10h]
0x4b3e07: cmp byte ptr [edi+0Fh],0
0x4b3e0b: mov ebx,ecx
0x4b3e0d: mov esi,edi
0x4b3e0f: jne short 004B3E2Fh
0x4b3e11: mov eax,[esi+8]
0x4b3e14: push eax
0x4b3e15: mov ecx,ebx
0x4b3e17: call 004B3E00h
0x4b3e1c: mov esi,[esi]
0x4b3e1e: push edi
0x4b3e1f: call 006516BAh
0x4b3e24: add esp,4
0x4b3e27: cmp byte ptr [esi+0Fh],0
0x4b3e2b: mov edi,esi
0x4b3e2d: je short 004B3E11h
0x4b3e2f: pop edi
0x4b3e30: pop esi
0x4b3e31: pop ebx
0x4b3e32: ret 4
````

`sub_4b3e00` is called by sub_4b3cc0, sub_4b3e00. It delegates to sub_4b3e00, j_ORDINAL 764 (2 callees).

### sub_4b3ff0 at 0x4b3ff0 (26 instructions)

````text
0x4b3ff0: push ebp
0x4b3ff1: mov ebp,esp
0x4b3ff3: and esp,0FFFFFFF8h
0x4b3ff6: sub esp,0Ch
0x4b3ff9: push edi
0x4b3ffa: mov edi,eax
0x4b3ffc: mov eax,[edi+4]
0x4b3fff: mov ecx,[eax]
0x4b4001: push eax
0x4b4002: push edi
0x4b4003: push ecx
0x4b4004: push edi
0x4b4005: lea eax,[esp+18h]
0x4b4009: push eax
0x4b400a: call 004B3CC0h
0x4b400f: mov ecx,[edi+4]
0x4b4012: push ecx
0x4b4013: call 006516BAh
0x4b4018: add esp,4
0x4b401b: xor eax,eax
0x4b401d: mov [edi+4],eax
0x4b4020: mov [edi+8],eax
0x4b4023: pop edi
0x4b4024: mov esp,ebp
0x4b4026: pop ebp
0x4b4027: ret
````

`sub_4b3ff0` is called by sub_6245b0. It delegates to sub_4b3cc0, j_ORDINAL 764 (2 callees).

### sub_4b4030 at 0x4b4030 (72 instructions)

````text
0x4b4030: mov eax,[edi+4]
0x4b4033: sub esp,0Ch
0x4b4036: push ebx
0x4b4037: mov ebx,[esp+18h]
0x4b403b: test ebx,ebx
0x4b403d: push ebp
0x4b403e: push esi
0x4b403f: mov esi,[eax]
0x4b4041: je short 004B4047h
0x4b4043: cmp ebx,edi
0x4b4045: je short 004B404Dh
0x4b4047: call dword ptr ds:[77D0E4h]
0x4b404d: mov ebp,[esp+24h]
0x4b4051: cmp ebp,esi
0x4b4053: jne short 004B40B0h
0x4b4055: mov eax,[esp+28h]
0x4b4059: test eax,eax
0x4b405b: mov esi,[edi+4]
0x4b405e: je short 004B4064h
0x4b4060: cmp eax,edi
0x4b4062: je short 004B406Ah
0x4b4064: call dword ptr ds:[77D0E4h]
0x4b406a: cmp [esp+2Ch],esi
0x4b406e: jne short 004B40B0h
0x4b4070: mov ecx,[edi+4]
0x4b4073: mov edx,[ecx+4]
0x4b4076: push edx
0x4b4077: mov ecx,edi
0x4b4079: call 0060AC40h
0x4b407e: mov eax,[edi+4]
0x4b4081: mov [eax+4],eax
0x4b4084: mov eax,[edi+4]
0x4b4087: mov dword ptr [edi+8],0
0x4b408e: mov [eax],eax
0x4b4090: mov eax,[edi+4]
0x4b4093: mov [eax+8],eax
0x4b4096: mov eax,[edi+4]
0x4b4099: mov ecx,[eax]
0x4b409b: mov eax,[esp+1Ch]
0x4b409f: mov [eax+4],ecx
0x4b40a2: mov [eax],edi
0x4b40a4: pop esi
0x4b40a5: pop ebp
0x4b40a6: pop ebx
0x4b40a7: add esp,0Ch
0x4b40aa: ret 14h
0x4b40b0: test ebx,ebx
0x4b40b2: je short 004B40BAh
0x4b40b4: cmp ebx,[esp+28h]
0x4b40b8: je short 004B40C0h
0x4b40ba: call dword ptr ds:[77D0E4h]
0x4b40c0: cmp ebp,[esp+2Ch]
0x4b40c4: je short 004B40E6h
0x4b40c6: lea esi,[esp+20h]
0x4b40ca: call 004B6490h
0x4b40cf: push ebp
0x4b40d0: push ebx
0x4b40d1: lea edx,[esp+18h]
0x4b40d5: push edx
0x4b40d6: push edi
0x4b40d7: call 004B5020h
0x4b40dc: mov ebp,[esp+24h]
0x4b40e0: mov ebx,[esp+20h]
0x4b40e4: jmp short 004B40B0h
0x4b40e6: mov eax,[esp+1Ch]
0x4b40ea: pop esi
0x4b40eb: mov [eax+4],ebp
0x4b40ee: pop ebp
0x4b40ef: mov [eax],ebx
0x4b40f1: pop ebx
0x4b40f2: add esp,0Ch
0x4b40f5: ret 14h
````

`sub_4b4030` is called by sub_4b4320. It delegates to sub_4b5020, sub_4b6490, sub_60ac40 (3 callees).

### sub_4b4320 at 0x4b4320 (26 instructions)

````text
0x4b4320: push ebp
0x4b4321: mov ebp,esp
0x4b4323: and esp,0FFFFFFF8h
0x4b4326: sub esp,0Ch
0x4b4329: push edi
0x4b432a: mov edi,eax
0x4b432c: mov eax,[edi+4]
0x4b432f: mov ecx,[eax]
0x4b4331: push eax
0x4b4332: push edi
0x4b4333: push ecx
0x4b4334: push edi
0x4b4335: lea eax,[esp+18h]
0x4b4339: push eax
0x4b433a: call 004B4030h
0x4b433f: mov ecx,[edi+4]
0x4b4342: push ecx
0x4b4343: call 006516BAh
0x4b4348: add esp,4
0x4b434b: xor eax,eax
0x4b434d: mov [edi+4],eax
0x4b4350: mov [edi+8],eax
0x4b4353: pop edi
0x4b4354: mov esp,ebp
0x4b4356: pop ebp
0x4b4357: ret
````

`sub_4b4320` is called by sub_6245b0. It delegates to sub_4b4030, j_ORDINAL 764 (2 callees).

### sub_4b4360 at 0x4b4360 (26 instructions)

````text
0x4b4360: push ebp
0x4b4361: mov ebp,esp
0x4b4363: and esp,0FFFFFFF8h
0x4b4366: sub esp,0Ch
0x4b4369: push edi
0x4b436a: mov edi,eax
0x4b436c: mov eax,[edi+4]
0x4b436f: mov ecx,[eax]
0x4b4371: push eax
0x4b4372: push edi
0x4b4373: push ecx
0x4b4374: push edi
0x4b4375: lea eax,[esp+18h]
0x4b4379: push eax
0x4b437a: call 004B5430h
0x4b437f: mov ecx,[edi+4]
0x4b4382: push ecx
0x4b4383: call 006516BAh
0x4b4388: add esp,4
0x4b438b: xor eax,eax
0x4b438d: mov [edi+4],eax
0x4b4390: mov [edi+8],eax
0x4b4393: pop edi
0x4b4394: mov esp,ebp
0x4b4396: pop ebp
0x4b4397: ret
````

`sub_4b4360` is called by sub_5dfe00. It delegates to sub_4b5430, j_ORDINAL 764 (2 callees).

### sub_4b4590 at 0x4b4590 (72 instructions)

````text
0x4b4590: mov eax,[edi+4]
0x4b4593: sub esp,0Ch
0x4b4596: push ebx
0x4b4597: mov ebx,[esp+18h]
0x4b459b: test ebx,ebx
0x4b459d: push ebp
0x4b459e: push esi
0x4b459f: mov esi,[eax]
0x4b45a1: je short 004B45A7h
0x4b45a3: cmp ebx,edi
0x4b45a5: je short 004B45ADh
0x4b45a7: call dword ptr ds:[77D0E4h]
0x4b45ad: mov ebp,[esp+24h]
0x4b45b1: cmp ebp,esi
0x4b45b3: jne short 004B4610h
0x4b45b5: mov eax,[esp+28h]
0x4b45b9: test eax,eax
0x4b45bb: mov esi,[edi+4]
0x4b45be: je short 004B45C4h
0x4b45c0: cmp eax,edi
0x4b45c2: je short 004B45CAh
0x4b45c4: call dword ptr ds:[77D0E4h]
0x4b45ca: cmp [esp+2Ch],esi
0x4b45ce: jne short 004B4610h
0x4b45d0: mov ecx,[edi+4]
0x4b45d3: mov edx,[ecx+4]
0x4b45d6: push edx
0x4b45d7: mov ecx,edi
0x4b45d9: call 00573610h
0x4b45de: mov eax,[edi+4]
0x4b45e1: mov [eax+4],eax
0x4b45e4: mov eax,[edi+4]
0x4b45e7: mov dword ptr [edi+8],0
0x4b45ee: mov [eax],eax
0x4b45f0: mov eax,[edi+4]
0x4b45f3: mov [eax+8],eax
0x4b45f6: mov eax,[edi+4]
0x4b45f9: mov ecx,[eax]
0x4b45fb: mov eax,[esp+1Ch]
0x4b45ff: mov [eax+4],ecx
0x4b4602: mov [eax],edi
0x4b4604: pop esi
0x4b4605: pop ebp
0x4b4606: pop ebx
0x4b4607: add esp,0Ch
0x4b460a: ret 14h
0x4b4610: test ebx,ebx
0x4b4612: je short 004B461Ah
0x4b4614: cmp ebx,[esp+28h]
0x4b4618: je short 004B4620h
0x4b461a: call dword ptr ds:[77D0E4h]
0x4b4620: cmp ebp,[esp+2Ch]
0x4b4624: je short 004B4646h
0x4b4626: lea esi,[esp+20h]
0x4b462a: call 0043A360h
0x4b462f: push ebp
0x4b4630: push ebx
0x4b4631: lea edx,[esp+18h]
0x4b4635: push edx
0x4b4636: push edi
0x4b4637: call 004B57E0h
0x4b463c: mov ebp,[esp+24h]
0x4b4640: mov ebx,[esp+20h]
0x4b4644: jmp short 004B4610h
0x4b4646: mov eax,[esp+1Ch]
0x4b464a: pop esi
0x4b464b: mov [eax+4],ebp
0x4b464e: pop ebp
0x4b464f: mov [eax],ebx
0x4b4651: pop ebx
0x4b4652: add esp,0Ch
0x4b4655: ret 14h
````

`sub_4b4590` is called by sub_4b3ba0. It delegates to sub_43a360, sub_4b57e0, sub_573610 (3 callees).

### sub_4b4760 at 0x4b4760 (8 instructions)

````text
0x4b4760: mov ecx,[eax]
0x4b4762: cmp byte ptr [ecx+2Dh],0
0x4b4766: jne short 004B4772h
0x4b4768: mov eax,ecx
0x4b476a: mov ecx,[eax]
0x4b476c: cmp byte ptr [ecx+2Dh],0
0x4b4770: je short 004B4768h
0x4b4772: ret
````

`sub_4b4760` is called by sub_4655a0, sub_4b57e0. It calls nothing else.

### sub_4b4b50 at 0x4b4b50 (232 instructions)

````text
0x4b4b50: push 0FFFFFFFFh
0x4b4b52: push 7410D9h
0x4b4b57: mov eax,fs:[0]
0x4b4b5d: push eax
0x4b4b5e: sub esp,44h
0x4b4b61: push ebx
0x4b4b62: push ebp
0x4b4b63: push esi
0x4b4b64: push edi
0x4b4b65: mov eax,ds:[858220h]
0x4b4b6a: xor eax,esp
0x4b4b6c: push eax
0x4b4b6d: lea eax,[esp+58h]
0x4b4b71: mov fs:[0],eax
0x4b4b77: mov ebp,[esp+68h]
0x4b4b7b: mov eax,[esp+74h]
0x4b4b7f: cmp byte ptr [eax+0Fh],0
0x4b4b83: je short 004B4BC1h
0x4b4b85: push 7C5AECh
0x4b4b8a: lea ecx,[esp+18h]
0x4b4b8e: call dword ptr ds:[77CD7Ch]
0x4b4b94: lea eax,[esp+14h]
0x4b4b98: push eax
0x4b4b99: lea ecx,[esp+34h]
0x4b4b9d: mov dword ptr [esp+64h],0
0x4b4ba5: call 00401230h
0x4b4baa: push 80A4F8h
0x4b4baf: lea ecx,[esp+34h]
0x4b4bb3: push ecx
0x4b4bb4: mov dword ptr [esp+38h],790F90h
0x4b4bbc: call 00652AC4h
0x4b4bc1: mov ebx,eax
0x4b4bc3: lea esi,[esp+70h]
0x4b4bc7: mov [esp+68h],ebx
0x4b4bcb: call 004B6500h
0x4b4bd0: mov eax,[ebx]
0x4b4bd2: cmp byte ptr [eax+0Fh],0
0x4b4bd6: je short 004B4BDDh
0x4b4bd8: mov edi,[ebx+8]
0x4b4bdb: jmp short 004B4BF5h
0x4b4bdd: mov edx,[ebx+8]
0x4b4be0: cmp byte ptr [edx+0Fh],0
0x4b4be4: je short 004B4BEAh
0x4b4be6: mov edi,eax
0x4b4be8: jmp short 004B4BF5h
0x4b4bea: mov ecx,[esp+74h]
0x4b4bee: cmp ecx,ebx
0x4b4bf0: mov edi,[ecx+8]
0x4b4bf3: jne short 004B4C5Ch
0x4b4bf5: cmp byte ptr [edi+0Fh],0
0x4b4bf9: mov esi,[ebx+4]
0x4b4bfc: jne short 004B4C01h
0x4b4bfe: mov [edi+4],esi
0x4b4c01: mov eax,[ebp+4]
0x4b4c04: cmp [eax+4],ebx
0x4b4c07: jne short 004B4C0Eh
0x4b4c09: mov [eax+4],edi
0x4b4c0c: jmp short 004B4C19h
0x4b4c0e: cmp [esi],ebx
0x4b4c10: jne short 004B4C16h
0x4b4c12: mov [esi],edi
0x4b4c14: jmp short 004B4C19h
0x4b4c16: mov [esi+8],edi
0x4b4c19: mov ebx,[ebp+4]
0x4b4c1c: mov eax,[ebx]
0x4b4c1e: cmp eax,[esp+68h]
0x4b4c22: jne short 004B4C37h
0x4b4c24: cmp byte ptr [edi+0Fh],0
0x4b4c28: je short 004B4C2Eh
0x4b4c2a: mov eax,esi
0x4b4c2c: jmp short 004B4C35h
0x4b4c2e: mov eax,edi
0x4b4c30: call 004B4F30h
0x4b4c35: mov [ebx],eax
0x4b4c37: mov ebx,[ebp+4]
0x4b4c3a: mov ecx,[esp+68h]
0x4b4c3e: cmp [ebx+8],ecx
0x4b4c41: jne short 004B4CB3h
0x4b4c43: cmp byte ptr [edi+0Fh],0
0x4b4c47: je short 004B4C50h
0x4b4c49: mov eax,esi
0x4b4c4b: mov [ebx+8],eax
0x4b4c4e: jmp short 004B4CB3h
0x4b4c50: mov eax,edi
0x4b4c52: call 004B4F10h
0x4b4c57: mov [ebx+8],eax
0x4b4c5a: jmp short 004B4CB3h
0x4b4c5c: mov [eax+4],ecx
0x4b4c5f: mov edx,[ebx]
0x4b4c61: mov [ecx],edx
0x4b4c63: cmp ecx,[ebx+8]
0x4b4c66: jne short 004B4C6Ch
0x4b4c68: mov esi,ecx
0x4b4c6a: jmp short 004B4C86h
0x4b4c6c: cmp byte ptr [edi+0Fh],0
0x4b4c70: mov esi,[ecx+4]
0x4b4c73: jne short 004B4C78h
0x4b4c75: mov [edi+4],esi
0x4b4c78: mov [esi],edi
0x4b4c7a: mov eax,[ebx+8]
0x4b4c7d: mov [ecx+8],eax
0x4b4c80: mov edx,[ebx+8]
0x4b4c83: mov [edx+4],ecx
0x4b4c86: mov eax,[ebp+4]
0x4b4c89: cmp [eax+4],ebx
0x4b4c8c: jne short 004B4C93h
0x4b4c8e: mov [eax+4],ecx
0x4b4c91: jmp short 004B4CA1h
0x4b4c93: mov eax,[ebx+4]
0x4b4c96: cmp [eax],ebx
0x4b4c98: jne short 004B4C9Eh
0x4b4c9a: mov [eax],ecx
0x4b4c9c: jmp short 004B4CA1h
0x4b4c9e: mov [eax+8],ecx
0x4b4ca1: mov eax,[ebx+4]
0x4b4ca4: mov [ecx+4],eax
0x4b4ca7: mov dl,[ebx+0Eh]
0x4b4caa: mov al,[ecx+0Eh]
0x4b4cad: mov [ecx+0Eh],dl
0x4b4cb0: mov [ebx+0Eh],al
0x4b4cb3: mov eax,[esp+68h]
0x4b4cb7: mov bl,1
0x4b4cb9: cmp [eax+0Eh],bl
0x4b4cbc: jne near ptr 004B4DB7h
0x4b4cc2: mov ecx,[ebp+4]
0x4b4cc5: cmp edi,[ecx+4]
0x4b4cc8: je near ptr 004B4DB4h
0x4b4cce: mov edi,edi
0x4b4cd0: cmp [edi+0Eh],bl
0x4b4cd3: jne near ptr 004B4DB4h
0x4b4cd9: mov ecx,[esi]
0x4b4cdb: cmp edi,ecx
0x4b4cdd: jne short 004B4D42h
0x4b4cdf: mov ecx,[esi+8]
0x4b4ce2: cmp byte ptr [ecx+0Eh],0
0x4b4ce6: jne short 004B4CFAh
0x4b4ce8: mov [ecx+0Eh],bl
0x4b4ceb: push ebp
0x4b4cec: mov ecx,esi
0x4b4cee: mov byte ptr [esi+0Eh],0
0x4b4cf2: call 004B4EC0h
0x4b4cf7: mov ecx,[esi+8]
0x4b4cfa: cmp byte ptr [ecx+0Fh],0
0x4b4cfe: jne short 004B4D72h
0x4b4d00: mov edx,[ecx]
0x4b4d02: cmp [edx+0Eh],bl
0x4b4d05: jne short 004B4D0Fh
0x4b4d07: mov eax,[ecx+8]
0x4b4d0a: cmp [eax+0Eh],bl
0x4b4d0d: je short 004B4D6Eh
0x4b4d0f: mov edx,[ecx+8]
0x4b4d12: cmp [edx+0Eh],bl
0x4b4d15: jne short 004B4D29h
0x4b4d17: mov eax,[ecx]
0x4b4d19: mov [eax+0Eh],bl
0x4b4d1c: push ebp
0x4b4d1d: mov byte ptr [ecx+0Eh],0
0x4b4d21: call 004B4F50h
0x4b4d26: mov ecx,[esi+8]
0x4b4d29: mov dl,[esi+0Eh]
0x4b4d2c: mov [ecx+0Eh],dl
0x4b4d2f: mov [esi+0Eh],bl
0x4b4d32: mov eax,[ecx+8]
0x4b4d35: push ebp
0x4b4d36: mov ecx,esi
0x4b4d38: mov [eax+0Eh],bl
0x4b4d3b: call 004B4EC0h
0x4b4d40: jmp short 004B4DB4h
0x4b4d42: cmp byte ptr [ecx+0Eh],0
0x4b4d46: jne short 004B4D59h
0x4b4d48: mov [ecx+0Eh],bl
0x4b4d4b: push ebp
0x4b4d4c: mov ecx,esi
0x4b4d4e: mov byte ptr [esi+0Eh],0
0x4b4d52: call 004B4F50h
0x4b4d57: mov ecx,[esi]
0x4b4d59: cmp byte ptr [ecx+0Fh],0
0x4b4d5d: jne short 004B4D72h
0x4b4d5f: mov edx,[ecx+8]
0x4b4d62: cmp [edx+0Eh],bl
0x4b4d65: jne short 004B4D85h
0x4b4d67: mov eax,[ecx]
0x4b4d69: cmp [eax+0Eh],bl
0x4b4d6c: jne short 004B4D85h
0x4b4d6e: mov byte ptr [ecx+0Eh],0
0x4b4d72: mov ecx,[ebp+4]
0x4b4d75: mov edi,esi
0x4b4d77: cmp edi,[ecx+4]
0x4b4d7a: mov esi,[esi+4]
0x4b4d7d: jne near ptr 004B4CD0h
0x4b4d83: jmp short 004B4DB4h
0x4b4d85: mov edx,[ecx]
0x4b4d87: cmp [edx+0Eh],bl
0x4b4d8a: jne short 004B4D9Eh
0x4b4d8c: mov eax,[ecx+8]
0x4b4d8f: mov [eax+0Eh],bl
0x4b4d92: push ebp
0x4b4d93: mov byte ptr [ecx+0Eh],0
0x4b4d97: call 004B4EC0h
0x4b4d9c: mov ecx,[esi]
0x4b4d9e: mov dl,[esi+0Eh]
0x4b4da1: mov [ecx+0Eh],dl
0x4b4da4: mov [esi+0Eh],bl
0x4b4da7: mov eax,[ecx]
0x4b4da9: push ebp
0x4b4daa: mov ecx,esi
0x4b4dac: mov [eax+0Eh],bl
0x4b4daf: call 004B4F50h
0x4b4db4: mov [edi+0Eh],bl
0x4b4db7: mov ecx,[esp+68h]
0x4b4dbb: push ecx
0x4b4dbc: call 006516BAh
0x4b4dc1: mov eax,[ebp+8]
0x4b4dc4: add esp,4
0x4b4dc7: test eax,eax
0x4b4dc9: jbe short 004B4DD1h
0x4b4dcb: add eax,0FFFFFFFFh
0x4b4dce: mov [ebp+8],eax
0x4b4dd1: mov eax,[esp+6Ch]
0x4b4dd5: mov edx,[esp+70h]
0x4b4dd9: mov ecx,[esp+74h]
0x4b4ddd: mov [eax],edx
0x4b4ddf: mov [eax+4],ecx
0x4b4de2: mov ecx,[esp+58h]
0x4b4de6: mov fs:[0],ecx
0x4b4ded: pop ecx
0x4b4dee: pop edi
0x4b4def: pop esi
0x4b4df0: pop ebp
0x4b4df1: pop ebx
0x4b4df2: add esp,50h
0x4b4df5: ret 10h
````

`sub_4b4b50` is called by sub_4b3cc0. It delegates to sub_401230, sub_4b4ec0, sub_4b4f10 (8 callees).

### sub_4b4ec0 at 0x4b4ec0 (28 instructions)

````text
0x4b4ec0: mov eax,[ecx+8]
0x4b4ec3: mov edx,[eax]
0x4b4ec5: mov [ecx+8],edx
0x4b4ec8: mov edx,[eax]
0x4b4eca: cmp byte ptr [edx+0Fh],0
0x4b4ece: jne short 004B4ED3h
0x4b4ed0: mov [edx+4],ecx
0x4b4ed3: mov edx,[ecx+4]
0x4b4ed6: mov [eax+4],edx
0x4b4ed9: mov edx,[esp+4]
0x4b4edd: mov edx,[edx+4]
0x4b4ee0: cmp ecx,[edx+4]
0x4b4ee3: jne short 004B4EF0h
0x4b4ee5: mov [edx+4],eax
0x4b4ee8: mov [eax],ecx
0x4b4eea: mov [ecx+4],eax
0x4b4eed: ret 4
0x4b4ef0: mov edx,[ecx+4]
0x4b4ef3: cmp ecx,[edx]
0x4b4ef5: jne short 004B4F01h
0x4b4ef7: mov [edx],eax
0x4b4ef9: mov [eax],ecx
0x4b4efb: mov [ecx+4],eax
0x4b4efe: ret 4
0x4b4f01: mov [edx+8],eax
0x4b4f04: mov [eax],ecx
0x4b4f06: mov [ecx+4],eax
0x4b4f09: ret 4
````

`sub_4b4ec0` is called by sub_4b4b50. It calls nothing else.

### sub_4b4f10 at 0x4b4f10 (9 instructions)

````text
0x4b4f10: mov ecx,[eax+8]
0x4b4f13: cmp byte ptr [ecx+0Fh],0
0x4b4f17: jne short 004B4F2Bh
0x4b4f19: lea esp,[esp]
0x4b4f20: mov eax,ecx
0x4b4f22: mov ecx,[eax+8]
0x4b4f25: cmp byte ptr [ecx+0Fh],0
0x4b4f29: je short 004B4F20h
0x4b4f2b: ret
````

`sub_4b4f10` is called by sub_4b4b50. It calls nothing else.

### sub_4b4f30 at 0x4b4f30 (8 instructions)

````text
0x4b4f30: mov ecx,[eax]
0x4b4f32: cmp byte ptr [ecx+0Fh],0
0x4b4f36: jne short 004B4F42h
0x4b4f38: mov eax,ecx
0x4b4f3a: mov ecx,[eax]
0x4b4f3c: cmp byte ptr [ecx+0Fh],0
0x4b4f40: je short 004B4F38h
0x4b4f42: ret
````

`sub_4b4f30` is called by sub_4b4b50. It calls nothing else.

### sub_4b4f50 at 0x4b4f50 (28 instructions)

````text
0x4b4f50: mov eax,[ecx]
0x4b4f52: mov edx,[eax+8]
0x4b4f55: mov [ecx],edx
0x4b4f57: mov edx,[eax+8]
0x4b4f5a: cmp byte ptr [edx+0Fh],0
0x4b4f5e: jne short 004B4F63h
0x4b4f60: mov [edx+4],ecx
0x4b4f63: mov edx,[ecx+4]
0x4b4f66: mov [eax+4],edx
0x4b4f69: mov edx,[esp+4]
0x4b4f6d: mov edx,[edx+4]
0x4b4f70: cmp ecx,[edx+4]
0x4b4f73: jne short 004B4F81h
0x4b4f75: mov [edx+4],eax
0x4b4f78: mov [eax+8],ecx
0x4b4f7b: mov [ecx+4],eax
0x4b4f7e: ret 4
0x4b4f81: mov edx,[ecx+4]
0x4b4f84: cmp ecx,[edx+8]
0x4b4f87: jne short 004B4F95h
0x4b4f89: mov [edx+8],eax
0x4b4f8c: mov [eax+8],ecx
0x4b4f8f: mov [ecx+4],eax
0x4b4f92: ret 4
0x4b4f95: mov [edx],eax
0x4b4f97: mov [eax+8],ecx
0x4b4f9a: mov [ecx+4],eax
0x4b4f9d: ret 4
````

`sub_4b4f50` is called by sub_4b4b50. It calls nothing else.

### sub_4b4fa0 at 0x4b4fa0 (16 instructions)

````text
0x4b4fa0: mov ecx,1
0x4b4fa5: call 005CE370h
0x4b4faa: test eax,eax
0x4b4fac: je short 004B4FB4h
0x4b4fae: mov dword ptr [eax],0
0x4b4fb4: lea ecx,[eax+4]
0x4b4fb7: test ecx,ecx
0x4b4fb9: je short 004B4FC1h
0x4b4fbb: mov dword ptr [ecx],0
0x4b4fc1: lea ecx,[eax+8]
0x4b4fc4: test ecx,ecx
0x4b4fc6: je short 004B4FCEh
0x4b4fc8: mov dword ptr [ecx],0
0x4b4fce: mov byte ptr [eax+0Eh],1
0x4b4fd2: mov byte ptr [eax+0Fh],0
0x4b4fd6: ret
````

`sub_4b4fa0` is called by sub_624350. It delegates to sub_5ce370 (1 callees).

### sub_4b5020 at 0x4b5020 (232 instructions)

````text
0x4b5020: push 0FFFFFFFFh
0x4b5022: push 7410D9h
0x4b5027: mov eax,fs:[0]
0x4b502d: push eax
0x4b502e: sub esp,44h
0x4b5031: push ebx
0x4b5032: push ebp
0x4b5033: push esi
0x4b5034: push edi
0x4b5035: mov eax,ds:[858220h]
0x4b503a: xor eax,esp
0x4b503c: push eax
0x4b503d: lea eax,[esp+58h]
0x4b5041: mov fs:[0],eax
0x4b5047: mov ebp,[esp+68h]
0x4b504b: mov eax,[esp+74h]
0x4b504f: cmp byte ptr [eax+11h],0
0x4b5053: je short 004B5091h
0x4b5055: push 7C5AECh
0x4b505a: lea ecx,[esp+18h]
0x4b505e: call dword ptr ds:[77CD7Ch]
0x4b5064: lea eax,[esp+14h]
0x4b5068: push eax
0x4b5069: lea ecx,[esp+34h]
0x4b506d: mov dword ptr [esp+64h],0
0x4b5075: call 00401230h
0x4b507a: push 80A4F8h
0x4b507f: lea ecx,[esp+34h]
0x4b5083: push ecx
0x4b5084: mov dword ptr [esp+38h],790F90h
0x4b508c: call 00652AC4h
0x4b5091: mov ebx,eax
0x4b5093: lea esi,[esp+70h]
0x4b5097: mov [esp+68h],ebx
0x4b509b: call 004B6490h
0x4b50a0: mov eax,[ebx]
0x4b50a2: cmp byte ptr [eax+11h],0
0x4b50a6: je short 004B50ADh
0x4b50a8: mov edi,[ebx+8]
0x4b50ab: jmp short 004B50C5h
0x4b50ad: mov edx,[ebx+8]
0x4b50b0: cmp byte ptr [edx+11h],0
0x4b50b4: je short 004B50BAh
0x4b50b6: mov edi,eax
0x4b50b8: jmp short 004B50C5h
0x4b50ba: mov ecx,[esp+74h]
0x4b50be: cmp ecx,ebx
0x4b50c0: mov edi,[ecx+8]
0x4b50c3: jne short 004B512Ch
0x4b50c5: cmp byte ptr [edi+11h],0
0x4b50c9: mov esi,[ebx+4]
0x4b50cc: jne short 004B50D1h
0x4b50ce: mov [edi+4],esi
0x4b50d1: mov eax,[ebp+4]
0x4b50d4: cmp [eax+4],ebx
0x4b50d7: jne short 004B50DEh
0x4b50d9: mov [eax+4],edi
0x4b50dc: jmp short 004B50E9h
0x4b50de: cmp [esi],ebx
0x4b50e0: jne short 004B50E6h
0x4b50e2: mov [esi],edi
0x4b50e4: jmp short 004B50E9h
0x4b50e6: mov [esi+8],edi
0x4b50e9: mov ebx,[ebp+4]
0x4b50ec: mov eax,[ebx]
0x4b50ee: cmp eax,[esp+68h]
0x4b50f2: jne short 004B5107h
0x4b50f4: cmp byte ptr [edi+11h],0
0x4b50f8: je short 004B50FEh
0x4b50fa: mov eax,esi
0x4b50fc: jmp short 004B5105h
0x4b50fe: mov eax,edi
0x4b5100: call 004B5390h
0x4b5105: mov [ebx],eax
0x4b5107: mov ebx,[ebp+4]
0x4b510a: mov ecx,[esp+68h]
0x4b510e: cmp [ebx+8],ecx
0x4b5111: jne short 004B5183h
0x4b5113: cmp byte ptr [edi+11h],0
0x4b5117: je short 004B5120h
0x4b5119: mov eax,esi
0x4b511b: mov [ebx+8],eax
0x4b511e: jmp short 004B5183h
0x4b5120: mov eax,edi
0x4b5122: call 004DE470h
0x4b5127: mov [ebx+8],eax
0x4b512a: jmp short 004B5183h
0x4b512c: mov [eax+4],ecx
0x4b512f: mov edx,[ebx]
0x4b5131: mov [ecx],edx
0x4b5133: cmp ecx,[ebx+8]
0x4b5136: jne short 004B513Ch
0x4b5138: mov esi,ecx
0x4b513a: jmp short 004B5156h
0x4b513c: cmp byte ptr [edi+11h],0
0x4b5140: mov esi,[ecx+4]
0x4b5143: jne short 004B5148h
0x4b5145: mov [edi+4],esi
0x4b5148: mov [esi],edi
0x4b514a: mov eax,[ebx+8]
0x4b514d: mov [ecx+8],eax
0x4b5150: mov edx,[ebx+8]
0x4b5153: mov [edx+4],ecx
0x4b5156: mov eax,[ebp+4]
0x4b5159: cmp [eax+4],ebx
0x4b515c: jne short 004B5163h
0x4b515e: mov [eax+4],ecx
0x4b5161: jmp short 004B5171h
0x4b5163: mov eax,[ebx+4]
0x4b5166: cmp [eax],ebx
0x4b5168: jne short 004B516Eh
0x4b516a: mov [eax],ecx
0x4b516c: jmp short 004B5171h
0x4b516e: mov [eax+8],ecx
0x4b5171: mov eax,[ebx+4]
0x4b5174: mov [ecx+4],eax
0x4b5177: mov dl,[ebx+10h]
0x4b517a: mov al,[ecx+10h]
0x4b517d: mov [ecx+10h],dl
0x4b5180: mov [ebx+10h],al
0x4b5183: mov eax,[esp+68h]
0x4b5187: mov bl,1
0x4b5189: cmp [eax+10h],bl
0x4b518c: jne near ptr 004B5287h
0x4b5192: mov ecx,[ebp+4]
0x4b5195: cmp edi,[ecx+4]
0x4b5198: je near ptr 004B5284h
0x4b519e: mov edi,edi
0x4b51a0: cmp [edi+10h],bl
0x4b51a3: jne near ptr 004B5284h
0x4b51a9: mov ecx,[esi]
0x4b51ab: cmp edi,ecx
0x4b51ad: jne short 004B5212h
0x4b51af: mov ecx,[esi+8]
0x4b51b2: cmp byte ptr [ecx+10h],0
0x4b51b6: jne short 004B51CAh
0x4b51b8: mov [ecx+10h],bl
0x4b51bb: push ebp
0x4b51bc: mov ecx,esi
0x4b51be: mov byte ptr [esi+10h],0
0x4b51c2: call 0060B470h
0x4b51c7: mov ecx,[esi+8]
0x4b51ca: cmp byte ptr [ecx+11h],0
0x4b51ce: jne short 004B5242h
0x4b51d0: mov edx,[ecx]
0x4b51d2: cmp [edx+10h],bl
0x4b51d5: jne short 004B51DFh
0x4b51d7: mov eax,[ecx+8]
0x4b51da: cmp [eax+10h],bl
0x4b51dd: je short 004B523Eh
0x4b51df: mov edx,[ecx+8]
0x4b51e2: cmp [edx+10h],bl
0x4b51e5: jne short 004B51F9h
0x4b51e7: mov eax,[ecx]
0x4b51e9: mov [eax+10h],bl
0x4b51ec: push ebp
0x4b51ed: mov byte ptr [ecx+10h],0
0x4b51f1: call 004DE490h
0x4b51f6: mov ecx,[esi+8]
0x4b51f9: mov dl,[esi+10h]
0x4b51fc: mov [ecx+10h],dl
0x4b51ff: mov [esi+10h],bl
0x4b5202: mov eax,[ecx+8]
0x4b5205: push ebp
0x4b5206: mov ecx,esi
0x4b5208: mov [eax+10h],bl
0x4b520b: call 0060B470h
0x4b5210: jmp short 004B5284h
0x4b5212: cmp byte ptr [ecx+10h],0
0x4b5216: jne short 004B5229h
0x4b5218: mov [ecx+10h],bl
0x4b521b: push ebp
0x4b521c: mov ecx,esi
0x4b521e: mov byte ptr [esi+10h],0
0x4b5222: call 004DE490h
0x4b5227: mov ecx,[esi]
0x4b5229: cmp byte ptr [ecx+11h],0
0x4b522d: jne short 004B5242h
0x4b522f: mov edx,[ecx+8]
0x4b5232: cmp [edx+10h],bl
0x4b5235: jne short 004B5255h
0x4b5237: mov eax,[ecx]
0x4b5239: cmp [eax+10h],bl
0x4b523c: jne short 004B5255h
0x4b523e: mov byte ptr [ecx+10h],0
0x4b5242: mov ecx,[ebp+4]
0x4b5245: mov edi,esi
0x4b5247: cmp edi,[ecx+4]
0x4b524a: mov esi,[esi+4]
0x4b524d: jne near ptr 004B51A0h
0x4b5253: jmp short 004B5284h
0x4b5255: mov edx,[ecx]
0x4b5257: cmp [edx+10h],bl
0x4b525a: jne short 004B526Eh
0x4b525c: mov eax,[ecx+8]
0x4b525f: mov [eax+10h],bl
0x4b5262: push ebp
0x4b5263: mov byte ptr [ecx+10h],0
0x4b5267: call 0060B470h
0x4b526c: mov ecx,[esi]
0x4b526e: mov dl,[esi+10h]
0x4b5271: mov [ecx+10h],dl
0x4b5274: mov [esi+10h],bl
0x4b5277: mov eax,[ecx]
0x4b5279: push ebp
0x4b527a: mov ecx,esi
0x4b527c: mov [eax+10h],bl
0x4b527f: call 004DE490h
0x4b5284: mov [edi+10h],bl
0x4b5287: mov ecx,[esp+68h]
0x4b528b: push ecx
0x4b528c: call 006516BAh
0x4b5291: mov eax,[ebp+8]
0x4b5294: add esp,4
0x4b5297: test eax,eax
0x4b5299: jbe short 004B52A1h
0x4b529b: add eax,0FFFFFFFFh
0x4b529e: mov [ebp+8],eax
0x4b52a1: mov eax,[esp+6Ch]
0x4b52a5: mov edx,[esp+70h]
0x4b52a9: mov ecx,[esp+74h]
0x4b52ad: mov [eax],edx
0x4b52af: mov [eax+4],ecx
0x4b52b2: mov ecx,[esp+58h]
0x4b52b6: mov fs:[0],ecx
0x4b52bd: pop ecx
0x4b52be: pop edi
0x4b52bf: pop esi
0x4b52c0: pop ebp
0x4b52c1: pop ebx
0x4b52c2: add esp,50h
0x4b52c5: ret 10h
````

`sub_4b5020` is called by sub_4b4030. It delegates to sub_401230, sub_4b5390, sub_4b6490 (8 callees).

### sub_4b5390 at 0x4b5390 (8 instructions)

````text
0x4b5390: mov ecx,[eax]
0x4b5392: cmp byte ptr [ecx+11h],0
0x4b5396: jne short 004B53A2h
0x4b5398: mov eax,ecx
0x4b539a: mov ecx,[eax]
0x4b539c: cmp byte ptr [ecx+11h],0
0x4b53a0: je short 004B5398h
0x4b53a2: ret
````

`sub_4b5390` is called by sub_4b5020. It calls nothing else.

### sub_4b53b0 at 0x4b53b0 (16 instructions)

````text
0x4b53b0: mov ecx,1
0x4b53b5: call 004FA340h
0x4b53ba: test eax,eax
0x4b53bc: je short 004B53C4h
0x4b53be: mov dword ptr [eax],0
0x4b53c4: lea ecx,[eax+4]
0x4b53c7: test ecx,ecx
0x4b53c9: je short 004B53D1h
0x4b53cb: mov dword ptr [ecx],0
0x4b53d1: lea ecx,[eax+8]
0x4b53d4: test ecx,ecx
0x4b53d6: je short 004B53DEh
0x4b53d8: mov dword ptr [ecx],0
0x4b53de: mov byte ptr [eax+10h],1
0x4b53e2: mov byte ptr [eax+11h],0
0x4b53e6: ret
````

`sub_4b53b0` is called by sub_4ddd40, sub_609e80, sub_624350. It delegates to sub_4fa340 (1 callees).

### sub_4b5430 at 0x4b5430 (72 instructions)

````text
0x4b5430: mov eax,[edi+4]
0x4b5433: sub esp,0Ch
0x4b5436: push ebx
0x4b5437: mov ebx,[esp+18h]
0x4b543b: test ebx,ebx
0x4b543d: push ebp
0x4b543e: push esi
0x4b543f: mov esi,[eax]
0x4b5441: je short 004B5447h
0x4b5443: cmp ebx,edi
0x4b5445: je short 004B544Dh
0x4b5447: call dword ptr ds:[77D0E4h]
0x4b544d: mov ebp,[esp+24h]
0x4b5451: cmp ebp,esi
0x4b5453: jne short 004B54B0h
0x4b5455: mov eax,[esp+28h]
0x4b5459: test eax,eax
0x4b545b: mov esi,[edi+4]
0x4b545e: je short 004B5464h
0x4b5460: cmp eax,edi
0x4b5462: je short 004B546Ah
0x4b5464: call dword ptr ds:[77D0E4h]
0x4b546a: cmp [esp+2Ch],esi
0x4b546e: jne short 004B54B0h
0x4b5470: mov ecx,[edi+4]
0x4b5473: mov edx,[ecx+4]
0x4b5476: push edx
0x4b5477: mov ecx,edi
0x4b5479: call 004B6300h
0x4b547e: mov eax,[edi+4]
0x4b5481: mov [eax+4],eax
0x4b5484: mov eax,[edi+4]
0x4b5487: mov dword ptr [edi+8],0
0x4b548e: mov [eax],eax
0x4b5490: mov eax,[edi+4]
0x4b5493: mov [eax+8],eax
0x4b5496: mov eax,[edi+4]
0x4b5499: mov ecx,[eax]
0x4b549b: mov eax,[esp+1Ch]
0x4b549f: mov [eax+4],ecx
0x4b54a2: mov [eax],edi
0x4b54a4: pop esi
0x4b54a5: pop ebp
0x4b54a6: pop ebx
0x4b54a7: add esp,0Ch
0x4b54aa: ret 14h
0x4b54b0: test ebx,ebx
0x4b54b2: je short 004B54BAh
0x4b54b4: cmp ebx,[esp+28h]
0x4b54b8: je short 004B54C0h
0x4b54ba: call dword ptr ds:[77D0E4h]
0x4b54c0: cmp ebp,[esp+2Ch]
0x4b54c4: je short 004B54E6h
0x4b54c6: lea esi,[esp+20h]
0x4b54ca: call 004B6660h
0x4b54cf: push ebp
0x4b54d0: push ebx
0x4b54d1: lea edx,[esp+18h]
0x4b54d5: push edx
0x4b54d6: push edi
0x4b54d7: call 004B5AB0h
0x4b54dc: mov ebp,[esp+24h]
0x4b54e0: mov ebx,[esp+20h]
0x4b54e4: jmp short 004B54B0h
0x4b54e6: mov eax,[esp+1Ch]
0x4b54ea: pop esi
0x4b54eb: mov [eax+4],ebp
0x4b54ee: pop ebp
0x4b54ef: mov [eax],ebx
0x4b54f1: pop ebx
0x4b54f2: add esp,0Ch
0x4b54f5: ret 14h
````

`sub_4b5430` is called by sub_4b4360. It delegates to sub_4b5ab0, sub_4b6300, sub_4b6660 (3 callees).

### sub_4b57e0 at 0x4b57e0 (237 instructions)

````text
0x4b57e0: push 0FFFFFFFFh
0x4b57e2: push 7410D9h
0x4b57e7: mov eax,fs:[0]
0x4b57ed: push eax
0x4b57ee: sub esp,44h
0x4b57f1: push ebx
0x4b57f2: push ebp
0x4b57f3: push esi
0x4b57f4: push edi
0x4b57f5: mov eax,ds:[858220h]
0x4b57fa: xor eax,esp
0x4b57fc: push eax
0x4b57fd: lea eax,[esp+58h]
0x4b5801: mov fs:[0],eax
0x4b5807: mov eax,[esp+74h]
0x4b580b: cmp byte ptr [eax+2Dh],0
0x4b580f: je short 004B584Dh
0x4b5811: push 7C5AECh
0x4b5816: lea ecx,[esp+18h]
0x4b581a: call dword ptr ds:[77CD7Ch]
0x4b5820: lea eax,[esp+14h]
0x4b5824: push eax
0x4b5825: lea ecx,[esp+34h]
0x4b5829: mov dword ptr [esp+64h],0
0x4b5831: call 00401230h
0x4b5836: push 80A4F8h
0x4b583b: lea ecx,[esp+34h]
0x4b583f: push ecx
0x4b5840: mov dword ptr [esp+38h],790F90h
0x4b5848: call 00652AC4h
0x4b584d: lea esi,[esp+70h]
0x4b5851: mov ebp,eax
0x4b5853: call 0043A360h
0x4b5858: mov eax,[ebp]
0x4b585b: cmp byte ptr [eax+2Dh],0
0x4b585f: je short 004B5866h
0x4b5861: mov edi,[ebp+8]
0x4b5864: jmp short 004B587Eh
0x4b5866: mov edx,[ebp+8]
0x4b5869: cmp byte ptr [edx+2Dh],0
0x4b586d: je short 004B5873h
0x4b586f: mov edi,eax
0x4b5871: jmp short 004B587Eh
0x4b5873: mov ecx,[esp+74h]
0x4b5877: cmp ecx,ebp
0x4b5879: mov edi,[ecx+8]
0x4b587c: jne short 004B58E9h
0x4b587e: cmp byte ptr [edi+2Dh],0
0x4b5882: mov esi,[ebp+4]
0x4b5885: jne short 004B588Ah
0x4b5887: mov [edi+4],esi
0x4b588a: mov edx,[esp+68h]
0x4b588e: mov eax,[edx+4]
0x4b5891: cmp [eax+4],ebp
0x4b5894: jne short 004B589Bh
0x4b5896: mov [eax+4],edi
0x4b5899: jmp short 004B58A6h
0x4b589b: cmp [esi],ebp
0x4b589d: jne short 004B58A3h
0x4b589f: mov [esi],edi
0x4b58a1: jmp short 004B58A6h
0x4b58a3: mov [esi+8],edi
0x4b58a6: mov ebx,[edx+4]
0x4b58a9: cmp [ebx],ebp
0x4b58ab: jne short 004B58C4h
0x4b58ad: cmp byte ptr [edi+2Dh],0
0x4b58b1: je short 004B58B7h
0x4b58b3: mov eax,esi
0x4b58b5: jmp short 004B58C2h
0x4b58b7: mov eax,edi
0x4b58b9: call 004B4760h
0x4b58be: mov edx,[esp+68h]
0x4b58c2: mov [ebx],eax
0x4b58c4: mov ebx,[edx+4]
0x4b58c7: cmp [ebx+8],ebp
0x4b58ca: jne short 004B5949h
0x4b58cc: cmp byte ptr [edi+2Dh],0
0x4b58d0: je short 004B58D9h
0x4b58d2: mov eax,esi
0x4b58d4: mov [ebx+8],eax
0x4b58d7: jmp short 004B5949h
0x4b58d9: mov eax,edi
0x4b58db: call 005733F0h
0x4b58e0: mov edx,[esp+68h]
0x4b58e4: mov [ebx+8],eax
0x4b58e7: jmp short 004B5949h
0x4b58e9: mov [eax+4],ecx
0x4b58ec: mov eax,[ebp]
0x4b58ef: mov [ecx],eax
0x4b58f1: cmp ecx,[ebp+8]
0x4b58f4: jne short 004B58FAh
0x4b58f6: mov esi,ecx
0x4b58f8: jmp short 004B5914h
0x4b58fa: cmp byte ptr [edi+2Dh],0
0x4b58fe: mov esi,[ecx+4]
0x4b5901: jne short 004B5906h
0x4b5903: mov [edi+4],esi
0x4b5906: mov [esi],edi
0x4b5908: mov edx,[ebp+8]
0x4b590b: mov [ecx+8],edx
0x4b590e: mov eax,[ebp+8]
0x4b5911: mov [eax+4],ecx
0x4b5914: mov edx,[esp+68h]
0x4b5918: mov eax,[edx+4]
0x4b591b: cmp [eax+4],ebp
0x4b591e: jne short 004B5925h
0x4b5920: mov [eax+4],ecx
0x4b5923: jmp short 004B5933h
0x4b5925: mov eax,[ebp+4]
0x4b5928: cmp [eax],ebp
0x4b592a: jne short 004B5930h
0x4b592c: mov [eax],ecx
0x4b592e: jmp short 004B5933h
0x4b5930: mov [eax+8],ecx
0x4b5933: mov eax,[ebp+4]
0x4b5936: mov [ecx+4],eax
0x4b5939: mov dl,[ebp+2Ch]
0x4b593c: mov al,[ecx+2Ch]
0x4b593f: mov [ecx+2Ch],dl
0x4b5942: mov edx,[esp+68h]
0x4b5946: mov [ebp+2Ch],al
0x4b5949: mov bl,1
0x4b594b: cmp [ebp+2Ch],bl
0x4b594e: jne near ptr 004B5A57h
0x4b5954: mov eax,[edx+4]
0x4b5957: cmp edi,[eax+4]
0x4b595a: je near ptr 004B5A54h
0x4b5960: cmp [edi+2Ch],bl
0x4b5963: jne near ptr 004B5A54h
0x4b5969: mov ecx,[esi]
0x4b596b: cmp edi,ecx
0x4b596d: jne short 004B59DAh
0x4b596f: mov ecx,[esi+8]
0x4b5972: cmp byte ptr [ecx+2Ch],0
0x4b5976: jne short 004B598Eh
0x4b5978: mov [ecx+2Ch],bl
0x4b597b: push edx
0x4b597c: mov ecx,esi
0x4b597e: mov byte ptr [esi+2Ch],0
0x4b5982: call 005733A0h
0x4b5987: mov ecx,[esi+8]
0x4b598a: mov edx,[esp+68h]
0x4b598e: cmp byte ptr [ecx+2Dh],0
0x4b5992: jne short 004B5A0Eh
0x4b5994: mov eax,[ecx]
0x4b5996: cmp [eax+2Ch],bl
0x4b5999: jne short 004B59A3h
0x4b599b: mov eax,[ecx+8]
0x4b599e: cmp [eax+2Ch],bl
0x4b59a1: je short 004B5A0Ah
0x4b59a3: mov eax,[ecx+8]
0x4b59a6: cmp [eax+2Ch],bl
0x4b59a9: jne short 004B59C1h
0x4b59ab: mov eax,[ecx]
0x4b59ad: mov [eax+2Ch],bl
0x4b59b0: push edx
0x4b59b1: mov byte ptr [ecx+2Ch],0
0x4b59b5: call 00465F60h
0x4b59ba: mov ecx,[esi+8]
0x4b59bd: mov edx,[esp+68h]
0x4b59c1: mov al,[esi+2Ch]
0x4b59c4: mov [ecx+2Ch],al
0x4b59c7: mov [esi+2Ch],bl
0x4b59ca: mov ecx,[ecx+8]
0x4b59cd: mov [ecx+2Ch],bl
0x4b59d0: push edx
0x4b59d1: mov ecx,esi
0x4b59d3: call 005733A0h
0x4b59d8: jmp short 004B5A54h
0x4b59da: cmp byte ptr [ecx+2Ch],0
0x4b59de: jne short 004B59F5h
0x4b59e0: mov [ecx+2Ch],bl
0x4b59e3: push edx
0x4b59e4: mov ecx,esi
0x4b59e6: mov byte ptr [esi+2Ch],0
0x4b59ea: call 00465F60h
0x4b59ef: mov ecx,[esi]
0x4b59f1: mov edx,[esp+68h]
0x4b59f5: cmp byte ptr [ecx+2Dh],0
0x4b59f9: jne short 004B5A0Eh
0x4b59fb: mov eax,[ecx+8]
0x4b59fe: cmp [eax+2Ch],bl
0x4b5a01: jne short 004B5A21h
0x4b5a03: mov eax,[ecx]
0x4b5a05: cmp [eax+2Ch],bl
0x4b5a08: jne short 004B5A21h
0x4b5a0a: mov byte ptr [ecx+2Ch],0
0x4b5a0e: mov ecx,[edx+4]
0x4b5a11: mov edi,esi
0x4b5a13: cmp edi,[ecx+4]
0x4b5a16: mov esi,[esi+4]
0x4b5a19: jne near ptr 004B5960h
0x4b5a1f: jmp short 004B5A54h
0x4b5a21: mov eax,[ecx]
0x4b5a23: cmp [eax+2Ch],bl
0x4b5a26: jne short 004B5A3Eh
0x4b5a28: mov eax,[ecx+8]
0x4b5a2b: mov [eax+2Ch],bl
0x4b5a2e: push edx
0x4b5a2f: mov byte ptr [ecx+2Ch],0
0x4b5a33: call 005733A0h
0x4b5a38: mov ecx,[esi]
0x4b5a3a: mov edx,[esp+68h]
0x4b5a3e: mov al,[esi+2Ch]
0x4b5a41: mov [ecx+2Ch],al
0x4b5a44: mov [esi+2Ch],bl
0x4b5a47: mov ecx,[ecx]
0x4b5a49: mov [ecx+2Ch],bl
0x4b5a4c: push edx
0x4b5a4d: mov ecx,esi
0x4b5a4f: call 00465F60h
0x4b5a54: mov [edi+2Ch],bl
0x4b5a57: lea ecx,[ebp+0Ch]
0x4b5a5a: call dword ptr ds:[77CD74h]
0x4b5a60: push ebp
0x4b5a61: call 006516BAh
0x4b5a66: mov ecx,[esp+6Ch]
0x4b5a6a: mov eax,[ecx+8]
0x4b5a6d: add esp,4
0x4b5a70: test eax,eax
0x4b5a72: jbe short 004B5A7Ah
0x4b5a74: add eax,0FFFFFFFFh
0x4b5a77: mov [ecx+8],eax
0x4b5a7a: mov eax,[esp+6Ch]
0x4b5a7e: mov edx,[esp+70h]
0x4b5a82: mov ecx,[esp+74h]
0x4b5a86: mov [eax],edx
0x4b5a88: mov [eax+4],ecx
0x4b5a8b: mov ecx,[esp+58h]
0x4b5a8f: mov fs:[0],ecx
0x4b5a96: pop ecx
0x4b5a97: pop edi
0x4b5a98: pop esi
0x4b5a99: pop ebp
0x4b5a9a: pop ebx
0x4b5a9b: add esp,50h
0x4b5a9e: ret 10h
````

`sub_4b57e0` is called by sub_4b4590. It delegates to sub_401230, sub_43a360, sub_465f60 (8 callees).

### sub_4b5ab0 at 0x4b5ab0 (246 instructions)

````text
0x4b5ab0: push 0FFFFFFFFh
0x4b5ab2: push 7410D9h
0x4b5ab7: mov eax,fs:[0]
0x4b5abd: push eax
0x4b5abe: sub esp,44h
0x4b5ac1: push ebx
0x4b5ac2: push ebp
0x4b5ac3: push esi
0x4b5ac4: push edi
0x4b5ac5: mov eax,ds:[858220h]
0x4b5aca: xor eax,esp
0x4b5acc: push eax
0x4b5acd: lea eax,[esp+58h]
0x4b5ad1: mov fs:[0],eax
0x4b5ad7: mov eax,[esp+74h]
0x4b5adb: cmp byte ptr [eax+29h],0
0x4b5adf: je short 004B5B1Dh
0x4b5ae1: push 7C5AECh
0x4b5ae6: lea ecx,[esp+18h]
0x4b5aea: call dword ptr ds:[77CD7Ch]
0x4b5af0: lea eax,[esp+14h]
0x4b5af4: push eax
0x4b5af5: lea ecx,[esp+34h]
0x4b5af9: mov dword ptr [esp+64h],0
0x4b5b01: call 00401230h
0x4b5b06: push 80A4F8h
0x4b5b0b: lea ecx,[esp+34h]
0x4b5b0f: push ecx
0x4b5b10: mov dword ptr [esp+38h],790F90h
0x4b5b18: call 00652AC4h
0x4b5b1d: lea esi,[esp+70h]
0x4b5b21: mov ebp,eax
0x4b5b23: call 004B6660h
0x4b5b28: mov eax,[ebp]
0x4b5b2b: cmp byte ptr [eax+29h],0
0x4b5b2f: je short 004B5B36h
0x4b5b31: mov edi,[ebp+8]
0x4b5b34: jmp short 004B5B4Eh
0x4b5b36: mov edx,[ebp+8]
0x4b5b39: cmp byte ptr [edx+29h],0
0x4b5b3d: je short 004B5B43h
0x4b5b3f: mov edi,eax
0x4b5b41: jmp short 004B5B4Eh
0x4b5b43: mov ecx,[esp+74h]
0x4b5b47: cmp ecx,ebp
0x4b5b49: mov edi,[ecx+8]
0x4b5b4c: jne short 004B5BC2h
0x4b5b4e: cmp byte ptr [edi+29h],0
0x4b5b52: mov esi,[ebp+4]
0x4b5b55: jne short 004B5B5Ah
0x4b5b57: mov [edi+4],esi
0x4b5b5a: mov ecx,[esp+68h]
0x4b5b5e: mov eax,[ecx+4]
0x4b5b61: cmp [eax+4],ebp
0x4b5b64: jne short 004B5B6Bh
0x4b5b66: mov [eax+4],edi
0x4b5b69: jmp short 004B5B76h
0x4b5b6b: cmp [esi],ebp
0x4b5b6d: jne short 004B5B73h
0x4b5b6f: mov [esi],edi
0x4b5b71: jmp short 004B5B76h
0x4b5b73: mov [esi+8],edi
0x4b5b76: mov edx,[ecx+4]
0x4b5b79: cmp [edx],ebp
0x4b5b7b: jne short 004B5B9Dh
0x4b5b7d: cmp byte ptr [edi+29h],0
0x4b5b81: je short 004B5B87h
0x4b5b83: mov ecx,esi
0x4b5b85: jmp short 004B5B9Bh
0x4b5b87: mov eax,[edi]
0x4b5b89: cmp byte ptr [eax+29h],0
0x4b5b8d: mov ecx,edi
0x4b5b8f: jne short 004B5B9Bh
0x4b5b91: mov ecx,eax
0x4b5b93: mov eax,[ecx]
0x4b5b95: cmp byte ptr [eax+29h],0
0x4b5b99: je short 004B5B91h
0x4b5b9b: mov [edx],ecx
0x4b5b9d: mov eax,[esp+68h]
0x4b5ba1: mov ebx,[eax+4]
0x4b5ba4: cmp [ebx+8],ebp
0x4b5ba7: jne short 004B5C1Eh
0x4b5ba9: cmp byte ptr [edi+29h],0
0x4b5bad: je short 004B5BB6h
0x4b5baf: mov eax,esi
0x4b5bb1: mov [ebx+8],eax
0x4b5bb4: jmp short 004B5C1Eh
0x4b5bb6: mov eax,edi
0x4b5bb8: call 004B6340h
0x4b5bbd: mov [ebx+8],eax
0x4b5bc0: jmp short 004B5C1Eh
0x4b5bc2: mov [eax+4],ecx
0x4b5bc5: mov edx,[ebp]
0x4b5bc8: mov [ecx],edx
0x4b5bca: cmp ecx,[ebp+8]
0x4b5bcd: jne short 004B5BD3h
0x4b5bcf: mov esi,ecx
0x4b5bd1: jmp short 004B5BEDh
0x4b5bd3: cmp byte ptr [edi+29h],0
0x4b5bd7: mov esi,[ecx+4]
0x4b5bda: jne short 004B5BDFh
0x4b5bdc: mov [edi+4],esi
0x4b5bdf: mov [esi],edi
0x4b5be1: mov eax,[ebp+8]
0x4b5be4: mov [ecx+8],eax
0x4b5be7: mov edx,[ebp+8]
0x4b5bea: mov [edx+4],ecx
0x4b5bed: mov eax,[esp+68h]
0x4b5bf1: mov eax,[eax+4]
0x4b5bf4: cmp [eax+4],ebp
0x4b5bf7: jne short 004B5BFEh
0x4b5bf9: mov [eax+4],ecx
0x4b5bfc: jmp short 004B5C0Ch
0x4b5bfe: mov eax,[ebp+4]
0x4b5c01: cmp [eax],ebp
0x4b5c03: jne short 004B5C09h
0x4b5c05: mov [eax],ecx
0x4b5c07: jmp short 004B5C0Ch
0x4b5c09: mov [eax+8],ecx
0x4b5c0c: mov edx,[ebp+4]
0x4b5c0f: mov [ecx+4],edx
0x4b5c12: mov dl,[ebp+28h]
0x4b5c15: mov al,[ecx+28h]
0x4b5c18: mov [ecx+28h],dl
0x4b5c1b: mov [ebp+28h],al
0x4b5c1e: mov bl,1
0x4b5c20: cmp [ebp+28h],bl
0x4b5c23: jne near ptr 004B5D4Ah
0x4b5c29: mov eax,[esp+68h]
0x4b5c2d: mov ecx,[eax+4]
0x4b5c30: cmp edi,[ecx+4]
0x4b5c33: je near ptr 004B5D47h
0x4b5c39: lea esp,[esp]
0x4b5c40: cmp [edi+28h],bl
0x4b5c43: jne near ptr 004B5D47h
0x4b5c49: mov ecx,[esi]
0x4b5c4b: cmp edi,ecx
0x4b5c4d: jne short 004B5CC5h
0x4b5c4f: mov ecx,[esi+8]
0x4b5c52: cmp byte ptr [ecx+28h],0
0x4b5c56: jne short 004B5C6Eh
0x4b5c58: mov edx,[esp+68h]
0x4b5c5c: mov [ecx+28h],bl
0x4b5c5f: push edx
0x4b5c60: mov ecx,esi
0x4b5c62: mov byte ptr [esi+28h],0
0x4b5c66: call 0063A450h
0x4b5c6b: mov ecx,[esi+8]
0x4b5c6e: cmp byte ptr [ecx+29h],0
0x4b5c72: jne near ptr 004B5CF9h
0x4b5c78: mov eax,[ecx]
0x4b5c7a: cmp [eax+28h],bl
0x4b5c7d: jne short 004B5C87h
0x4b5c7f: mov edx,[ecx+8]
0x4b5c82: cmp [edx+28h],bl
0x4b5c85: je short 004B5CF5h
0x4b5c87: mov eax,[ecx+8]
0x4b5c8a: cmp [eax+28h],bl
0x4b5c8d: jne short 004B5CA5h
0x4b5c8f: mov edx,[ecx]
0x4b5c91: mov eax,[esp+68h]
0x4b5c95: mov [edx+28h],bl
0x4b5c98: push eax
0x4b5c99: mov byte ptr [ecx+28h],0
0x4b5c9d: call 004B6360h
0x4b5ca2: mov ecx,[esi+8]
0x4b5ca5: mov dl,[esi+28h]
0x4b5ca8: mov [ecx+28h],dl
0x4b5cab: mov [esi+28h],bl
0x4b5cae: mov eax,[ecx+8]
0x4b5cb1: mov ecx,[esp+68h]
0x4b5cb5: push ecx
0x4b5cb6: mov ecx,esi
0x4b5cb8: mov [eax+28h],bl
0x4b5cbb: call 0063A450h
0x4b5cc0: jmp near ptr 004B5D47h
0x4b5cc5: cmp byte ptr [ecx+28h],0
0x4b5cc9: jne short 004B5CE0h
0x4b5ccb: mov eax,[esp+68h]
0x4b5ccf: mov [ecx+28h],bl
0x4b5cd2: push eax
0x4b5cd3: mov ecx,esi
0x4b5cd5: mov byte ptr [esi+28h],0
0x4b5cd9: call 004B6360h
0x4b5cde: mov ecx,[esi]
0x4b5ce0: cmp byte ptr [ecx+29h],0
0x4b5ce4: jne short 004B5CF9h
0x4b5ce6: mov edx,[ecx+8]
0x4b5ce9: cmp [edx+28h],bl
0x4b5cec: jne short 004B5D10h
0x4b5cee: mov eax,[ecx]
0x4b5cf0: cmp [eax+28h],bl
0x4b5cf3: jne short 004B5D10h
0x4b5cf5: mov byte ptr [ecx+28h],0
0x4b5cf9: mov ecx,[esp+68h]
0x4b5cfd: mov edx,[ecx+4]
0x4b5d00: mov edi,esi
0x4b5d02: cmp edi,[edx+4]
0x4b5d05: mov esi,[esi+4]
0x4b5d08: jne near ptr 004B5C40h
0x4b5d0e: jmp short 004B5D47h
0x4b5d10: mov edx,[ecx]
0x4b5d12: cmp [edx+28h],bl
0x4b5d15: jne short 004B5D2Dh
0x4b5d17: mov eax,[ecx+8]
0x4b5d1a: mov edx,[esp+68h]
0x4b5d1e: mov [eax+28h],bl
0x4b5d21: push edx
0x4b5d22: mov byte ptr [ecx+28h],0
0x4b5d26: call 0063A450h
0x4b5d2b: mov ecx,[esi]
0x4b5d2d: mov al,[esi+28h]
0x4b5d30: mov edx,[esp+68h]
0x4b5d34: mov [ecx+28h],al
0x4b5d37: mov [esi+28h],bl
0x4b5d3a: mov ecx,[ecx]
0x4b5d3c: mov [ecx+28h],bl
0x4b5d3f: push edx
0x4b5d40: mov ecx,esi
0x4b5d42: call 004B6360h
0x4b5d47: mov [edi+28h],bl
0x4b5d4a: lea ecx,[ebp+0Ch]
0x4b5d4d: call dword ptr ds:[77CD74h]
0x4b5d53: push ebp
0x4b5d54: call 006516BAh
0x4b5d59: mov ecx,[esp+6Ch]
0x4b5d5d: mov eax,[ecx+8]
0x4b5d60: add esp,4
0x4b5d63: test eax,eax
0x4b5d65: jbe short 004B5D6Dh
0x4b5d67: add eax,0FFFFFFFFh
0x4b5d6a: mov [ecx+8],eax
0x4b5d6d: mov eax,[esp+6Ch]
0x4b5d71: mov ecx,[esp+70h]
0x4b5d75: mov edx,[esp+74h]
0x4b5d79: mov [eax],ecx
0x4b5d7b: mov [eax+4],edx
0x4b5d7e: mov ecx,[esp+58h]
0x4b5d82: mov fs:[0],ecx
0x4b5d89: pop ecx
0x4b5d8a: pop edi
0x4b5d8b: pop esi
0x4b5d8c: pop ebp
0x4b5d8d: pop ebx
0x4b5d8e: add esp,50h
0x4b5d91: ret 10h
````

`sub_4b5ab0` is called by sub_4b5430. It delegates to sub_401230, sub_4b6340, sub_4b6360 (7 callees).

### sub_4b6300 at 0x4b6300 (25 instructions)

````text
0x4b6300: push ebx
0x4b6301: push esi
0x4b6302: push edi
0x4b6303: mov edi,[esp+10h]
0x4b6307: cmp byte ptr [edi+29h],0
0x4b630b: mov ebx,ecx
0x4b630d: mov esi,edi
0x4b630f: jne short 004B6338h
0x4b6311: mov eax,[esi+8]
0x4b6314: push eax
0x4b6315: mov ecx,ebx
0x4b6317: call 004B6300h
0x4b631c: mov esi,[esi]
0x4b631e: lea ecx,[edi+0Ch]
0x4b6321: call dword ptr ds:[77CD74h]
0x4b6327: push edi
0x4b6328: call 006516BAh
0x4b632d: add esp,4
0x4b6330: cmp byte ptr [esi+29h],0
0x4b6334: mov edi,esi
0x4b6336: je short 004B6311h
0x4b6338: pop edi
0x4b6339: pop esi
0x4b633a: pop ebx
0x4b633b: ret 4
````

`sub_4b6300` is called by sub_4b5430, sub_4b6300. It delegates to sub_4b6300, j_ORDINAL 764 (2 callees).

### sub_4b6340 at 0x4b6340 (9 instructions)

````text
0x4b6340: mov ecx,[eax+8]
0x4b6343: cmp byte ptr [ecx+29h],0
0x4b6347: jne short 004B635Bh
0x4b6349: lea esp,[esp]
0x4b6350: mov eax,ecx
0x4b6352: mov ecx,[eax+8]
0x4b6355: cmp byte ptr [ecx+29h],0
0x4b6359: je short 004B6350h
0x4b635b: ret
````

`sub_4b6340` is called by sub_4b5ab0, sub_63a1a0. It calls nothing else.

### sub_4b6360 at 0x4b6360 (28 instructions)

````text
0x4b6360: mov eax,[ecx]
0x4b6362: mov edx,[eax+8]
0x4b6365: mov [ecx],edx
0x4b6367: mov edx,[eax+8]
0x4b636a: cmp byte ptr [edx+29h],0
0x4b636e: jne short 004B6373h
0x4b6370: mov [edx+4],ecx
0x4b6373: mov edx,[ecx+4]
0x4b6376: mov [eax+4],edx
0x4b6379: mov edx,[esp+4]
0x4b637d: mov edx,[edx+4]
0x4b6380: cmp ecx,[edx+4]
0x4b6383: jne short 004B6391h
0x4b6385: mov [edx+4],eax
0x4b6388: mov [eax+8],ecx
0x4b638b: mov [ecx+4],eax
0x4b638e: ret 4
0x4b6391: mov edx,[ecx+4]
0x4b6394: cmp ecx,[edx+8]
0x4b6397: jne short 004B63A5h
0x4b6399: mov [edx+8],eax
0x4b639c: mov [eax+8],ecx
0x4b639f: mov [ecx+4],eax
0x4b63a2: ret 4
0x4b63a5: mov [edx],eax
0x4b63a7: mov [eax+8],ecx
0x4b63aa: mov [ecx+4],eax
0x4b63ad: ret 4
````

`sub_4b6360` is called by sub_4b5ab0, sub_639ff0, sub_63a1a0. It calls nothing else.

### sub_4b6490 at 0x4b6490 (39 instructions)

````text
0x4b6490: cmp dword ptr [esi],0
0x4b6493: push edi
0x4b6494: mov edi,ds:[77D0E4h]
0x4b649a: jne short 004B649Eh
0x4b649c: call edi
0x4b649e: mov eax,[esi+4]
0x4b64a1: cmp byte ptr [eax+11h],0
0x4b64a5: je short 004B64ABh
0x4b64a7: call edi
0x4b64a9: pop edi
0x4b64aa: ret
0x4b64ab: mov ecx,[eax+8]
0x4b64ae: cmp byte ptr [ecx+11h],0
0x4b64b2: jne short 004B64CFh
0x4b64b4: mov eax,[ecx]
0x4b64b6: cmp byte ptr [eax+11h],0
0x4b64ba: jne short 004B64CAh
0x4b64bc: lea esp,[esp]
0x4b64c0: mov ecx,eax
0x4b64c2: mov eax,[ecx]
0x4b64c4: cmp byte ptr [eax+11h],0
0x4b64c8: je short 004B64C0h
0x4b64ca: mov [esi+4],ecx
0x4b64cd: pop edi
0x4b64ce: ret
0x4b64cf: mov eax,[eax+4]
0x4b64d2: cmp byte ptr [eax+11h],0
0x4b64d6: jne short 004B64EEh
0x4b64d8: mov ecx,[esi+4]
0x4b64db: cmp ecx,[eax+8]
0x4b64de: jne short 004B64EEh
0x4b64e0: mov [esi+4],eax
0x4b64e3: mov edx,eax
0x4b64e5: mov eax,[edx+4]
0x4b64e8: cmp byte ptr [eax+11h],0
0x4b64ec: je short 004B64D8h
0x4b64ee: mov [esi+4],eax
0x4b64f1: pop edi
0x4b64f2: ret
````

`sub_4b6490` is called by sub_4b4030, sub_4b5020, sub_60b040, sub_60b1c0. It calls nothing else.

### sub_4b6500 at 0x4b6500 (39 instructions)

````text
0x4b6500: cmp dword ptr [esi],0
0x4b6503: push edi
0x4b6504: mov edi,ds:[77D0E4h]
0x4b650a: jne short 004B650Eh
0x4b650c: call edi
0x4b650e: mov eax,[esi+4]
0x4b6511: cmp byte ptr [eax+0Fh],0
0x4b6515: je short 004B651Bh
0x4b6517: call edi
0x4b6519: pop edi
0x4b651a: ret
0x4b651b: mov ecx,[eax+8]
0x4b651e: cmp byte ptr [ecx+0Fh],0
0x4b6522: jne short 004B653Fh
0x4b6524: mov eax,[ecx]
0x4b6526: cmp byte ptr [eax+0Fh],0
0x4b652a: jne short 004B653Ah
0x4b652c: lea esp,[esp]
0x4b6530: mov ecx,eax
0x4b6532: mov eax,[ecx]
0x4b6534: cmp byte ptr [eax+0Fh],0
0x4b6538: je short 004B6530h
0x4b653a: mov [esi+4],ecx
0x4b653d: pop edi
0x4b653e: ret
0x4b653f: mov eax,[eax+4]
0x4b6542: cmp byte ptr [eax+0Fh],0
0x4b6546: jne short 004B655Eh
0x4b6548: mov ecx,[esi+4]
0x4b654b: cmp ecx,[eax+8]
0x4b654e: jne short 004B655Eh
0x4b6550: mov [esi+4],eax
0x4b6553: mov edx,eax
0x4b6555: mov eax,[edx+4]
0x4b6558: cmp byte ptr [eax+0Fh],0
0x4b655c: je short 004B6548h
0x4b655e: mov [esi+4],eax
0x4b6561: pop edi
0x4b6562: ret
````

`sub_4b6500` is called by sub_4b3cc0, sub_4b4b50. It calls nothing else.

### sub_4b6660 at 0x4b6660 (39 instructions)

````text
0x4b6660: cmp dword ptr [esi],0
0x4b6663: push edi
0x4b6664: mov edi,ds:[77D0E4h]
0x4b666a: jne short 004B666Eh
0x4b666c: call edi
0x4b666e: mov eax,[esi+4]
0x4b6671: cmp byte ptr [eax+29h],0
0x4b6675: je short 004B667Bh
0x4b6677: call edi
0x4b6679: pop edi
0x4b667a: ret
0x4b667b: mov ecx,[eax+8]
0x4b667e: cmp byte ptr [ecx+29h],0
0x4b6682: jne short 004B669Fh
0x4b6684: mov eax,[ecx]
0x4b6686: cmp byte ptr [eax+29h],0
0x4b668a: jne short 004B669Ah
0x4b668c: lea esp,[esp]
0x4b6690: mov ecx,eax
0x4b6692: mov eax,[ecx]
0x4b6694: cmp byte ptr [eax+29h],0
0x4b6698: je short 004B6690h
0x4b669a: mov [esi+4],ecx
0x4b669d: pop edi
0x4b669e: ret
0x4b669f: mov eax,[eax+4]
0x4b66a2: cmp byte ptr [eax+29h],0
0x4b66a6: jne short 004B66BEh
0x4b66a8: mov ecx,[esi+4]
0x4b66ab: cmp ecx,[eax+8]
0x4b66ae: jne short 004B66BEh
0x4b66b0: mov [esi+4],eax
0x4b66b3: mov edx,eax
0x4b66b5: mov eax,[edx+4]
0x4b66b8: cmp byte ptr [eax+29h],0
0x4b66bc: je short 004B66A8h
0x4b66be: mov [esi+4],eax
0x4b66c1: pop edi
0x4b66c2: ret
````

`sub_4b6660` is called by sub_4b5430, sub_4b5ab0, sub_639c30, sub_639f20, sub_63a1a0. It calls nothing else.

### sub_4c6520 at 0x4c6520 (47 instructions)

````text
0x4c6520: cmp dword ptr [esi],0
0x4c6523: push edi
0x4c6524: mov edi,ds:[77D0E4h]
0x4c652a: jne short 004C652Eh
0x4c652c: call edi
0x4c652e: mov eax,[esi+4]
0x4c6531: cmp byte ptr [eax+29h],0
0x4c6535: je short 004C6547h
0x4c6537: mov eax,[eax+8]
0x4c653a: mov [esi+4],eax
0x4c653d: cmp byte ptr [eax+29h],0
0x4c6541: je short 004C65A1h
0x4c6543: call edi
0x4c6545: pop edi
0x4c6546: ret
0x4c6547: mov ecx,[eax]
0x4c6549: cmp byte ptr [ecx+29h],0
0x4c654d: jne short 004C6570h
0x4c654f: mov eax,[ecx+8]
0x4c6552: cmp byte ptr [eax+29h],0
0x4c6556: jne short 004C656Bh
0x4c6558: jmp short 004C6560h
0x4c6560: mov ecx,eax
0x4c6562: mov eax,[ecx+8]
0x4c6565: cmp byte ptr [eax+29h],0
0x4c6569: je short 004C6560h
0x4c656b: mov [esi+4],ecx
0x4c656e: pop edi
0x4c656f: ret
0x4c6570: mov eax,[eax+4]
0x4c6573: cmp byte ptr [eax+29h],0
0x4c6577: jne short 004C6595h
0x4c6579: lea esp,[esp]
0x4c6580: mov ecx,[esi+4]
0x4c6583: cmp ecx,[eax]
0x4c6585: jne short 004C6595h
0x4c6587: mov [esi+4],eax
0x4c658a: mov edx,eax
0x4c658c: mov eax,[edx+4]
0x4c658f: cmp byte ptr [eax+29h],0
0x4c6593: je short 004C6580h
0x4c6595: mov ecx,[esi+4]
0x4c6598: cmp byte ptr [ecx+29h],0
0x4c659c: jne short 004C6543h
0x4c659e: mov [esi+4],eax
0x4c65a1: pop edi
0x4c65a2: ret
````

`sub_4c6520` is called by sub_639c30, sub_639e40. It calls nothing else.

### sub_4cc190 at 0x4cc190 (23 instructions)

````text
0x4cc190: push esi
0x4cc191: mov esi,[ebx+4]
0x4cc194: test esi,esi
0x4cc196: je short 004CC1BAh
0x4cc198: push edi
0x4cc199: mov edi,[ebx+8]
0x4cc19c: cmp esi,edi
0x4cc19e: je short 004CC1ADh
0x4cc1a0: push esi
0x4cc1a1: call 004738D0h
0x4cc1a6: add esi,74h
0x4cc1a9: cmp esi,edi
0x4cc1ab: jne short 004CC1A0h
0x4cc1ad: mov eax,[ebx+4]
0x4cc1b0: push eax
0x4cc1b1: call 006516BAh
0x4cc1b6: add esp,4
0x4cc1b9: pop edi
0x4cc1ba: mov dword ptr [ebx+4],0
0x4cc1c1: mov dword ptr [ebx+8],0
0x4cc1c8: mov dword ptr [ebx+0Ch],0
0x4cc1cf: pop esi
0x4cc1d0: ret
````

`sub_4cc190` is called by sub_631110, sub_632130. It delegates to sub_4738d0, j_ORDINAL 764 (2 callees).

### sub_4cf400 at 0x4cf400 (30 instructions)

````text
0x4cf400: push ebp
0x4cf401: mov ebp,[esp+8]
0x4cf405: push edi
0x4cf406: mov edi,eax
0x4cf408: cmp edi,ebp
0x4cf40a: je short 004CF43Eh
0x4cf40c: push ebx
0x4cf40d: push esi
0x4cf40e: lea esi,[edi+20h]
0x4cf411: xor ebx,ebx
0x4cf413: mov eax,[esi]
0x4cf415: cmp eax,ebx
0x4cf417: je short 004CF422h
0x4cf419: push eax
0x4cf41a: call 006516BAh
0x4cf41f: add esp,4
0x4cf422: mov ecx,edi
0x4cf424: mov [esi],ebx
0x4cf426: mov [esi+4],ebx
0x4cf429: mov [esi+8],ebx
0x4cf42c: call dword ptr ds:[77CD74h]
0x4cf432: add edi,34h
0x4cf435: add esi,34h
0x4cf438: cmp edi,ebp
0x4cf43a: jne short 004CF413h
0x4cf43c: pop esi
0x4cf43d: pop ebx
0x4cf43e: pop edi
0x4cf43f: pop ebp
0x4cf440: ret
````

`sub_4cf400` is called by sub_5dcbb0. It delegates to j_ORDINAL 764 (1 callees).

### sub_4db900 at 0x4db900 (23 instructions)

````text
0x4db900: or eax,0FFFFFFFFh
0x4db903: xor edx,edx
0x4db905: div ecx
0x4db907: sub esp,10h
0x4db90a: cmp eax,30h
0x4db90d: jae short 004DB93Ch
0x4db90f: lea eax,[esp]
0x4db912: push eax
0x4db913: lea ecx,[esp+8]
0x4db917: mov dword ptr [esp+4],0
0x4db91f: call dword ptr ds:[77D0DCh]
0x4db925: push 80A2ACh
0x4db92a: lea ecx,[esp+8]
0x4db92e: push ecx
0x4db92f: mov dword ptr [esp+0Ch],78FFD4h
0x4db937: call 00652AC4h
0x4db93c: lea edx,[ecx+ecx*2]
0x4db93f: shl edx,4
0x4db942: push edx
0x4db943: call 006516C0h
0x4db948: add esp,4
0x4db94b: add esp,10h
0x4db94e: ret
````

`sub_4db900` is called by sub_5735d0. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_4dc4d0 at 0x4dc4d0 (48 instructions)

````text
0x4dc4d0: push 0FFFFFFFFh
0x4dc4d2: push 7569A7h
0x4dc4d7: mov eax,fs:[0]
0x4dc4dd: push eax
0x4dc4de: sub esp,8
0x4dc4e1: push ebx
0x4dc4e2: mov eax,ds:[858220h]
0x4dc4e7: xor eax,esp
0x4dc4e9: push eax
0x4dc4ea: lea eax,[esp+10h]
0x4dc4ee: mov fs:[0],eax
0x4dc4f4: xor ebx,ebx
0x4dc4f6: mov ecx,874E64h
0x4dc4fb: mov dword ptr [esp+0Ch],874E54h
0x4dc503: mov ds:[874E54h],bl
0x4dc509: mov ds:[874E58h],ebx
0x4dc50f: mov ds:[874E5Ch],ebx
0x4dc515: mov ds:[874E60h],ebx
0x4dc51b: call dword ptr ds:[77DF80h]
0x4dc521: mov [esp+18h],ebx
0x4dc525: mov ds:[874E70h],ebx
0x4dc52b: mov ds:[874E74h],ebx
0x4dc531: mov ds:[874E78h],ebx
0x4dc537: push 20h
0x4dc539: mov byte ptr [esp+1Ch],1
0x4dc53e: call 006516C0h
0x4dc543: add esp,4
0x4dc546: cmp eax,ebx
0x4dc548: je short 004DC577h
0x4dc54a: mov [eax+4],ebx
0x4dc54d: mov [eax+8],ebx
0x4dc550: mov dword ptr [eax+0Ch],64h
0x4dc557: mov [eax+10h],ebx
0x4dc55a: mov [eax+14h],ebx
0x4dc55d: mov [eax+18h],bl
0x4dc560: mov [eax+19h],bl
0x4dc563: mov dword ptr [eax],7DC264h
0x4dc569: mov dword ptr [eax+1Ch],874E54h
0x4dc570: mov ds:[874E7Ch],eax
0x4dc575: jmp short 004DC57Dh
0x4dc577: mov ds:[874E7Ch],ebx
0x4dc57d: mov eax,874E54h
0x4dc582: mov ecx,[esp+10h]
0x4dc586: mov fs:[0],ecx
0x4dc58d: pop ecx
0x4dc58e: pop ebx
0x4dc58f: add esp,14h
0x4dc592: ret
````

`sub_4dc4d0` is called by ?get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ. It delegates to j_ORDINAL 762 (1 callees).

### sub_4dc5a0 at 0x4dc5a0 (77 instructions)

````text
0x4dc5a0: push 0FFFFFFFFh
0x4dc5a2: push 7569A7h
0x4dc5a7: mov eax,fs:[0]
0x4dc5ad: push eax
0x4dc5ae: sub esp,8
0x4dc5b1: push esi
0x4dc5b2: mov eax,ds:[858220h]
0x4dc5b7: xor eax,esp
0x4dc5b9: push eax
0x4dc5ba: lea eax,[esp+10h]
0x4dc5be: mov fs:[0],eax
0x4dc5c4: mov dword ptr [esp+0Ch],874E54h
0x4dc5cc: mov dword ptr [esp+18h],1
0x4dc5d4: mov eax,ds:[874E64h]
0x4dc5d9: mov edx,[eax+4]
0x4dc5dc: mov ecx,874E64h
0x4dc5e1: call edx
0x4dc5e3: mov eax,874E6Ch
0x4dc5e8: call 0052C150h
0x4dc5ed: mov eax,ds:[874E64h]
0x4dc5f2: mov edx,[eax+0Ch]
0x4dc5f5: mov ecx,874E64h
0x4dc5fa: call edx
0x4dc5fc: mov esi,ds:[874E7Ch]
0x4dc602: call 00401080h
0x4dc607: mov ecx,ds:[874E7Ch]
0x4dc60d: test ecx,ecx
0x4dc60f: je short 004DC619h
0x4dc611: mov eax,[ecx]
0x4dc613: mov edx,[eax]
0x4dc615: push 1
0x4dc617: call edx
0x4dc619: mov eax,ds:[874E58h]
0x4dc61e: test eax,eax
0x4dc620: je short 004DC635h
0x4dc622: mov esi,eax
0x4dc624: add eax,4
0x4dc627: call 004DD230h
0x4dc62c: push esi
0x4dc62d: call 006516BAh
0x4dc632: add esp,4
0x4dc635: mov eax,ds:[874E5Ch]
0x4dc63a: test eax,eax
0x4dc63c: je short 004DC651h
0x4dc63e: mov esi,eax
0x4dc640: add eax,4
0x4dc643: call 004DD230h
0x4dc648: push esi
0x4dc649: call 006516BAh
0x4dc64e: add esp,4
0x4dc651: mov eax,ds:[874E60h]
0x4dc656: test eax,eax
0x4dc658: je short 004DC66Dh
0x4dc65a: mov esi,eax
0x4dc65c: add eax,4
0x4dc65f: call 004DD230h
0x4dc664: push esi
0x4dc665: call 006516BAh
0x4dc66a: add esp,4
0x4dc66d: mov eax,ds:[874E70h]
0x4dc672: test eax,eax
0x4dc674: je short 004DC67Fh
0x4dc676: push eax
0x4dc677: call 006516BAh
0x4dc67c: add esp,4
0x4dc67f: mov ecx,874E64h
0x4dc684: mov dword ptr ds:[874E70h],0
0x4dc68e: mov dword ptr ds:[874E74h],0
0x4dc698: mov dword ptr ds:[874E78h],0
0x4dc6a2: mov dword ptr [esp+18h],0FFFFFFFFh
0x4dc6aa: call dword ptr ds:[77DF7Ch]
0x4dc6b0: mov ecx,[esp+10h]
0x4dc6b4: mov fs:[0],ecx
0x4dc6bb: pop ecx
0x4dc6bc: pop esi
0x4dc6bd: add esp,14h
0x4dc6c0: ret
````

`sub_4dc5a0` is called by sub_77b180. It delegates to sub_401080, sub_4dd230, sub_52c150 (4 callees).

### sub_4dc780 at 0x4dc780 (77 instructions)

````text
0x4dc780: push ebp
0x4dc781: mov ebp,esp
0x4dc783: and esp,0FFFFFFF8h
0x4dc786: push 0FFFFFFFFh
0x4dc788: push 73C188h
0x4dc78d: mov eax,fs:[0]
0x4dc793: push eax
0x4dc794: sub esp,8
0x4dc797: push ebx
0x4dc798: push esi
0x4dc799: push edi
0x4dc79a: mov eax,ds:[858220h]
0x4dc79f: xor eax,esp
0x4dc7a1: push eax
0x4dc7a2: lea eax,[esp+18h]
0x4dc7a6: mov fs:[0],eax
0x4dc7ac: mov esi,ecx
0x4dc7ae: mov eax,[esi+10h]
0x4dc7b1: mov edx,[eax+4]
0x4dc7b4: lea ecx,[esi+10h]
0x4dc7b7: mov [esp+10h],ecx
0x4dc7bb: call edx
0x4dc7bd: add esi,18h
0x4dc7c0: mov dword ptr [esp+20h],0
0x4dc7c8: mov edi,[esi+4]
0x4dc7cb: cmp edi,[esi+8]
0x4dc7ce: jbe short 004DC7D6h
0x4dc7d0: call dword ptr ds:[77D0E4h]
0x4dc7d6: mov ebx,[esi+8]
0x4dc7d9: cmp [esi+4],ebx
0x4dc7dc: jbe short 004DC7E4h
0x4dc7de: call dword ptr ds:[77D0E4h]
0x4dc7e4: cmp esi,esi
0x4dc7e6: je short 004DC7EEh
0x4dc7e8: call dword ptr ds:[77D0E4h]
0x4dc7ee: cmp edi,ebx
0x4dc7f0: je short 004DC838h
0x4dc7f2: cmp edi,[esi+8]
0x4dc7f5: jb short 004DC7FDh
0x4dc7f7: call dword ptr ds:[77D0E4h]
0x4dc7fd: mov eax,[ebp+8]
0x4dc800: cmp [edi],eax
0x4dc802: je short 004DC814h
0x4dc804: cmp edi,[esi+8]
0x4dc807: jb short 004DC80Fh
0x4dc809: call dword ptr ds:[77D0E4h]
0x4dc80f: add edi,4
0x4dc812: jmp short 004DC7D6h
0x4dc814: mov eax,[esi+8]
0x4dc817: lea ecx,[edi+4]
0x4dc81a: sub eax,ecx
0x4dc81c: sar eax,2
0x4dc81f: test eax,eax
0x4dc821: jle short 004DC834h
0x4dc823: add eax,eax
0x4dc825: add eax,eax
0x4dc827: push eax
0x4dc828: push ecx
0x4dc829: push eax
0x4dc82a: push edi
0x4dc82b: call dword ptr ds:[77D0C0h]
0x4dc831: add esp,10h
0x4dc834: add dword ptr [esi+8],0FFFFFFFCh
0x4dc838: mov dword ptr [esp+20h],0FFFFFFFFh
0x4dc840: mov ecx,[esp+10h]
0x4dc844: mov edx,[ecx]
0x4dc846: mov eax,[edx+0Ch]
0x4dc849: call eax
0x4dc84b: mov ecx,[esp+18h]
0x4dc84f: mov fs:[0],ecx
0x4dc856: pop ecx
0x4dc857: pop edi
0x4dc858: pop esi
0x4dc859: pop ebx
0x4dc85a: mov esp,ebp
0x4dc85c: pop ebp
0x4dc85d: ret 4
````

`sub_4dc780` is called by sub_585a40, sub_5ea9c0, sub_77b400, sub_77b420. It calls nothing else.

### ?get_mutable_instance@?$singleton@VCEventMan@@@serialization@boost@@SAAAVCEventMan@@XZ at 0x4dcf80 (4 instructions)

````text
0x4dcf80: push ecx
0x4dcf81: call 004DD270h
0x4dcf86: pop ecx
0x4dcf87: ret
````

`?get_mutable_instance@?$singleton@VCEventMan@@@serialization@boost@@SAAAVCEventMan@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ (1 callees).

### sub_4dcf90 at 0x4dcf90 (42 instructions)

````text
0x4dcf90: push 0FFFFFFFFh
0x4dcf92: push 73B5A8h
0x4dcf97: mov eax,fs:[0]
0x4dcf9d: push eax
0x4dcf9e: push esi
0x4dcf9f: push edi
0x4dcfa0: mov eax,ds:[858220h]
0x4dcfa5: xor eax,esp
0x4dcfa7: push eax
0x4dcfa8: lea eax,[esp+0Ch]
0x4dcfac: mov fs:[0],eax
0x4dcfb2: mov edi,[esp+1Ch]
0x4dcfb6: mov dword ptr [esp+14h],0
0x4dcfbe: mov esi,[edi+28h]
0x4dcfc1: test esi,esi
0x4dcfc3: je short 004DCFEFh
0x4dcfc5: lea eax,[esi+4]
0x4dcfc8: or ecx,0FFFFFFFFh
0x4dcfcb: lock xadd [eax],ecx
0x4dcfcf: jne short 004DCFEFh
0x4dcfd1: mov edx,[esi]
0x4dcfd3: mov eax,[edx+4]
0x4dcfd6: mov ecx,esi
0x4dcfd8: call eax
0x4dcfda: lea ecx,[esi+8]
0x4dcfdd: or edx,0FFFFFFFFh
0x4dcfe0: lock xadd [ecx],edx
0x4dcfe4: jne short 004DCFEFh
0x4dcfe6: mov eax,[esi]
0x4dcfe8: mov edx,[eax+8]
0x4dcfeb: mov ecx,esi
0x4dcfed: call edx
0x4dcfef: lea ecx,[edi+4]
0x4dcff2: mov dword ptr [esp+14h],0FFFFFFFFh
0x4dcffa: call dword ptr ds:[77CD74h]
0x4dd000: mov ecx,[esp+0Ch]
0x4dd004: mov fs:[0],ecx
0x4dd00b: pop ecx
0x4dd00c: pop edi
0x4dd00d: pop esi
0x4dd00e: add esp,0Ch
0x4dd011: ret 4
````

`sub_4dcf90` is called by sub_4dd6d0, sub_4ddaa0. It calls nothing else.

### sub_4dd230 at 0x4dd230 (26 instructions)

````text
0x4dd230: push ebp
0x4dd231: mov ebp,esp
0x4dd233: and esp,0FFFFFFF8h
0x4dd236: sub esp,0Ch
0x4dd239: push edi
0x4dd23a: mov edi,eax
0x4dd23c: mov eax,[edi+4]
0x4dd23f: mov ecx,[eax]
0x4dd241: push eax
0x4dd242: push edi
0x4dd243: push ecx
0x4dd244: push edi
0x4dd245: lea eax,[esp+18h]
0x4dd249: push eax
0x4dd24a: call 004DD400h
0x4dd24f: mov ecx,[edi+4]
0x4dd252: push ecx
0x4dd253: call 006516BAh
0x4dd258: add esp,4
0x4dd25b: xor eax,eax
0x4dd25d: mov [edi+4],eax
0x4dd260: mov [edi+8],eax
0x4dd263: pop edi
0x4dd264: mov esp,ebp
0x4dd266: pop ebp
0x4dd267: ret
````

`sub_4dd230` is called by sub_4dc5a0. It delegates to sub_4dd400, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ at 0x4dd270 (25 instructions)

````text
0x4dd270: push 0FFFFFFFFh
0x4dd272: push 75D04Eh
0x4dd277: mov eax,fs:[0]
0x4dd27d: push eax
0x4dd27e: mov eax,ds:[858220h]
0x4dd283: push ecx
0x4dd284: xor eax,esp
0x4dd286: push eax
0x4dd287: lea eax,[esp+8]
0x4dd28b: mov fs:[0],eax
0x4dd291: mov eax,1
0x4dd296: test ds:[875F3Ch],al
0x4dd29c: jne short 004DD2BEh
0x4dd29e: or ds:[875F3Ch],eax
0x4dd2a4: mov dword ptr [esp+10h],0
0x4dd2ac: call 004DC4D0h
0x4dd2b1: push 77B180h
0x4dd2b6: call 006527EDh
0x4dd2bb: add esp,4
0x4dd2be: mov eax,874E54h
0x4dd2c3: mov ecx,[esp+8]
0x4dd2c7: mov fs:[0],ecx
0x4dd2ce: pop ecx
0x4dd2cf: add esp,10h
0x4dd2d2: ret
````

`?get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ` is called by ?get_mutable_instance@?$singleton@VCEventMan@@@serialization@boost@@SAAAVCEventMan@@XZ, sub_585a40, sub_5ea9c0, sub_77b400, sub_77b420. It delegates to sub_4dc4d0, sub_6527ed (2 callees).

### sub_4dd400 at 0x4dd400 (72 instructions)

````text
0x4dd400: mov eax,[edi+4]
0x4dd403: sub esp,0Ch
0x4dd406: push ebx
0x4dd407: mov ebx,[esp+18h]
0x4dd40b: test ebx,ebx
0x4dd40d: push ebp
0x4dd40e: push esi
0x4dd40f: mov esi,[eax]
0x4dd411: je short 004DD417h
0x4dd413: cmp ebx,edi
0x4dd415: je short 004DD41Dh
0x4dd417: call dword ptr ds:[77D0E4h]
0x4dd41d: mov ebp,[esp+24h]
0x4dd421: cmp ebp,esi
0x4dd423: jne short 004DD480h
0x4dd425: mov eax,[esp+28h]
0x4dd429: test eax,eax
0x4dd42b: mov esi,[edi+4]
0x4dd42e: je short 004DD434h
0x4dd430: cmp eax,edi
0x4dd432: je short 004DD43Ah
0x4dd434: call dword ptr ds:[77D0E4h]
0x4dd43a: cmp [esp+2Ch],esi
0x4dd43e: jne short 004DD480h
0x4dd440: mov ecx,[edi+4]
0x4dd443: mov edx,[ecx+4]
0x4dd446: push edx
0x4dd447: mov ecx,edi
0x4dd449: call 004DDAA0h
0x4dd44e: mov eax,[edi+4]
0x4dd451: mov [eax+4],eax
0x4dd454: mov eax,[edi+4]
0x4dd457: mov dword ptr [edi+8],0
0x4dd45e: mov [eax],eax
0x4dd460: mov eax,[edi+4]
0x4dd463: mov [eax+8],eax
0x4dd466: mov eax,[edi+4]
0x4dd469: mov ecx,[eax]
0x4dd46b: mov eax,[esp+1Ch]
0x4dd46f: mov [eax+4],ecx
0x4dd472: mov [eax],edi
0x4dd474: pop esi
0x4dd475: pop ebp
0x4dd476: pop ebx
0x4dd477: add esp,0Ch
0x4dd47a: ret 14h
0x4dd480: test ebx,ebx
0x4dd482: je short 004DD48Ah
0x4dd484: cmp ebx,[esp+28h]
0x4dd488: je short 004DD490h
0x4dd48a: call dword ptr ds:[77D0E4h]
0x4dd490: cmp ebp,[esp+2Ch]
0x4dd494: je short 004DD4B6h
0x4dd496: lea esi,[esp+20h]
0x4dd49a: call 00633EE0h
0x4dd49f: push ebp
0x4dd4a0: push ebx
0x4dd4a1: lea edx,[esp+18h]
0x4dd4a5: push edx
0x4dd4a6: push edi
0x4dd4a7: call 004DD6D0h
0x4dd4ac: mov ebp,[esp+24h]
0x4dd4b0: mov ebx,[esp+20h]
0x4dd4b4: jmp short 004DD480h
0x4dd4b6: mov eax,[esp+1Ch]
0x4dd4ba: pop esi
0x4dd4bb: mov [eax+4],ebp
0x4dd4be: pop ebp
0x4dd4bf: mov [eax],ebx
0x4dd4c1: pop ebx
0x4dd4c2: add esp,0Ch
0x4dd4c5: ret 14h
````

`sub_4dd400` is called by sub_4dd230. It delegates to sub_4dd6d0, sub_4ddaa0, sub_633ee0 (3 callees).

### sub_4dd6d0 at 0x4dd6d0 (247 instructions)

````text
0x4dd6d0: push 0FFFFFFFFh
0x4dd6d2: push 7410D9h
0x4dd6d7: mov eax,fs:[0]
0x4dd6dd: push eax
0x4dd6de: sub esp,44h
0x4dd6e1: push ebx
0x4dd6e2: push ebp
0x4dd6e3: push esi
0x4dd6e4: push edi
0x4dd6e5: mov eax,ds:[858220h]
0x4dd6ea: xor eax,esp
0x4dd6ec: push eax
0x4dd6ed: lea eax,[esp+58h]
0x4dd6f1: mov fs:[0],eax
0x4dd6f7: mov eax,[esp+74h]
0x4dd6fb: cmp byte ptr [eax+39h],0
0x4dd6ff: je short 004DD73Dh
0x4dd701: push 7C5AECh
0x4dd706: lea ecx,[esp+18h]
0x4dd70a: call dword ptr ds:[77CD7Ch]
0x4dd710: lea eax,[esp+14h]
0x4dd714: push eax
0x4dd715: lea ecx,[esp+34h]
0x4dd719: mov dword ptr [esp+64h],0
0x4dd721: call 00401230h
0x4dd726: push 80A4F8h
0x4dd72b: lea ecx,[esp+34h]
0x4dd72f: push ecx
0x4dd730: mov dword ptr [esp+38h],790F90h
0x4dd738: call 00652AC4h
0x4dd73d: lea esi,[esp+70h]
0x4dd741: mov ebp,eax
0x4dd743: call 00633EE0h
0x4dd748: mov eax,[ebp]
0x4dd74b: cmp byte ptr [eax+39h],0
0x4dd74f: je short 004DD756h
0x4dd751: mov edi,[ebp+8]
0x4dd754: jmp short 004DD76Eh
0x4dd756: mov edx,[ebp+8]
0x4dd759: cmp byte ptr [edx+39h],0
0x4dd75d: je short 004DD763h
0x4dd75f: mov edi,eax
0x4dd761: jmp short 004DD76Eh
0x4dd763: mov ecx,[esp+74h]
0x4dd767: cmp ecx,ebp
0x4dd769: mov edi,[ecx+8]
0x4dd76c: jne short 004DD7E2h
0x4dd76e: cmp byte ptr [edi+39h],0
0x4dd772: mov esi,[ebp+4]
0x4dd775: jne short 004DD77Ah
0x4dd777: mov [edi+4],esi
0x4dd77a: mov ecx,[esp+68h]
0x4dd77e: mov eax,[ecx+4]
0x4dd781: cmp [eax+4],ebp
0x4dd784: jne short 004DD78Bh
0x4dd786: mov [eax+4],edi
0x4dd789: jmp short 004DD796h
0x4dd78b: cmp [esi],ebp
0x4dd78d: jne short 004DD793h
0x4dd78f: mov [esi],edi
0x4dd791: jmp short 004DD796h
0x4dd793: mov [esi+8],edi
0x4dd796: mov edx,[ecx+4]
0x4dd799: cmp [edx],ebp
0x4dd79b: jne short 004DD7BDh
0x4dd79d: cmp byte ptr [edi+39h],0
0x4dd7a1: je short 004DD7A7h
0x4dd7a3: mov ecx,esi
0x4dd7a5: jmp short 004DD7BBh
0x4dd7a7: mov eax,[edi]
0x4dd7a9: cmp byte ptr [eax+39h],0
0x4dd7ad: mov ecx,edi
0x4dd7af: jne short 004DD7BBh
0x4dd7b1: mov ecx,eax
0x4dd7b3: mov eax,[ecx]
0x4dd7b5: cmp byte ptr [eax+39h],0
0x4dd7b9: je short 004DD7B1h
0x4dd7bb: mov [edx],ecx
0x4dd7bd: mov eax,[esp+68h]
0x4dd7c1: mov ebx,[eax+4]
0x4dd7c4: cmp [ebx+8],ebp
0x4dd7c7: jne short 004DD83Eh
0x4dd7c9: cmp byte ptr [edi+39h],0
0x4dd7cd: je short 004DD7D6h
0x4dd7cf: mov eax,esi
0x4dd7d1: mov [ebx+8],eax
0x4dd7d4: jmp short 004DD83Eh
0x4dd7d6: mov eax,edi
0x4dd7d8: call 00458540h
0x4dd7dd: mov [ebx+8],eax
0x4dd7e0: jmp short 004DD83Eh
0x4dd7e2: mov [eax+4],ecx
0x4dd7e5: mov edx,[ebp]
0x4dd7e8: mov [ecx],edx
0x4dd7ea: cmp ecx,[ebp+8]
0x4dd7ed: jne short 004DD7F3h
0x4dd7ef: mov esi,ecx
0x4dd7f1: jmp short 004DD80Dh
0x4dd7f3: cmp byte ptr [edi+39h],0
0x4dd7f7: mov esi,[ecx+4]
0x4dd7fa: jne short 004DD7FFh
0x4dd7fc: mov [edi+4],esi
0x4dd7ff: mov [esi],edi
0x4dd801: mov eax,[ebp+8]
0x4dd804: mov [ecx+8],eax
0x4dd807: mov edx,[ebp+8]
0x4dd80a: mov [edx+4],ecx
0x4dd80d: mov eax,[esp+68h]
0x4dd811: mov eax,[eax+4]
0x4dd814: cmp [eax+4],ebp
0x4dd817: jne short 004DD81Eh
0x4dd819: mov [eax+4],ecx
0x4dd81c: jmp short 004DD82Ch
0x4dd81e: mov eax,[ebp+4]
0x4dd821: cmp [eax],ebp
0x4dd823: jne short 004DD829h
0x4dd825: mov [eax],ecx
0x4dd827: jmp short 004DD82Ch
0x4dd829: mov [eax+8],ecx
0x4dd82c: mov edx,[ebp+4]
0x4dd82f: mov [ecx+4],edx
0x4dd832: mov dl,[ebp+38h]
0x4dd835: mov al,[ecx+38h]
0x4dd838: mov [ecx+38h],dl
0x4dd83b: mov [ebp+38h],al
0x4dd83e: mov bl,1
0x4dd840: cmp [ebp+38h],bl
0x4dd843: jne near ptr 004DD96Ah
0x4dd849: mov eax,[esp+68h]
0x4dd84d: mov ecx,[eax+4]
0x4dd850: cmp edi,[ecx+4]
0x4dd853: je near ptr 004DD967h
0x4dd859: lea esp,[esp]
0x4dd860: cmp [edi+38h],bl
0x4dd863: jne near ptr 004DD967h
0x4dd869: mov ecx,[esi]
0x4dd86b: cmp edi,ecx
0x4dd86d: jne short 004DD8E5h
0x4dd86f: mov ecx,[esi+8]
0x4dd872: cmp byte ptr [ecx+38h],0
0x4dd876: jne short 004DD88Eh
0x4dd878: mov edx,[esp+68h]
0x4dd87c: mov [ecx+38h],bl
0x4dd87f: push edx
0x4dd880: mov ecx,esi
0x4dd882: mov byte ptr [esi+38h],0
0x4dd886: call 005F9650h
0x4dd88b: mov ecx,[esi+8]
0x4dd88e: cmp byte ptr [ecx+39h],0
0x4dd892: jne near ptr 004DD919h
0x4dd898: mov eax,[ecx]
0x4dd89a: cmp [eax+38h],bl
0x4dd89d: jne short 004DD8A7h
0x4dd89f: mov edx,[ecx+8]
0x4dd8a2: cmp [edx+38h],bl
0x4dd8a5: je short 004DD915h
0x4dd8a7: mov eax,[ecx+8]
0x4dd8aa: cmp [eax+38h],bl
0x4dd8ad: jne short 004DD8C5h
0x4dd8af: mov edx,[ecx]
0x4dd8b1: mov eax,[esp+68h]
0x4dd8b5: mov [edx+38h],bl
0x4dd8b8: push eax
0x4dd8b9: mov byte ptr [ecx+38h],0
0x4dd8bd: call 004DD9C0h
0x4dd8c2: mov ecx,[esi+8]
0x4dd8c5: mov dl,[esi+38h]
0x4dd8c8: mov [ecx+38h],dl
0x4dd8cb: mov [esi+38h],bl
0x4dd8ce: mov eax,[ecx+8]
0x4dd8d1: mov ecx,[esp+68h]
0x4dd8d5: push ecx
0x4dd8d6: mov ecx,esi
0x4dd8d8: mov [eax+38h],bl
0x4dd8db: call 005F9650h
0x4dd8e0: jmp near ptr 004DD967h
0x4dd8e5: cmp byte ptr [ecx+38h],0
0x4dd8e9: jne short 004DD900h
0x4dd8eb: mov eax,[esp+68h]
0x4dd8ef: mov [ecx+38h],bl
0x4dd8f2: push eax
0x4dd8f3: mov ecx,esi
0x4dd8f5: mov byte ptr [esi+38h],0
0x4dd8f9: call 004DD9C0h
0x4dd8fe: mov ecx,[esi]
0x4dd900: cmp byte ptr [ecx+39h],0
0x4dd904: jne short 004DD919h
0x4dd906: mov edx,[ecx+8]
0x4dd909: cmp [edx+38h],bl
0x4dd90c: jne short 004DD930h
0x4dd90e: mov eax,[ecx]
0x4dd910: cmp [eax+38h],bl
0x4dd913: jne short 004DD930h
0x4dd915: mov byte ptr [ecx+38h],0
0x4dd919: mov ecx,[esp+68h]
0x4dd91d: mov edx,[ecx+4]
0x4dd920: mov edi,esi
0x4dd922: cmp edi,[edx+4]
0x4dd925: mov esi,[esi+4]
0x4dd928: jne near ptr 004DD860h
0x4dd92e: jmp short 004DD967h
0x4dd930: mov edx,[ecx]
0x4dd932: cmp [edx+38h],bl
0x4dd935: jne short 004DD94Dh
0x4dd937: mov eax,[ecx+8]
0x4dd93a: mov edx,[esp+68h]
0x4dd93e: mov [eax+38h],bl
0x4dd941: push edx
0x4dd942: mov byte ptr [ecx+38h],0
0x4dd946: call 005F9650h
0x4dd94b: mov ecx,[esi]
0x4dd94d: mov al,[esi+38h]
0x4dd950: mov edx,[esp+68h]
0x4dd954: mov [ecx+38h],al
0x4dd957: mov [esi+38h],bl
0x4dd95a: mov ecx,[ecx]
0x4dd95c: mov [ecx+38h],bl
0x4dd95f: push edx
0x4dd960: mov ecx,esi
0x4dd962: call 004DD9C0h
0x4dd967: mov [edi+38h],bl
0x4dd96a: lea eax,[ebp+0Ch]
0x4dd96d: push eax
0x4dd96e: call 004DCF90h
0x4dd973: push ebp
0x4dd974: call 006516BAh
0x4dd979: mov ecx,[esp+6Ch]
0x4dd97d: mov eax,[ecx+8]
0x4dd980: add esp,4
0x4dd983: test eax,eax
0x4dd985: jbe short 004DD98Dh
0x4dd987: add eax,0FFFFFFFFh
0x4dd98a: mov [ecx+8],eax
0x4dd98d: mov eax,[esp+6Ch]
0x4dd991: mov ecx,[esp+70h]
0x4dd995: mov edx,[esp+74h]
0x4dd999: mov [eax],ecx
0x4dd99b: mov [eax+4],edx
0x4dd99e: mov ecx,[esp+58h]
0x4dd9a2: mov fs:[0],ecx
0x4dd9a9: pop ecx
0x4dd9aa: pop edi
0x4dd9ab: pop esi
0x4dd9ac: pop ebp
0x4dd9ad: pop ebx
0x4dd9ae: add esp,50h
0x4dd9b1: ret 10h
````

`sub_4dd6d0` is called by sub_4dd400. It delegates to sub_401230, sub_458540, sub_4dcf90 (8 callees).

### sub_4dd9c0 at 0x4dd9c0 (28 instructions)

````text
0x4dd9c0: mov eax,[ecx]
0x4dd9c2: mov edx,[eax+8]
0x4dd9c5: mov [ecx],edx
0x4dd9c7: mov edx,[eax+8]
0x4dd9ca: cmp byte ptr [edx+39h],0
0x4dd9ce: jne short 004DD9D3h
0x4dd9d0: mov [edx+4],ecx
0x4dd9d3: mov edx,[ecx+4]
0x4dd9d6: mov [eax+4],edx
0x4dd9d9: mov edx,[esp+4]
0x4dd9dd: mov edx,[edx+4]
0x4dd9e0: cmp ecx,[edx+4]
0x4dd9e3: jne short 004DD9F1h
0x4dd9e5: mov [edx+4],eax
0x4dd9e8: mov [eax+8],ecx
0x4dd9eb: mov [ecx+4],eax
0x4dd9ee: ret 4
0x4dd9f1: mov edx,[ecx+4]
0x4dd9f4: cmp ecx,[edx+8]
0x4dd9f7: jne short 004DDA05h
0x4dd9f9: mov [edx+8],eax
0x4dd9fc: mov [eax+8],ecx
0x4dd9ff: mov [ecx+4],eax
0x4dda02: ret 4
0x4dda05: mov [edx],eax
0x4dda07: mov [eax+8],ecx
0x4dda0a: mov [ecx+4],eax
0x4dda0d: ret 4
````

`sub_4dd9c0` is called by sub_4dd6d0, sub_506d20, sub_5e3ee0, sub_5e42e0, sub_5e6990, sub_5ef4e0, sub_5f9360, sub_6229f0, sub_633610. It calls nothing else.

### sub_4ddaa0 at 0x4ddaa0 (26 instructions)

````text
0x4ddaa0: push ebx
0x4ddaa1: push esi
0x4ddaa2: push edi
0x4ddaa3: mov edi,[esp+10h]
0x4ddaa7: cmp byte ptr [edi+39h],0
0x4ddaab: mov ebx,ecx
0x4ddaad: mov esi,edi
0x4ddaaf: jne short 004DDAD8h
0x4ddab1: mov eax,[esi+8]
0x4ddab4: push eax
0x4ddab5: mov ecx,ebx
0x4ddab7: call 004DDAA0h
0x4ddabc: mov esi,[esi]
0x4ddabe: lea ecx,[edi+0Ch]
0x4ddac1: push ecx
0x4ddac2: call 004DCF90h
0x4ddac7: push edi
0x4ddac8: call 006516BAh
0x4ddacd: add esp,4
0x4ddad0: cmp byte ptr [esi+39h],0
0x4ddad4: mov edi,esi
0x4ddad6: je short 004DDAB1h
0x4ddad8: pop edi
0x4ddad9: pop esi
0x4ddada: pop ebx
0x4ddadb: ret 4
````

`sub_4ddaa0` is called by sub_4dd400, sub_4ddaa0. It delegates to sub_4dcf90, sub_4ddaa0, j_ORDINAL 764 (3 callees).

### sub_4ddb30 at 0x4ddb30 (23 instructions)

````text
0x4ddb30: push 0FFFFFFFFh
0x4ddb32: push 74CA09h
0x4ddb37: mov eax,fs:[0]
0x4ddb3d: push eax
0x4ddb3e: push esi
0x4ddb3f: mov eax,ds:[858220h]
0x4ddb44: xor eax,esp
0x4ddb46: push eax
0x4ddb47: lea eax,[esp+8]
0x4ddb4b: mov fs:[0],eax
0x4ddb51: mov esi,[esp+18h]
0x4ddb55: lea eax,[esi+0Ch]
0x4ddb58: mov dword ptr [esp+10h],0
0x4ddb60: call 004664C0h
0x4ddb65: mov ecx,esi
0x4ddb67: mov dword ptr [esp+10h],0FFFFFFFFh
0x4ddb6f: call dword ptr ds:[77DF7Ch]
0x4ddb75: mov ecx,[esp+8]
0x4ddb79: mov fs:[0],ecx
0x4ddb80: pop ecx
0x4ddb81: pop esi
0x4ddb82: add esp,0Ch
0x4ddb85: ret 4
````

`sub_4ddb30` is called by sub_4dde10. It delegates to sub_4664c0 (1 callees).

### sub_4ddd40 at 0x4ddd40 (52 instructions)

````text
0x4ddd40: push 0FFFFFFFFh
0x4ddd42: push 7518A7h
0x4ddd47: mov eax,fs:[0]
0x4ddd4d: push eax
0x4ddd4e: push ebx
0x4ddd4f: push ebp
0x4ddd50: push esi
0x4ddd51: push edi
0x4ddd52: mov eax,ds:[858220h]
0x4ddd57: xor eax,esp
0x4ddd59: push eax
0x4ddd5a: lea eax,[esp+14h]
0x4ddd5e: mov fs:[0],eax
0x4ddd64: mov esi,[esp+24h]
0x4ddd68: mov ebp,ds:[77DF80h]
0x4ddd6e: lea ecx,[esi+4]
0x4ddd71: mov dword ptr [esi],7DC278h
0x4ddd77: call ebp
0x4ddd79: mov eax,[esp+28h]
0x4ddd7d: xor ebx,ebx
0x4ddd7f: mov [esp+1Ch],ebx
0x4ddd83: mov [esi+0Ch],eax
0x4ddd86: call 004B53B0h
0x4ddd8b: mov [esi+14h],eax
0x4ddd8e: mov cl,1
0x4ddd90: mov [eax+11h],cl
0x4ddd93: mov eax,[esi+14h]
0x4ddd96: mov [eax+4],eax
0x4ddd99: mov eax,[esi+14h]
0x4ddd9c: mov [eax],eax
0x4ddd9e: mov eax,[esi+14h]
0x4ddda1: mov [eax+8],eax
0x4ddda4: mov [esi+18h],ebx
0x4ddda7: mov [esp+1Ch],cl
0x4dddab: lea edi,[esi+1Ch]
0x4dddae: mov ecx,edi
0x4dddb0: call ebp
0x4dddb2: mov dword ptr [edi+8],186A0h
0x4dddb9: mov [edi+10h],ebx
0x4dddbc: mov [edi+14h],ebx
0x4dddbf: mov [edi+18h],ebx
0x4dddc2: mov [edi+1Ch],ebx
0x4dddc5: mov eax,esi
0x4dddc7: mov ecx,[esp+14h]
0x4dddcb: mov fs:[0],ecx
0x4dddd2: pop ecx
0x4dddd3: pop edi
0x4dddd4: pop esi
0x4dddd5: pop ebp
0x4dddd6: pop ebx
0x4dddd7: add esp,0Ch
0x4dddda: ret 8
````

`sub_4ddd40` is called by sub_5859c0, sub_5d7560, sub_5ea5d0. It delegates to sub_4b53b0 (1 callees).

### sub_4dde10 at 0x4dde10 (30 instructions)

````text
0x4dde10: push 0FFFFFFFFh
0x4dde12: push 751867h
0x4dde17: mov eax,fs:[0]
0x4dde1d: push eax
0x4dde1e: sub esp,8
0x4dde21: push esi
0x4dde22: mov eax,ds:[858220h]
0x4dde27: xor eax,esp
0x4dde29: push eax
0x4dde2a: lea eax,[esp+10h]
0x4dde2e: mov fs:[0],eax
0x4dde34: mov esi,ecx
0x4dde36: mov [esp+0Ch],esi
0x4dde3a: mov dword ptr [esi],7DC278h
0x4dde40: lea eax,[esi+1Ch]
0x4dde43: push eax
0x4dde44: mov dword ptr [esp+1Ch],1
0x4dde4c: call 004DDB30h
0x4dde51: lea eax,[esi+10h]
0x4dde54: mov byte ptr [esp+18h],0
0x4dde59: call 0060AC80h
0x4dde5e: lea ecx,[esi+4]
0x4dde61: mov dword ptr [esp+18h],0FFFFFFFFh
0x4dde69: call dword ptr ds:[77DF7Ch]
0x4dde6f: mov ecx,[esp+10h]
0x4dde73: mov fs:[0],ecx
0x4dde7a: pop ecx
0x4dde7b: pop esi
0x4dde7c: add esp,14h
0x4dde7f: ret
````

`sub_4dde10` is called by sub_585a40, sub_5ea9c0, sub_77b400, sub_77b420. It delegates to sub_4ddb30, sub_60ac80 (2 callees).

### sub_4de470 at 0x4de470 (9 instructions)

````text
0x4de470: mov ecx,[eax+8]
0x4de473: cmp byte ptr [ecx+11h],0
0x4de477: jne short 004DE48Bh
0x4de479: lea esp,[esp]
0x4de480: mov eax,ecx
0x4de482: mov ecx,[eax+8]
0x4de485: cmp byte ptr [ecx+11h],0
0x4de489: je short 004DE480h
0x4de48b: ret
````

`sub_4de470` is called by sub_4b5020, sub_60b1c0. It calls nothing else.

### sub_4de490 at 0x4de490 (28 instructions)

````text
0x4de490: mov eax,[ecx]
0x4de492: mov edx,[eax+8]
0x4de495: mov [ecx],edx
0x4de497: mov edx,[eax+8]
0x4de49a: cmp byte ptr [edx+11h],0
0x4de49e: jne short 004DE4A3h
0x4de4a0: mov [edx+4],ecx
0x4de4a3: mov edx,[ecx+4]
0x4de4a6: mov [eax+4],edx
0x4de4a9: mov edx,[esp+4]
0x4de4ad: mov edx,[edx+4]
0x4de4b0: cmp ecx,[edx+4]
0x4de4b3: jne short 004DE4C1h
0x4de4b5: mov [edx+4],eax
0x4de4b8: mov [eax+8],ecx
0x4de4bb: mov [ecx+4],eax
0x4de4be: ret 4
0x4de4c1: mov edx,[ecx+4]
0x4de4c4: cmp ecx,[edx+8]
0x4de4c7: jne short 004DE4D5h
0x4de4c9: mov [edx+8],eax
0x4de4cc: mov [eax+8],ecx
0x4de4cf: mov [ecx+4],eax
0x4de4d2: ret 4
0x4de4d5: mov [edx],eax
0x4de4d7: mov [eax+8],ecx
0x4de4da: mov [ecx+4],eax
0x4de4dd: ret 4
````

`sub_4de490` is called by sub_4b5020, sub_60b1c0. It calls nothing else.

### sub_4de690 at 0x4de690 (27 instructions)

````text
0x4de690: push 0FFFFFFFFh
0x4de692: push 73C439h
0x4de697: mov eax,fs:[0]
0x4de69d: push eax
0x4de69e: push esi
0x4de69f: mov eax,ds:[858220h]
0x4de6a4: xor eax,esp
0x4de6a6: push eax
0x4de6a7: lea eax,[esp+8]
0x4de6ab: mov fs:[0],eax
0x4de6b1: mov esi,[esp+18h]
0x4de6b5: mov eax,[esp+1Ch]
0x4de6b9: push eax
0x4de6ba: mov ecx,esi
0x4de6bc: call dword ptr ds:[77CD78h]
0x4de6c2: mov ecx,[esp+20h]
0x4de6c6: push ecx
0x4de6c7: lea ecx,[esi+1Ch]
0x4de6ca: mov dword ptr [esp+14h],0
0x4de6d2: call dword ptr ds:[77CD78h]
0x4de6d8: mov eax,esi
0x4de6da: mov ecx,[esp+8]
0x4de6de: mov fs:[0],ecx
0x4de6e5: pop ecx
0x4de6e6: pop esi
0x4de6e7: add esp,0Ch
0x4de6ea: ret 0Ch
````

`sub_4de690` is called by sub_60ed90. It calls nothing else.

### sub_4dee70 at 0x4dee70 (23 instructions)

````text
0x4dee70: push 0FFFFFFFFh
0x4dee72: push 73C439h
0x4dee77: mov eax,fs:[0]
0x4dee7d: push eax
0x4dee7e: push esi
0x4dee7f: mov eax,ds:[858220h]
0x4dee84: xor eax,esp
0x4dee86: push eax
0x4dee87: lea eax,[esp+8]
0x4dee8b: mov fs:[0],eax
0x4dee91: mov esi,[esp+18h]
0x4dee95: lea ecx,[esi+1Ch]
0x4dee98: mov dword ptr [esp+10h],0
0x4deea0: call dword ptr ds:[77CD74h]
0x4deea6: mov ecx,esi
0x4deea8: mov dword ptr [esp+10h],0FFFFFFFFh
0x4deeb0: call dword ptr ds:[77CD74h]
0x4deeb6: mov ecx,[esp+8]
0x4deeba: mov fs:[0],ecx
0x4deec1: pop ecx
0x4deec2: pop esi
0x4deec3: add esp,0Ch
0x4deec6: ret 4
````

`sub_4dee70` is called by sub_610c30. It calls nothing else.

### sub_4e96c0 at 0x4e96c0 (30 instructions)

````text
0x4e96c0: push 0FFFFFFFFh
0x4e96c2: push 73C439h
0x4e96c7: mov eax,fs:[0]
0x4e96cd: push eax
0x4e96ce: push esi
0x4e96cf: mov eax,ds:[858220h]
0x4e96d4: xor eax,esp
0x4e96d6: push eax
0x4e96d7: lea eax,[esp+8]
0x4e96db: mov fs:[0],eax
0x4e96e1: mov esi,[esp+18h]
0x4e96e5: cmp esi,edi
0x4e96e7: je short 004E971Ch
0x4e96e9: lea esp,[esp]
0x4e96f0: lea ecx,[esi+1Ch]
0x4e96f3: mov dword ptr [esp+10h],0
0x4e96fb: call dword ptr ds:[77CD74h]
0x4e9701: mov ecx,esi
0x4e9703: mov dword ptr [esp+10h],0FFFFFFFFh
0x4e970b: call dword ptr ds:[77CD74h]
0x4e9711: add esi,38h
0x4e9714: cmp esi,edi
0x4e9716: mov [esp+18h],esi
0x4e971a: jne short 004E96F0h
0x4e971c: mov ecx,[esp+8]
0x4e9720: mov fs:[0],ecx
0x4e9727: pop ecx
0x4e9728: pop esi
0x4e9729: add esp,0Ch
0x4e972c: ret
````

`sub_4e96c0` is called by sub_62bc80. It calls nothing else.

### sub_4ef1a0 at 0x4ef1a0 (23 instructions)

````text
0x4ef1a0: push esi
0x4ef1a1: mov esi,[ebx+4]
0x4ef1a4: test esi,esi
0x4ef1a6: je short 004EF1CAh
0x4ef1a8: push edi
0x4ef1a9: mov edi,[ebx+8]
0x4ef1ac: cmp esi,edi
0x4ef1ae: je short 004EF1BDh
0x4ef1b0: push esi
0x4ef1b1: call 0044C770h
0x4ef1b6: add esi,5Ch
0x4ef1b9: cmp esi,edi
0x4ef1bb: jne short 004EF1B0h
0x4ef1bd: mov eax,[ebx+4]
0x4ef1c0: push eax
0x4ef1c1: call 006516BAh
0x4ef1c6: add esp,4
0x4ef1c9: pop edi
0x4ef1ca: mov dword ptr [ebx+4],0
0x4ef1d1: mov dword ptr [ebx+8],0
0x4ef1d8: mov dword ptr [ebx+0Ch],0
0x4ef1df: pop esi
0x4ef1e0: ret
````

`sub_4ef1a0` is called by sub_6287e0. It delegates to sub_44c770, j_ORDINAL 764 (2 callees).

### sub_4fa340 at 0x4fa340 (24 instructions)

````text
0x4fa340: or eax,0FFFFFFFFh
0x4fa343: xor edx,edx
0x4fa345: div ecx
0x4fa347: sub esp,10h
0x4fa34a: cmp eax,14h
0x4fa34d: jae short 004FA37Ch
0x4fa34f: lea eax,[esp]
0x4fa352: push eax
0x4fa353: lea ecx,[esp+8]
0x4fa357: mov dword ptr [esp+4],0
0x4fa35f: call dword ptr ds:[77D0DCh]
0x4fa365: push 80A2ACh
0x4fa36a: lea ecx,[esp+8]
0x4fa36e: push ecx
0x4fa36f: mov dword ptr [esp+0Ch],78FFD4h
0x4fa377: call 00652AC4h
0x4fa37c: lea edx,[ecx+ecx*4]
0x4fa37f: add edx,edx
0x4fa381: add edx,edx
0x4fa383: push edx
0x4fa384: call 006516C0h
0x4fa389: add esp,4
0x4fa38c: add esp,10h
0x4fa38f: ret
````

`sub_4fa340` is called by sub_4b53b0. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_4ff900 at 0x4ff900 (15 instructions)

````text
0x4ff900: sub eax,edx
0x4ff902: sar eax,2
0x4ff905: lea eax,[eax*4]
0x4ff90c: push esi
0x4ff90d: lea esi,[eax+ecx]
0x4ff910: je short 004FF91Fh
0x4ff912: push eax
0x4ff913: push edx
0x4ff914: push eax
0x4ff915: push ecx
0x4ff916: call dword ptr ds:[77D0C0h]
0x4ff91c: add esp,10h
0x4ff91f: mov eax,esi
0x4ff921: pop esi
0x4ff922: ret
````

`sub_4ff900` is called by sub_425810. It calls nothing else.

### sub_506440 at 0x506440 (15 instructions)

````text
0x506440: test esi,esi
0x506442: mov eax,esi
0x506444: mov ecx,edi
0x506446: jbe short 0050645Fh
0x506448: push ebx
0x506449: lea esp,[esp]
0x506450: mov ebx,[edx]
0x506452: mov [ecx],ebx
0x506454: sub eax,1
0x506457: add ecx,4
0x50645a: test eax,eax
0x50645c: ja short 00506450h
0x50645e: pop ebx
0x50645f: lea eax,[edi+esi*4]
0x506462: ret
````

`sub_506440` is called by sub_425810. It calls nothing else.

### sub_5064e0 at 0x5064e0 (26 instructions)

````text
0x5064e0: push ebp
0x5064e1: mov ebp,esp
0x5064e3: and esp,0FFFFFFF8h
0x5064e6: sub esp,0Ch
0x5064e9: push edi
0x5064ea: mov edi,eax
0x5064ec: mov eax,[edi+4]
0x5064ef: mov ecx,[eax]
0x5064f1: push eax
0x5064f2: push edi
0x5064f3: push ecx
0x5064f4: push edi
0x5064f5: lea eax,[esp+18h]
0x5064f9: push eax
0x5064fa: call 00506680h
0x5064ff: mov ecx,[edi+4]
0x506502: push ecx
0x506503: call 006516BAh
0x506508: add esp,4
0x50650b: xor eax,eax
0x50650d: mov [edi+4],eax
0x506510: mov [edi+8],eax
0x506513: pop edi
0x506514: mov esp,ebp
0x506516: pop ebp
0x506517: ret
````

`sub_5064e0` is called by sub_619ee0. It delegates to sub_506680, j_ORDINAL 764 (2 callees).

### sub_506590 at 0x506590 (26 instructions)

````text
0x506590: push ebp
0x506591: mov ebp,esp
0x506593: and esp,0FFFFFFF8h
0x506596: sub esp,0Ch
0x506599: push edi
0x50659a: mov edi,eax
0x50659c: mov eax,[edi+4]
0x50659f: mov ecx,[eax]
0x5065a1: push eax
0x5065a2: push edi
0x5065a3: push ecx
0x5065a4: push edi
0x5065a5: lea eax,[esp+18h]
0x5065a9: push eax
0x5065aa: call 00506820h
0x5065af: mov ecx,[edi+4]
0x5065b2: push ecx
0x5065b3: call 006516BAh
0x5065b8: add esp,4
0x5065bb: xor eax,eax
0x5065bd: mov [edi+4],eax
0x5065c0: mov [edi+8],eax
0x5065c3: pop edi
0x5065c4: mov esp,ebp
0x5065c6: pop ebp
0x5065c7: ret
````

`sub_506590` is called by sub_619ee0. It delegates to sub_506820, j_ORDINAL 764 (2 callees).

### sub_506680 at 0x506680 (72 instructions)

````text
0x506680: mov eax,[edi+4]
0x506683: sub esp,0Ch
0x506686: push ebx
0x506687: mov ebx,[esp+18h]
0x50668b: test ebx,ebx
0x50668d: push ebp
0x50668e: push esi
0x50668f: mov esi,[eax]
0x506691: je short 00506697h
0x506693: cmp ebx,edi
0x506695: je short 0050669Dh
0x506697: call dword ptr ds:[77D0E4h]
0x50669d: mov ebp,[esp+24h]
0x5066a1: cmp ebp,esi
0x5066a3: jne short 00506700h
0x5066a5: mov eax,[esp+28h]
0x5066a9: test eax,eax
0x5066ab: mov esi,[edi+4]
0x5066ae: je short 005066B4h
0x5066b0: cmp eax,edi
0x5066b2: je short 005066BAh
0x5066b4: call dword ptr ds:[77D0E4h]
0x5066ba: cmp [esp+2Ch],esi
0x5066be: jne short 00506700h
0x5066c0: mov ecx,[edi+4]
0x5066c3: mov edx,[ecx+4]
0x5066c6: push edx
0x5066c7: mov ecx,edi
0x5066c9: call 00584ED0h
0x5066ce: mov eax,[edi+4]
0x5066d1: mov [eax+4],eax
0x5066d4: mov eax,[edi+4]
0x5066d7: mov dword ptr [edi+8],0
0x5066de: mov [eax],eax
0x5066e0: mov eax,[edi+4]
0x5066e3: mov [eax+8],eax
0x5066e6: mov eax,[edi+4]
0x5066e9: mov ecx,[eax]
0x5066eb: mov eax,[esp+1Ch]
0x5066ef: mov [eax+4],ecx
0x5066f2: mov [eax],edi
0x5066f4: pop esi
0x5066f5: pop ebp
0x5066f6: pop ebx
0x5066f7: add esp,0Ch
0x5066fa: ret 14h
0x506700: test ebx,ebx
0x506702: je short 0050670Ah
0x506704: cmp ebx,[esp+28h]
0x506708: je short 00506710h
0x50670a: call dword ptr ds:[77D0E4h]
0x506710: cmp ebp,[esp+2Ch]
0x506714: je short 00506736h
0x506716: lea esi,[esp+20h]
0x50671a: call 005853F0h
0x50671f: push ebp
0x506720: push ebx
0x506721: lea edx,[esp+18h]
0x506725: push edx
0x506726: push edi
0x506727: call 005069D0h
0x50672c: mov ebp,[esp+24h]
0x506730: mov ebx,[esp+20h]
0x506734: jmp short 00506700h
0x506736: mov eax,[esp+1Ch]
0x50673a: pop esi
0x50673b: mov [eax+4],ebp
0x50673e: pop ebp
0x50673f: mov [eax],ebx
0x506741: pop ebx
0x506742: add esp,0Ch
0x506745: ret 14h
````

`sub_506680` is called by sub_5064e0. It delegates to sub_5069d0, sub_584ed0, sub_5853f0 (3 callees).

### sub_506800 at 0x506800 (8 instructions)

````text
0x506800: mov ecx,[eax]
0x506802: cmp byte ptr [ecx+19h],0
0x506806: jne short 00506812h
0x506808: mov eax,ecx
0x50680a: mov ecx,[eax]
0x50680c: cmp byte ptr [ecx+19h],0
0x506810: je short 00506808h
0x506812: ret
````

`sub_506800` is called by sub_5069d0. It calls nothing else.

### sub_506820 at 0x506820 (72 instructions)

````text
0x506820: mov eax,[edi+4]
0x506823: sub esp,0Ch
0x506826: push ebx
0x506827: mov ebx,[esp+18h]
0x50682b: test ebx,ebx
0x50682d: push ebp
0x50682e: push esi
0x50682f: mov esi,[eax]
0x506831: je short 00506837h
0x506833: cmp ebx,edi
0x506835: je short 0050683Dh
0x506837: call dword ptr ds:[77D0E4h]
0x50683d: mov ebp,[esp+24h]
0x506841: cmp ebp,esi
0x506843: jne short 005068A0h
0x506845: mov eax,[esp+28h]
0x506849: test eax,eax
0x50684b: mov esi,[edi+4]
0x50684e: je short 00506854h
0x506850: cmp eax,edi
0x506852: je short 0050685Ah
0x506854: call dword ptr ds:[77D0E4h]
0x50685a: cmp [esp+2Ch],esi
0x50685e: jne short 005068A0h
0x506860: mov ecx,[edi+4]
0x506863: mov edx,[ecx+4]
0x506866: push edx
0x506867: mov ecx,edi
0x506869: call 00506FF0h
0x50686e: mov eax,[edi+4]
0x506871: mov [eax+4],eax
0x506874: mov eax,[edi+4]
0x506877: mov dword ptr [edi+8],0
0x50687e: mov [eax],eax
0x506880: mov eax,[edi+4]
0x506883: mov [eax+8],eax
0x506886: mov eax,[edi+4]
0x506889: mov ecx,[eax]
0x50688b: mov eax,[esp+1Ch]
0x50688f: mov [eax+4],ecx
0x506892: mov [eax],edi
0x506894: pop esi
0x506895: pop ebp
0x506896: pop ebx
0x506897: add esp,0Ch
0x50689a: ret 14h
0x5068a0: test ebx,ebx
0x5068a2: je short 005068AAh
0x5068a4: cmp ebx,[esp+28h]
0x5068a8: je short 005068B0h
0x5068aa: call dword ptr ds:[77D0E4h]
0x5068b0: cmp ebp,[esp+2Ch]
0x5068b4: je short 005068D6h
0x5068b6: lea esi,[esp+20h]
0x5068ba: call 00633EE0h
0x5068bf: push ebp
0x5068c0: push ebx
0x5068c1: lea edx,[esp+18h]
0x5068c5: push edx
0x5068c6: push edi
0x5068c7: call 00506D20h
0x5068cc: mov ebp,[esp+24h]
0x5068d0: mov ebx,[esp+20h]
0x5068d4: jmp short 005068A0h
0x5068d6: mov eax,[esp+1Ch]
0x5068da: pop esi
0x5068db: mov [eax+4],ebp
0x5068de: pop ebp
0x5068df: mov [eax],ebx
0x5068e1: pop ebx
0x5068e2: add esp,0Ch
0x5068e5: ret 14h
````

`sub_506820` is called by sub_506590. It delegates to sub_506d20, sub_506ff0, sub_633ee0 (3 callees).

### sub_5069b0 at 0x5069b0 (8 instructions)

````text
0x5069b0: mov ecx,[eax]
0x5069b2: cmp byte ptr [ecx+39h],0
0x5069b6: jne short 005069C2h
0x5069b8: mov eax,ecx
0x5069ba: mov ecx,[eax]
0x5069bc: cmp byte ptr [ecx+39h],0
0x5069c0: je short 005069B8h
0x5069c2: ret
````

`sub_5069b0` is called by sub_506d20. It calls nothing else.

### sub_5069d0 at 0x5069d0 (254 instructions)

````text
0x5069d0: push 0FFFFFFFFh
0x5069d2: push 7410D9h
0x5069d7: mov eax,fs:[0]
0x5069dd: push eax
0x5069de: sub esp,44h
0x5069e1: push ebx
0x5069e2: push ebp
0x5069e3: push esi
0x5069e4: push edi
0x5069e5: mov eax,ds:[858220h]
0x5069ea: xor eax,esp
0x5069ec: push eax
0x5069ed: lea eax,[esp+58h]
0x5069f1: mov fs:[0],eax
0x5069f7: mov eax,[esp+74h]
0x5069fb: cmp byte ptr [eax+19h],0
0x5069ff: je short 00506A3Dh
0x506a01: push 7C5AECh
0x506a06: lea ecx,[esp+18h]
0x506a0a: call dword ptr ds:[77CD7Ch]
0x506a10: lea eax,[esp+14h]
0x506a14: push eax
0x506a15: lea ecx,[esp+34h]
0x506a19: mov dword ptr [esp+64h],0
0x506a21: call 00401230h
0x506a26: push 80A4F8h
0x506a2b: lea ecx,[esp+34h]
0x506a2f: push ecx
0x506a30: mov dword ptr [esp+38h],790F90h
0x506a38: call 00652AC4h
0x506a3d: lea esi,[esp+70h]
0x506a41: mov ebp,eax
0x506a43: call 005853F0h
0x506a48: mov eax,[ebp]
0x506a4b: cmp byte ptr [eax+19h],0
0x506a4f: je short 00506A56h
0x506a51: mov edi,[ebp+8]
0x506a54: jmp short 00506A6Eh
0x506a56: mov edx,[ebp+8]
0x506a59: cmp byte ptr [edx+19h],0
0x506a5d: je short 00506A63h
0x506a5f: mov edi,eax
0x506a61: jmp short 00506A6Eh
0x506a63: mov ecx,[esp+74h]
0x506a67: cmp ecx,ebp
0x506a69: mov edi,[ecx+8]
0x506a6c: jne short 00506AD9h
0x506a6e: cmp byte ptr [edi+19h],0
0x506a72: mov esi,[ebp+4]
0x506a75: jne short 00506A7Ah
0x506a77: mov [edi+4],esi
0x506a7a: mov edx,[esp+68h]
0x506a7e: mov eax,[edx+4]
0x506a81: cmp [eax+4],ebp
0x506a84: jne short 00506A8Bh
0x506a86: mov [eax+4],edi
0x506a89: jmp short 00506A96h
0x506a8b: cmp [esi],ebp
0x506a8d: jne short 00506A93h
0x506a8f: mov [esi],edi
0x506a91: jmp short 00506A96h
0x506a93: mov [esi+8],edi
0x506a96: mov ebx,[edx+4]
0x506a99: cmp [ebx],ebp
0x506a9b: jne short 00506AB4h
0x506a9d: cmp byte ptr [edi+19h],0
0x506aa1: je short 00506AA7h
0x506aa3: mov eax,esi
0x506aa5: jmp short 00506AB2h
0x506aa7: mov eax,edi
0x506aa9: call 00506800h
0x506aae: mov edx,[esp+68h]
0x506ab2: mov [ebx],eax
0x506ab4: mov ebx,[edx+4]
0x506ab7: cmp [ebx+8],ebp
0x506aba: jne short 00506B39h
0x506abc: cmp byte ptr [edi+19h],0
0x506ac0: je short 00506AC9h
0x506ac2: mov eax,esi
0x506ac4: mov [ebx+8],eax
0x506ac7: jmp short 00506B39h
0x506ac9: mov eax,edi
0x506acb: call 00585460h
0x506ad0: mov edx,[esp+68h]
0x506ad4: mov [ebx+8],eax
0x506ad7: jmp short 00506B39h
0x506ad9: mov [eax+4],ecx
0x506adc: mov eax,[ebp]
0x506adf: mov [ecx],eax
0x506ae1: cmp ecx,[ebp+8]
0x506ae4: jne short 00506AEAh
0x506ae6: mov esi,ecx
0x506ae8: jmp short 00506B04h
0x506aea: cmp byte ptr [edi+19h],0
0x506aee: mov esi,[ecx+4]
0x506af1: jne short 00506AF6h
0x506af3: mov [edi+4],esi
0x506af6: mov [esi],edi
0x506af8: mov edx,[ebp+8]
0x506afb: mov [ecx+8],edx
0x506afe: mov eax,[ebp+8]
0x506b01: mov [eax+4],ecx
0x506b04: mov edx,[esp+68h]
0x506b08: mov eax,[edx+4]
0x506b0b: cmp [eax+4],ebp
0x506b0e: jne short 00506B15h
0x506b10: mov [eax+4],ecx
0x506b13: jmp short 00506B23h
0x506b15: mov eax,[ebp+4]
0x506b18: cmp [eax],ebp
0x506b1a: jne short 00506B20h
0x506b1c: mov [eax],ecx
0x506b1e: jmp short 00506B23h
0x506b20: mov [eax+8],ecx
0x506b23: mov eax,[ebp+4]
0x506b26: mov [ecx+4],eax
0x506b29: mov dl,[ebp+18h]
0x506b2c: mov al,[ecx+18h]
0x506b2f: mov [ecx+18h],dl
0x506b32: mov edx,[esp+68h]
0x506b36: mov [ebp+18h],al
0x506b39: mov bl,1
0x506b3b: cmp [ebp+18h],bl
0x506b3e: jne near ptr 00506C47h
0x506b44: mov eax,[edx+4]
0x506b47: cmp edi,[eax+4]
0x506b4a: je near ptr 00506C44h
0x506b50: cmp [edi+18h],bl
0x506b53: jne near ptr 00506C44h
0x506b59: mov ecx,[esi]
0x506b5b: cmp edi,ecx
0x506b5d: jne short 00506BCAh
0x506b5f: mov ecx,[esi+8]
0x506b62: cmp byte ptr [ecx+18h],0
0x506b66: jne short 00506B7Eh
0x506b68: mov [ecx+18h],bl
0x506b6b: push edx
0x506b6c: mov ecx,esi
0x506b6e: mov byte ptr [esi+18h],0
0x506b72: call 005070E0h
0x506b77: mov ecx,[esi+8]
0x506b7a: mov edx,[esp+68h]
0x506b7e: cmp byte ptr [ecx+19h],0
0x506b82: jne short 00506BFEh
0x506b84: mov eax,[ecx]
0x506b86: cmp [eax+18h],bl
0x506b89: jne short 00506B93h
0x506b8b: mov eax,[ecx+8]
0x506b8e: cmp [eax+18h],bl
0x506b91: je short 00506BFAh
0x506b93: mov eax,[ecx+8]
0x506b96: cmp [eax+18h],bl
0x506b99: jne short 00506BB1h
0x506b9b: mov eax,[ecx]
0x506b9d: mov [eax+18h],bl
0x506ba0: push edx
0x506ba1: mov byte ptr [ecx+18h],0
0x506ba5: call 005F0770h
0x506baa: mov ecx,[esi+8]
0x506bad: mov edx,[esp+68h]
0x506bb1: mov al,[esi+18h]
0x506bb4: mov [ecx+18h],al
0x506bb7: mov [esi+18h],bl
0x506bba: mov ecx,[ecx+8]
0x506bbd: mov [ecx+18h],bl
0x506bc0: push edx
0x506bc1: mov ecx,esi
0x506bc3: call 005070E0h
0x506bc8: jmp short 00506C44h
0x506bca: cmp byte ptr [ecx+18h],0
0x506bce: jne short 00506BE5h
0x506bd0: mov [ecx+18h],bl
0x506bd3: push edx
0x506bd4: mov ecx,esi
0x506bd6: mov byte ptr [esi+18h],0
0x506bda: call 005F0770h
0x506bdf: mov ecx,[esi]
0x506be1: mov edx,[esp+68h]
0x506be5: cmp byte ptr [ecx+19h],0
0x506be9: jne short 00506BFEh
0x506beb: mov eax,[ecx+8]
0x506bee: cmp [eax+18h],bl
0x506bf1: jne short 00506C11h
0x506bf3: mov eax,[ecx]
0x506bf5: cmp [eax+18h],bl
0x506bf8: jne short 00506C11h
0x506bfa: mov byte ptr [ecx+18h],0
0x506bfe: mov ecx,[edx+4]
0x506c01: mov edi,esi
0x506c03: cmp edi,[ecx+4]
0x506c06: mov esi,[esi+4]
0x506c09: jne near ptr 00506B50h
0x506c0f: jmp short 00506C44h
0x506c11: mov eax,[ecx]
0x506c13: cmp [eax+18h],bl
0x506c16: jne short 00506C2Eh
0x506c18: mov eax,[ecx+8]
0x506c1b: mov [eax+18h],bl
0x506c1e: push edx
0x506c1f: mov byte ptr [ecx+18h],0
0x506c23: call 005070E0h
0x506c28: mov ecx,[esi]
0x506c2a: mov edx,[esp+68h]
0x506c2e: mov al,[esi+18h]
0x506c31: mov [ecx+18h],al
0x506c34: mov [esi+18h],bl
0x506c37: mov ecx,[ecx]
0x506c39: mov [ecx+18h],bl
0x506c3c: push edx
0x506c3d: mov ecx,esi
0x506c3f: call 005F0770h
0x506c44: mov [edi+18h],bl
0x506c47: mov esi,[ebp+14h]
0x506c4a: test esi,esi
0x506c4c: je short 00506C78h
0x506c4e: lea edx,[esi+4]
0x506c51: or eax,0FFFFFFFFh
0x506c54: lock xadd [edx],eax
0x506c58: jne short 00506C78h
0x506c5a: mov edx,[esi]
0x506c5c: mov eax,[edx+4]
0x506c5f: mov ecx,esi
0x506c61: call eax
0x506c63: lea ecx,[esi+8]
0x506c66: or edx,0FFFFFFFFh
0x506c69: lock xadd [ecx],edx
0x506c6d: jne short 00506C78h
0x506c6f: mov eax,[esi]
0x506c71: mov edx,[eax+8]
0x506c74: mov ecx,esi
0x506c76: call edx
0x506c78: push ebp
0x506c79: call 006516BAh
0x506c7e: mov ecx,[esp+6Ch]
0x506c82: mov eax,[ecx+8]
0x506c85: add esp,4
0x506c88: test eax,eax
0x506c8a: jbe short 00506C92h
0x506c8c: add eax,0FFFFFFFFh
0x506c8f: mov [ecx+8],eax
0x506c92: mov eax,[esp+6Ch]
0x506c96: mov ecx,[esp+70h]
0x506c9a: mov edx,[esp+74h]
0x506c9e: mov [eax],ecx
0x506ca0: mov [eax+4],edx
0x506ca3: mov ecx,[esp+58h]
0x506ca7: mov fs:[0],ecx
0x506cae: pop ecx
0x506caf: pop edi
0x506cb0: pop esi
0x506cb1: pop ebp
0x506cb2: pop ebx
0x506cb3: add esp,50h
0x506cb6: ret 10h
````

`sub_5069d0` is called by sub_506680. It delegates to sub_401230, sub_506800, sub_5070e0 (8 callees).

### sub_506d20 at 0x506d20 (238 instructions)

````text
0x506d20: push 0FFFFFFFFh
0x506d22: push 7410D9h
0x506d27: mov eax,fs:[0]
0x506d2d: push eax
0x506d2e: sub esp,44h
0x506d31: push ebx
0x506d32: push ebp
0x506d33: push esi
0x506d34: push edi
0x506d35: mov eax,ds:[858220h]
0x506d3a: xor eax,esp
0x506d3c: push eax
0x506d3d: lea eax,[esp+58h]
0x506d41: mov fs:[0],eax
0x506d47: mov eax,[esp+74h]
0x506d4b: cmp byte ptr [eax+39h],0
0x506d4f: je short 00506D8Dh
0x506d51: push 7C5AECh
0x506d56: lea ecx,[esp+18h]
0x506d5a: call dword ptr ds:[77CD7Ch]
0x506d60: lea eax,[esp+14h]
0x506d64: push eax
0x506d65: lea ecx,[esp+34h]
0x506d69: mov dword ptr [esp+64h],0
0x506d71: call 00401230h
0x506d76: push 80A4F8h
0x506d7b: lea ecx,[esp+34h]
0x506d7f: push ecx
0x506d80: mov dword ptr [esp+38h],790F90h
0x506d88: call 00652AC4h
0x506d8d: lea esi,[esp+70h]
0x506d91: mov ebp,eax
0x506d93: call 00633EE0h
0x506d98: mov eax,[ebp]
0x506d9b: cmp byte ptr [eax+39h],0
0x506d9f: je short 00506DA6h
0x506da1: mov edi,[ebp+8]
0x506da4: jmp short 00506DBEh
0x506da6: mov edx,[ebp+8]
0x506da9: cmp byte ptr [edx+39h],0
0x506dad: je short 00506DB3h
0x506daf: mov edi,eax
0x506db1: jmp short 00506DBEh
0x506db3: mov ecx,[esp+74h]
0x506db7: cmp ecx,ebp
0x506db9: mov edi,[ecx+8]
0x506dbc: jne short 00506E29h
0x506dbe: cmp byte ptr [edi+39h],0
0x506dc2: mov esi,[ebp+4]
0x506dc5: jne short 00506DCAh
0x506dc7: mov [edi+4],esi
0x506dca: mov edx,[esp+68h]
0x506dce: mov eax,[edx+4]
0x506dd1: cmp [eax+4],ebp
0x506dd4: jne short 00506DDBh
0x506dd6: mov [eax+4],edi
0x506dd9: jmp short 00506DE6h
0x506ddb: cmp [esi],ebp
0x506ddd: jne short 00506DE3h
0x506ddf: mov [esi],edi
0x506de1: jmp short 00506DE6h
0x506de3: mov [esi+8],edi
0x506de6: mov ebx,[edx+4]
0x506de9: cmp [ebx],ebp
0x506deb: jne short 00506E04h
0x506ded: cmp byte ptr [edi+39h],0
0x506df1: je short 00506DF7h
0x506df3: mov eax,esi
0x506df5: jmp short 00506E02h
0x506df7: mov eax,edi
0x506df9: call 005069B0h
0x506dfe: mov edx,[esp+68h]
0x506e02: mov [ebx],eax
0x506e04: mov ebx,[edx+4]
0x506e07: cmp [ebx+8],ebp
0x506e0a: jne short 00506E89h
0x506e0c: cmp byte ptr [edi+39h],0
0x506e10: je short 00506E19h
0x506e12: mov eax,esi
0x506e14: mov [ebx+8],eax
0x506e17: jmp short 00506E89h
0x506e19: mov eax,edi
0x506e1b: call 00458540h
0x506e20: mov edx,[esp+68h]
0x506e24: mov [ebx+8],eax
0x506e27: jmp short 00506E89h
0x506e29: mov [eax+4],ecx
0x506e2c: mov eax,[ebp]
0x506e2f: mov [ecx],eax
0x506e31: cmp ecx,[ebp+8]
0x506e34: jne short 00506E3Ah
0x506e36: mov esi,ecx
0x506e38: jmp short 00506E54h
0x506e3a: cmp byte ptr [edi+39h],0
0x506e3e: mov esi,[ecx+4]
0x506e41: jne short 00506E46h
0x506e43: mov [edi+4],esi
0x506e46: mov [esi],edi
0x506e48: mov edx,[ebp+8]
0x506e4b: mov [ecx+8],edx
0x506e4e: mov eax,[ebp+8]
0x506e51: mov [eax+4],ecx
0x506e54: mov edx,[esp+68h]
0x506e58: mov eax,[edx+4]
0x506e5b: cmp [eax+4],ebp
0x506e5e: jne short 00506E65h
0x506e60: mov [eax+4],ecx
0x506e63: jmp short 00506E73h
0x506e65: mov eax,[ebp+4]
0x506e68: cmp [eax],ebp
0x506e6a: jne short 00506E70h
0x506e6c: mov [eax],ecx
0x506e6e: jmp short 00506E73h
0x506e70: mov [eax+8],ecx
0x506e73: mov eax,[ebp+4]
0x506e76: mov [ecx+4],eax
0x506e79: mov dl,[ebp+38h]
0x506e7c: mov al,[ecx+38h]
0x506e7f: mov [ecx+38h],dl
0x506e82: mov edx,[esp+68h]
0x506e86: mov [ebp+38h],al
0x506e89: mov bl,1
0x506e8b: cmp [ebp+38h],bl
0x506e8e: jne near ptr 00506F97h
0x506e94: mov eax,[edx+4]
0x506e97: cmp edi,[eax+4]
0x506e9a: je near ptr 00506F94h
0x506ea0: cmp [edi+38h],bl
0x506ea3: jne near ptr 00506F94h
0x506ea9: mov ecx,[esi]
0x506eab: cmp edi,ecx
0x506ead: jne short 00506F1Ah
0x506eaf: mov ecx,[esi+8]
0x506eb2: cmp byte ptr [ecx+38h],0
0x506eb6: jne short 00506ECEh
0x506eb8: mov [ecx+38h],bl
0x506ebb: push edx
0x506ebc: mov ecx,esi
0x506ebe: mov byte ptr [esi+38h],0
0x506ec2: call 005F9650h
0x506ec7: mov ecx,[esi+8]
0x506eca: mov edx,[esp+68h]
0x506ece: cmp byte ptr [ecx+39h],0
0x506ed2: jne short 00506F4Eh
0x506ed4: mov eax,[ecx]
0x506ed6: cmp [eax+38h],bl
0x506ed9: jne short 00506EE3h
0x506edb: mov eax,[ecx+8]
0x506ede: cmp [eax+38h],bl
0x506ee1: je short 00506F4Ah
0x506ee3: mov eax,[ecx+8]
0x506ee6: cmp [eax+38h],bl
0x506ee9: jne short 00506F01h
0x506eeb: mov eax,[ecx]
0x506eed: mov [eax+38h],bl
0x506ef0: push edx
0x506ef1: mov byte ptr [ecx+38h],0
0x506ef5: call 004DD9C0h
0x506efa: mov ecx,[esi+8]
0x506efd: mov edx,[esp+68h]
0x506f01: mov al,[esi+38h]
0x506f04: mov [ecx+38h],al
0x506f07: mov [esi+38h],bl
0x506f0a: mov ecx,[ecx+8]
0x506f0d: mov [ecx+38h],bl
0x506f10: push edx
0x506f11: mov ecx,esi
0x506f13: call 005F9650h
0x506f18: jmp short 00506F94h
0x506f1a: cmp byte ptr [ecx+38h],0
0x506f1e: jne short 00506F35h
0x506f20: mov [ecx+38h],bl
0x506f23: push edx
0x506f24: mov ecx,esi
0x506f26: mov byte ptr [esi+38h],0
0x506f2a: call 004DD9C0h
0x506f2f: mov ecx,[esi]
0x506f31: mov edx,[esp+68h]
0x506f35: cmp byte ptr [ecx+39h],0
0x506f39: jne short 00506F4Eh
0x506f3b: mov eax,[ecx+8]
0x506f3e: cmp [eax+38h],bl
0x506f41: jne short 00506F61h
0x506f43: mov eax,[ecx]
0x506f45: cmp [eax+38h],bl
0x506f48: jne short 00506F61h
0x506f4a: mov byte ptr [ecx+38h],0
0x506f4e: mov ecx,[edx+4]
0x506f51: mov edi,esi
0x506f53: cmp edi,[ecx+4]
0x506f56: mov esi,[esi+4]
0x506f59: jne near ptr 00506EA0h
0x506f5f: jmp short 00506F94h
0x506f61: mov eax,[ecx]
0x506f63: cmp [eax+38h],bl
0x506f66: jne short 00506F7Eh
0x506f68: mov eax,[ecx+8]
0x506f6b: mov [eax+38h],bl
0x506f6e: push edx
0x506f6f: mov byte ptr [ecx+38h],0
0x506f73: call 005F9650h
0x506f78: mov ecx,[esi]
0x506f7a: mov edx,[esp+68h]
0x506f7e: mov al,[esi+38h]
0x506f81: mov [ecx+38h],al
0x506f84: mov [esi+38h],bl
0x506f87: mov ecx,[ecx]
0x506f89: mov [ecx+38h],bl
0x506f8c: push edx
0x506f8d: mov ecx,esi
0x506f8f: call 004DD9C0h
0x506f94: mov [edi+38h],bl
0x506f97: lea edx,[ebp+0Ch]
0x506f9a: push edx
0x506f9b: call 005071D0h
0x506fa0: push ebp
0x506fa1: call 006516BAh
0x506fa6: mov ecx,[esp+6Ch]
0x506faa: mov eax,[ecx+8]
0x506fad: add esp,4
0x506fb0: test eax,eax
0x506fb2: jbe short 00506FBAh
0x506fb4: add eax,0FFFFFFFFh
0x506fb7: mov [ecx+8],eax
0x506fba: mov eax,[esp+6Ch]
0x506fbe: mov ecx,[esp+70h]
0x506fc2: mov edx,[esp+74h]
0x506fc6: mov [eax],ecx
0x506fc8: mov [eax+4],edx
0x506fcb: mov ecx,[esp+58h]
0x506fcf: mov fs:[0],ecx
0x506fd6: pop ecx
0x506fd7: pop edi
0x506fd8: pop esi
0x506fd9: pop ebp
0x506fda: pop ebx
0x506fdb: add esp,50h
0x506fde: ret 10h
````

`sub_506d20` is called by sub_506820. It delegates to sub_401230, sub_458540, sub_4dd9c0 (9 callees).

### sub_506ff0 at 0x506ff0 (26 instructions)

````text
0x506ff0: push ebx
0x506ff1: push esi
0x506ff2: push edi
0x506ff3: mov edi,[esp+10h]
0x506ff7: cmp byte ptr [edi+39h],0
0x506ffb: mov ebx,ecx
0x506ffd: mov esi,edi
0x506fff: jne short 00507028h
0x507001: mov eax,[esi+8]
0x507004: push eax
0x507005: mov ecx,ebx
0x507007: call 00506FF0h
0x50700c: mov esi,[esi]
0x50700e: lea ecx,[edi+0Ch]
0x507011: push ecx
0x507012: call 005071D0h
0x507017: push edi
0x507018: call 006516BAh
0x50701d: add esp,4
0x507020: cmp byte ptr [esi+39h],0
0x507024: mov edi,esi
0x507026: je short 00507001h
0x507028: pop edi
0x507029: pop esi
0x50702a: pop ebx
0x50702b: ret 4
````

`sub_506ff0` is called by sub_506820, sub_506ff0. It delegates to sub_506ff0, sub_5071d0, j_ORDINAL 764 (3 callees).

### sub_5070e0 at 0x5070e0 (28 instructions)

````text
0x5070e0: mov eax,[ecx+8]
0x5070e3: mov edx,[eax]
0x5070e5: mov [ecx+8],edx
0x5070e8: mov edx,[eax]
0x5070ea: cmp byte ptr [edx+19h],0
0x5070ee: jne short 005070F3h
0x5070f0: mov [edx+4],ecx
0x5070f3: mov edx,[ecx+4]
0x5070f6: mov [eax+4],edx
0x5070f9: mov edx,[esp+4]
0x5070fd: mov edx,[edx+4]
0x507100: cmp ecx,[edx+4]
0x507103: jne short 00507110h
0x507105: mov [edx+4],eax
0x507108: mov [eax],ecx
0x50710a: mov [ecx+4],eax
0x50710d: ret 4
0x507110: mov edx,[ecx+4]
0x507113: cmp ecx,[edx]
0x507115: jne short 00507121h
0x507117: mov [edx],eax
0x507119: mov [eax],ecx
0x50711b: mov [ecx+4],eax
0x50711e: ret 4
0x507121: mov [edx+8],eax
0x507124: mov [eax],ecx
0x507126: mov [ecx+4],eax
0x507129: ret 4
````

`sub_5070e0` is called by sub_5069d0, sub_584970, sub_5f08a0. It calls nothing else.

### sub_5071d0 at 0x5071d0 (41 instructions)

````text
0x5071d0: push 0FFFFFFFFh
0x5071d2: push 73BEE9h
0x5071d7: mov eax,fs:[0]
0x5071dd: push eax
0x5071de: push ebx
0x5071df: push esi
0x5071e0: push edi
0x5071e1: mov eax,ds:[858220h]
0x5071e6: xor eax,esp
0x5071e8: push eax
0x5071e9: lea eax,[esp+10h]
0x5071ed: mov fs:[0],eax
0x5071f3: mov esi,[esp+20h]
0x5071f7: xor ebx,ebx
0x5071f9: mov [esp+18h],ebx
0x5071fd: mov eax,[esi+20h]
0x507200: cmp eax,ebx
0x507202: je short 0050721Eh
0x507204: mov ecx,[esp+20h]
0x507208: mov edi,[esi+24h]
0x50720b: push ecx
0x50720c: push eax
0x50720d: call 00507680h
0x507212: mov eax,[esi+20h]
0x507215: push eax
0x507216: call 006516BAh
0x50721b: add esp,0Ch
0x50721e: mov ecx,esi
0x507220: mov [esi+20h],ebx
0x507223: mov [esi+24h],ebx
0x507226: mov [esi+28h],ebx
0x507229: mov dword ptr [esp+18h],0FFFFFFFFh
0x507231: call dword ptr ds:[77CD74h]
0x507237: mov ecx,[esp+10h]
0x50723b: mov fs:[0],ecx
0x507242: pop ecx
0x507243: pop edi
0x507244: pop esi
0x507245: pop ebx
0x507246: add esp,0Ch
0x507249: ret 4
````

`sub_5071d0` is called by sub_506d20, sub_506ff0. It delegates to sub_507680, j_ORDINAL 764 (2 callees).

### sub_507680 at 0x507680 (30 instructions)

````text
0x507680: push 0FFFFFFFFh
0x507682: push 73931Ch
0x507687: mov eax,fs:[0]
0x50768d: push eax
0x50768e: push esi
0x50768f: mov eax,ds:[858220h]
0x507694: xor eax,esp
0x507696: push eax
0x507697: lea eax,[esp+8]
0x50769b: mov fs:[0],eax
0x5076a1: mov esi,[esp+18h]
0x5076a5: cmp esi,edi
0x5076a7: je short 005076DDh
0x5076a9: lea esp,[esp]
0x5076b0: lea ecx,[esi+20h]
0x5076b3: mov dword ptr [esp+10h],0
0x5076bb: call dword ptr ds:[77CD74h]
0x5076c1: lea ecx,[esi+4]
0x5076c4: mov dword ptr [esp+10h],0FFFFFFFFh
0x5076cc: call dword ptr ds:[77CD74h]
0x5076d2: add esi,44h
0x5076d5: cmp esi,edi
0x5076d7: mov [esp+18h],esi
0x5076db: jne short 005076B0h
0x5076dd: mov ecx,[esp+8]
0x5076e1: mov fs:[0],ecx
0x5076e8: pop ecx
0x5076e9: pop esi
0x5076ea: add esp,0Ch
0x5076ed: ret
````

`sub_507680` is called by sub_5071d0. It calls nothing else.

### sub_50f8b0 at 0x50f8b0 (28 instructions)

````text
0x50f8b0: mov eax,[ecx]
0x50f8b2: mov edx,[eax+8]
0x50f8b5: mov [ecx],edx
0x50f8b7: mov edx,[eax+8]
0x50f8ba: cmp byte ptr [edx+21h],0
0x50f8be: jne short 0050F8C3h
0x50f8c0: mov [edx+4],ecx
0x50f8c3: mov edx,[ecx+4]
0x50f8c6: mov [eax+4],edx
0x50f8c9: mov edx,[esp+4]
0x50f8cd: mov edx,[edx+4]
0x50f8d0: cmp ecx,[edx+4]
0x50f8d3: jne short 0050F8E1h
0x50f8d5: mov [edx+4],eax
0x50f8d8: mov [eax+8],ecx
0x50f8db: mov [ecx+4],eax
0x50f8de: ret 4
0x50f8e1: mov edx,[ecx+4]
0x50f8e4: cmp ecx,[edx+8]
0x50f8e7: jne short 0050F8F5h
0x50f8e9: mov [edx+8],eax
0x50f8ec: mov [eax+8],ecx
0x50f8ef: mov [ecx+4],eax
0x50f8f2: ret 4
0x50f8f5: mov [edx],eax
0x50f8f7: mov [eax+8],ecx
0x50f8fa: mov [ecx+4],eax
0x50f8fd: ret 4
````

`sub_50f8b0` is called by sub_5b0180, sub_627940. It calls nothing else.

### sub_50fcb0 at 0x50fcb0 (16 instructions)

````text
0x50fcb0: mov ecx,1
0x50fcb5: call 00591FD0h
0x50fcba: test eax,eax
0x50fcbc: je short 0050FCC4h
0x50fcbe: mov dword ptr [eax],0
0x50fcc4: lea ecx,[eax+4]
0x50fcc7: test ecx,ecx
0x50fcc9: je short 0050FCD1h
0x50fccb: mov dword ptr [ecx],0
0x50fcd1: lea ecx,[eax+8]
0x50fcd4: test ecx,ecx
0x50fcd6: je short 0050FCDEh
0x50fcd8: mov dword ptr [ecx],0
0x50fcde: mov byte ptr [eax+20h],1
0x50fce2: mov byte ptr [eax+21h],0
0x50fce6: ret
````

`sub_50fcb0` is called by sub_609e80, sub_624350. It delegates to sub_591fd0 (1 callees).

### sub_52c150 at 0x52c150 (29 instructions)

````text
0x52c150: push ebp
0x52c151: mov ebp,esp
0x52c153: and esp,0FFFFFFF8h
0x52c156: sub esp,0Ch
0x52c159: push ebx
0x52c15a: mov ebx,eax
0x52c15c: push esi
0x52c15d: mov esi,[ebx+8]
0x52c160: cmp [ebx+4],esi
0x52c163: push edi
0x52c164: jbe short 0052C16Ch
0x52c166: call dword ptr ds:[77D0E4h]
0x52c16c: mov edi,[ebx+4]
0x52c16f: cmp edi,[ebx+8]
0x52c172: jbe short 0052C17Ah
0x52c174: call dword ptr ds:[77D0E4h]
0x52c17a: push esi
0x52c17b: push ebx
0x52c17c: push edi
0x52c17d: push ebx
0x52c17e: lea eax,[esp+20h]
0x52c182: push eax
0x52c183: call 0041FB70h
0x52c188: pop edi
0x52c189: pop esi
0x52c18a: pop ebx
0x52c18b: mov esp,ebp
0x52c18d: pop ebp
0x52c18e: ret
````

`sub_52c150` is called by sub_4dc5a0. It delegates to sub_41fb70 (1 callees).

### sub_5484d0 at 0x5484d0 (28 instructions)

````text
0x5484d0: mov eax,[ecx+8]
0x5484d3: mov edx,[eax]
0x5484d5: mov [ecx+8],edx
0x5484d8: mov edx,[eax]
0x5484da: cmp byte ptr [edx+21h],0
0x5484de: jne short 005484E3h
0x5484e0: mov [edx+4],ecx
0x5484e3: mov edx,[ecx+4]
0x5484e6: mov [eax+4],edx
0x5484e9: mov edx,[esp+4]
0x5484ed: mov edx,[edx+4]
0x5484f0: cmp ecx,[edx+4]
0x5484f3: jne short 00548500h
0x5484f5: mov [edx+4],eax
0x5484f8: mov [eax],ecx
0x5484fa: mov [ecx+4],eax
0x5484fd: ret 4
0x548500: mov edx,[ecx+4]
0x548503: cmp ecx,[edx]
0x548505: jne short 00548511h
0x548507: mov [edx],eax
0x548509: mov [eax],ecx
0x54850b: mov [ecx+4],eax
0x54850e: ret 4
0x548511: mov [edx+8],eax
0x548514: mov [eax],ecx
0x548516: mov [ecx+4],eax
0x548519: ret 4
````

`sub_5484d0` is called by sub_5b0180, sub_627940. It calls nothing else.

### sub_573040 at 0x573040 (252 instructions)

````text
0x573040: push ebp
0x573041: mov ebp,esp
0x573043: and esp,0FFFFFFF8h
0x573046: push 0FFFFFFFFh
0x573048: push 73EDF9h
0x57304d: mov eax,fs:[0]
0x573053: push eax
0x573054: sub esp,50h
0x573057: push ebx
0x573058: push esi
0x573059: push edi
0x57305a: mov eax,ds:[858220h]
0x57305f: xor eax,esp
0x573061: push eax
0x573062: lea eax,[esp+60h]
0x573066: mov fs:[0],eax
0x57306c: mov eax,[ebp+14h]
0x57306f: cmp byte ptr [eax+2Dh],0
0x573073: je short 005730B1h
0x573075: push 7C5AECh
0x57307a: lea ecx,[esp+1Ch]
0x57307e: call dword ptr ds:[77CD7Ch]
0x573084: lea eax,[esp+18h]
0x573088: push eax
0x573089: lea ecx,[esp+38h]
0x57308d: mov dword ptr [esp+6Ch],0
0x573095: call 00401230h
0x57309a: push 80A4F8h
0x57309f: lea ecx,[esp+38h]
0x5730a3: push ecx
0x5730a4: mov dword ptr [esp+3Ch],790F90h
0x5730ac: call 00652AC4h
0x5730b1: mov ebx,eax
0x5730b3: lea esi,[ebp+10h]
0x5730b6: mov [esp+10h],ebx
0x5730ba: call 0043A360h
0x5730bf: mov eax,[ebx]
0x5730c1: cmp byte ptr [eax+2Dh],0
0x5730c5: je short 005730CCh
0x5730c7: mov edi,[ebx+8]
0x5730ca: jmp short 005730E3h
0x5730cc: mov edx,[ebx+8]
0x5730cf: cmp byte ptr [edx+2Dh],0
0x5730d3: je short 005730D9h
0x5730d5: mov edi,eax
0x5730d7: jmp short 005730E3h
0x5730d9: mov ecx,[ebp+14h]
0x5730dc: cmp ecx,ebx
0x5730de: mov edi,[ecx+8]
0x5730e1: jne short 00573160h
0x5730e3: cmp byte ptr [edi+2Dh],0
0x5730e7: mov esi,[ebx+4]
0x5730ea: jne short 005730EFh
0x5730ec: mov [edi+4],esi
0x5730ef: mov edx,[ebp+8]
0x5730f2: mov eax,[edx+4]
0x5730f5: cmp [eax+4],ebx
0x5730f8: jne short 005730FFh
0x5730fa: mov [eax+4],edi
0x5730fd: jmp short 0057310Ah
0x5730ff: cmp [esi],ebx
0x573101: jne short 00573107h
0x573103: mov [esi],edi
0x573105: jmp short 0057310Ah
0x573107: mov [esi+8],edi
0x57310a: mov eax,[edx+4]
0x57310d: cmp [eax],ebx
0x57310f: jne short 00573134h
0x573111: cmp byte ptr [edi+2Dh],0
0x573115: je short 0057311Bh
0x573117: mov ecx,esi
0x573119: jmp short 0057312Fh
0x57311b: mov eax,[edi]
0x57311d: cmp byte ptr [eax+2Dh],0
0x573121: mov ecx,edi
0x573123: jne short 0057312Fh
0x573125: mov ecx,eax
0x573127: mov eax,[ecx]
0x573129: cmp byte ptr [eax+2Dh],0
0x57312d: je short 00573125h
0x57312f: mov eax,[edx+4]
0x573132: mov [eax],ecx
0x573134: mov ecx,[edx+4]
0x573137: cmp [ecx+8],ebx
0x57313a: mov [esp+14h],ecx
0x57313e: jne short 005731BDh
0x573140: cmp byte ptr [edi+2Dh],0
0x573144: je short 0057314Dh
0x573146: mov eax,esi
0x573148: mov [ecx+8],eax
0x57314b: jmp short 005731BDh
0x57314d: mov eax,edi
0x57314f: call 005733F0h
0x573154: mov ecx,[esp+14h]
0x573158: mov edx,[ebp+8]
0x57315b: mov [ecx+8],eax
0x57315e: jmp short 005731BDh
0x573160: mov [eax+4],ecx
0x573163: mov eax,[ebx]
0x573165: mov [ecx],eax
0x573167: cmp ecx,[ebx+8]
0x57316a: jne short 00573170h
0x57316c: mov esi,ecx
0x57316e: jmp short 0057318Ah
0x573170: cmp byte ptr [edi+2Dh],0
0x573174: mov esi,[ecx+4]
0x573177: jne short 0057317Ch
0x573179: mov [edi+4],esi
0x57317c: mov [esi],edi
0x57317e: mov edx,[ebx+8]
0x573181: mov [ecx+8],edx
0x573184: mov eax,[ebx+8]
0x573187: mov [eax+4],ecx
0x57318a: mov edx,[ebp+8]
0x57318d: mov eax,[edx+4]
0x573190: cmp [eax+4],ebx
0x573193: jne short 0057319Ah
0x573195: mov [eax+4],ecx
0x573198: jmp short 005731A8h
0x57319a: mov eax,[ebx+4]
0x57319d: cmp [eax],ebx
0x57319f: jne short 005731A5h
0x5731a1: mov [eax],ecx
0x5731a3: jmp short 005731A8h
0x5731a5: mov [eax+8],ecx
0x5731a8: mov eax,[ebx+4]
0x5731ab: mov [ecx+4],eax
0x5731ae: mov dl,[ebx+2Ch]
0x5731b1: mov al,[ecx+2Ch]
0x5731b4: mov [ecx+2Ch],dl
0x5731b7: mov edx,[ebp+8]
0x5731ba: mov [ebx+2Ch],al
0x5731bd: mov eax,[esp+10h]
0x5731c1: mov bl,1
0x5731c3: cmp [eax+2Ch],bl
0x5731c6: jne near ptr 005732D3h
0x5731cc: mov ecx,[edx+4]
0x5731cf: cmp edi,[ecx+4]
0x5731d2: je near ptr 005732D0h
0x5731d8: jmp short 005731E0h
0x5731e0: cmp [edi+2Ch],bl
0x5731e3: jne near ptr 005732D0h
0x5731e9: mov ecx,[esi]
0x5731eb: cmp edi,ecx
0x5731ed: jne short 00573258h
0x5731ef: mov ecx,[esi+8]
0x5731f2: cmp byte ptr [ecx+2Ch],0
0x5731f6: jne short 0057320Dh
0x5731f8: mov [ecx+2Ch],bl
0x5731fb: push edx
0x5731fc: mov ecx,esi
0x5731fe: mov byte ptr [esi+2Ch],0
0x573202: call 005733A0h
0x573207: mov ecx,[esi+8]
0x57320a: mov edx,[ebp+8]
0x57320d: cmp byte ptr [ecx+2Dh],0
0x573211: jne short 0057328Bh
0x573213: mov eax,[ecx]
0x573215: cmp [eax+2Ch],bl
0x573218: jne short 00573222h
0x57321a: mov eax,[ecx+8]
0x57321d: cmp [eax+2Ch],bl
0x573220: je short 00573287h
0x573222: mov eax,[ecx+8]
0x573225: cmp [eax+2Ch],bl
0x573228: jne short 0057323Fh
0x57322a: mov eax,[ecx]
0x57322c: mov [eax+2Ch],bl
0x57322f: push edx
0x573230: mov byte ptr [ecx+2Ch],0
0x573234: call 00465F60h
0x573239: mov ecx,[esi+8]
0x57323c: mov edx,[ebp+8]
0x57323f: mov al,[esi+2Ch]
0x573242: mov [ecx+2Ch],al
0x573245: mov [esi+2Ch],bl
0x573248: mov ecx,[ecx+8]
0x57324b: mov [ecx+2Ch],bl
0x57324e: push edx
0x57324f: mov ecx,esi
0x573251: call 005733A0h
0x573256: jmp short 005732D0h
0x573258: cmp byte ptr [ecx+2Ch],0
0x57325c: jne short 00573272h
0x57325e: mov [ecx+2Ch],bl
0x573261: push edx
0x573262: mov ecx,esi
0x573264: mov byte ptr [esi+2Ch],0
0x573268: call 00465F60h
0x57326d: mov ecx,[esi]
0x57326f: mov edx,[ebp+8]
0x573272: cmp byte ptr [ecx+2Dh],0
0x573276: jne short 0057328Bh
0x573278: mov eax,[ecx+8]
0x57327b: cmp [eax+2Ch],bl
0x57327e: jne short 0057329Eh
0x573280: mov eax,[ecx]
0x573282: cmp [eax+2Ch],bl
0x573285: jne short 0057329Eh
0x573287: mov byte ptr [ecx+2Ch],0
0x57328b: mov ecx,[edx+4]
0x57328e: mov edi,esi
0x573290: cmp edi,[ecx+4]
0x573293: mov esi,[esi+4]
0x573296: jne near ptr 005731E0h
0x57329c: jmp short 005732D0h
0x57329e: mov eax,[ecx]
0x5732a0: cmp [eax+2Ch],bl
0x5732a3: jne short 005732BAh
0x5732a5: mov eax,[ecx+8]
0x5732a8: mov [eax+2Ch],bl
0x5732ab: push edx
0x5732ac: mov byte ptr [ecx+2Ch],0
0x5732b0: call 005733A0h
0x5732b5: mov ecx,[esi]
0x5732b7: mov edx,[ebp+8]
0x5732ba: mov al,[esi+2Ch]
0x5732bd: mov [ecx+2Ch],al
0x5732c0: mov [esi+2Ch],bl
0x5732c3: mov ecx,[ecx]
0x5732c5: mov [ecx+2Ch],bl
0x5732c8: push edx
0x5732c9: mov ecx,esi
0x5732cb: call 00465F60h
0x5732d0: mov [edi+2Ch],bl
0x5732d3: mov ecx,[esp+10h]
0x5732d7: add ecx,0Ch
0x5732da: call dword ptr ds:[77CD74h]
0x5732e0: mov edx,[esp+10h]
0x5732e4: push edx
0x5732e5: call 006516BAh
0x5732ea: mov ecx,[ebp+8]
0x5732ed: mov eax,[ecx+8]
0x5732f0: add esp,4
0x5732f3: test eax,eax
0x5732f5: jbe short 005732FDh
0x5732f7: add eax,0FFFFFFFFh
0x5732fa: mov [ecx+8],eax
0x5732fd: mov eax,[ebp+0Ch]
0x573300: mov ecx,[ebp+10h]
0x573303: mov edx,[ebp+14h]
0x573306: mov [eax],ecx
0x573308: mov [eax+4],edx
0x57330b: mov ecx,[esp+60h]
0x57330f: mov fs:[0],ecx
0x573316: pop ecx
0x573317: pop edi
0x573318: pop esi
0x573319: pop ebx
0x57331a: mov esp,ebp
0x57331c: pop ebp
0x57331d: ret 10h
````

`sub_573040` is called by sub_573500. It delegates to sub_401230, sub_43a360, sub_465f60 (7 callees).

### ?get_mutable_instance@?$singleton@VCViewManager@@@serialization@boost@@SAAAVCViewManager@@XZ at 0x573390 (25 instructions)

````text
0x573390: jmp near ptr 00573450h
0x573450: push 0FFFFFFFFh
0x573452: push 75091Eh
0x573457: mov eax,fs:[0]
0x57345d: push eax
0x57345e: mov eax,ds:[858220h]
0x573463: xor eax,esp
0x573465: push eax
0x573466: lea eax,[esp+4]
0x57346a: mov fs:[0],eax
0x573470: mov eax,1
0x573475: test ds:[875DECh],al
0x57347b: jne short 0057349Dh
0x57347d: or ds:[875DECh],eax
0x573483: mov dword ptr [esp+0Ch],0
0x57348b: call 005734C0h
0x573490: push 77B380h
0x573495: call 006527EDh
0x57349a: add esp,4
0x57349d: mov eax,875A4Ch
0x5734a2: mov ecx,[esp+4]
0x5734a6: mov fs:[0],ecx
0x5734ad: pop ecx
0x5734ae: add esp,0Ch
0x5734b1: ret
````

`?get_mutable_instance@?$singleton@VCViewManager@@@serialization@boost@@SAAAVCViewManager@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5734c0, sub_6527ed (2 callees).

### sub_5733a0 at 0x5733a0 (28 instructions)

````text
0x5733a0: mov eax,[ecx+8]
0x5733a3: mov edx,[eax]
0x5733a5: mov [ecx+8],edx
0x5733a8: mov edx,[eax]
0x5733aa: cmp byte ptr [edx+2Dh],0
0x5733ae: jne short 005733B3h
0x5733b0: mov [edx+4],ecx
0x5733b3: mov edx,[ecx+4]
0x5733b6: mov [eax+4],edx
0x5733b9: mov edx,[esp+4]
0x5733bd: mov edx,[edx+4]
0x5733c0: cmp ecx,[edx+4]
0x5733c3: jne short 005733D0h
0x5733c5: mov [edx+4],eax
0x5733c8: mov [eax],ecx
0x5733ca: mov [ecx+4],eax
0x5733cd: ret 4
0x5733d0: mov edx,[ecx+4]
0x5733d3: cmp ecx,[edx]
0x5733d5: jne short 005733E1h
0x5733d7: mov [edx],eax
0x5733d9: mov [eax],ecx
0x5733db: mov [ecx+4],eax
0x5733de: ret 4
0x5733e1: mov [edx+8],eax
0x5733e4: mov [eax],ecx
0x5733e6: mov [ecx+4],eax
0x5733e9: ret 4
````

`sub_5733a0` is called by sub_4655a0, sub_4b57e0, sub_573040. It calls nothing else.

### sub_5733f0 at 0x5733f0 (9 instructions)

````text
0x5733f0: mov ecx,[eax+8]
0x5733f3: cmp byte ptr [ecx+2Dh],0
0x5733f7: jne short 0057340Bh
0x5733f9: lea esp,[esp]
0x573400: mov eax,ecx
0x573402: mov ecx,[eax+8]
0x573405: cmp byte ptr [ecx+2Dh],0
0x573409: je short 00573400h
0x57340b: ret
````

`sub_5733f0` is called by sub_4655a0, sub_4b57e0, sub_573040. It calls nothing else.

### ?get_instance@?$singleton@VCViewManager@@@serialization@boost@@CAAAVCViewManager@@XZ at 0x573450 (24 instructions)

````text
0x573450: push 0FFFFFFFFh
0x573452: push 75091Eh
0x573457: mov eax,fs:[0]
0x57345d: push eax
0x57345e: mov eax,ds:[858220h]
0x573463: xor eax,esp
0x573465: push eax
0x573466: lea eax,[esp+4]
0x57346a: mov fs:[0],eax
0x573470: mov eax,1
0x573475: test ds:[875DECh],al
0x57347b: jne short 0057349Dh
0x57347d: or ds:[875DECh],eax
0x573483: mov dword ptr [esp+0Ch],0
0x57348b: call 005734C0h
0x573490: push 77B380h
0x573495: call 006527EDh
0x57349a: add esp,4
0x57349d: mov eax,875A4Ch
0x5734a2: mov ecx,[esp+4]
0x5734a6: mov fs:[0],ecx
0x5734ad: pop ecx
0x5734ae: add esp,0Ch
0x5734b1: ret
````

`?get_instance@?$singleton@VCViewManager@@@serialization@boost@@CAAAVCViewManager@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5734c0, sub_6527ed (2 callees).

### sub_5734c0 at 0x5734c0 (13 instructions)

````text
0x5734c0: mov dword ptr ds:[875A4Ch],0
0x5734ca: call 005735D0h
0x5734cf: mov ds:[875A54h],eax
0x5734d4: mov byte ptr [eax+2Dh],1
0x5734d8: mov eax,ds:[875A54h]
0x5734dd: mov [eax+4],eax
0x5734e0: mov eax,ds:[875A54h]
0x5734e5: mov [eax],eax
0x5734e7: mov eax,ds:[875A54h]
0x5734ec: mov [eax+8],eax
0x5734ef: mov dword ptr ds:[875A58h],0
0x5734f9: mov eax,875A4Ch
0x5734fe: ret
````

`sub_5734c0` is called by ?get_mutable_instance@?$singleton@VCViewManager@@@serialization@boost@@SAAAVCViewManager@@XZ, ?get_instance@?$singleton@VCViewManager@@@serialization@boost@@CAAAVCViewManager@@XZ. It delegates to sub_5735d0 (1 callees).

### sub_573500 at 0x573500 (72 instructions)

````text
0x573500: mov eax,[edi+4]
0x573503: sub esp,0Ch
0x573506: push ebx
0x573507: mov ebx,[esp+18h]
0x57350b: test ebx,ebx
0x57350d: push ebp
0x57350e: push esi
0x57350f: mov esi,[eax]
0x573511: je short 00573517h
0x573513: cmp ebx,edi
0x573515: je short 0057351Dh
0x573517: call dword ptr ds:[77D0E4h]
0x57351d: mov ebp,[esp+24h]
0x573521: cmp ebp,esi
0x573523: jne short 00573580h
0x573525: mov eax,[esp+28h]
0x573529: test eax,eax
0x57352b: mov esi,[edi+4]
0x57352e: je short 00573534h
0x573530: cmp eax,edi
0x573532: je short 0057353Ah
0x573534: call dword ptr ds:[77D0E4h]
0x57353a: cmp [esp+2Ch],esi
0x57353e: jne short 00573580h
0x573540: mov ecx,[edi+4]
0x573543: mov edx,[ecx+4]
0x573546: push edx
0x573547: mov ecx,edi
0x573549: call 00573610h
0x57354e: mov eax,[edi+4]
0x573551: mov [eax+4],eax
0x573554: mov eax,[edi+4]
0x573557: mov dword ptr [edi+8],0
0x57355e: mov [eax],eax
0x573560: mov eax,[edi+4]
0x573563: mov [eax+8],eax
0x573566: mov eax,[edi+4]
0x573569: mov ecx,[eax]
0x57356b: mov eax,[esp+1Ch]
0x57356f: mov [eax+4],ecx
0x573572: mov [eax],edi
0x573574: pop esi
0x573575: pop ebp
0x573576: pop ebx
0x573577: add esp,0Ch
0x57357a: ret 14h
0x573580: test ebx,ebx
0x573582: je short 0057358Ah
0x573584: cmp ebx,[esp+28h]
0x573588: je short 00573590h
0x57358a: call dword ptr ds:[77D0E4h]
0x573590: cmp ebp,[esp+2Ch]
0x573594: je short 005735B6h
0x573596: lea esi,[esp+20h]
0x57359a: call 0043A360h
0x57359f: push ebp
0x5735a0: push ebx
0x5735a1: lea edx,[esp+18h]
0x5735a5: push edx
0x5735a6: push edi
0x5735a7: call 00573040h
0x5735ac: mov ebp,[esp+24h]
0x5735b0: mov ebx,[esp+20h]
0x5735b4: jmp short 00573580h
0x5735b6: mov eax,[esp+1Ch]
0x5735ba: pop esi
0x5735bb: mov [eax+4],ebp
0x5735be: pop ebp
0x5735bf: mov [eax],ebx
0x5735c1: pop ebx
0x5735c2: add esp,0Ch
0x5735c5: ret 14h
````

`sub_573500` is called by sub_77b380. It delegates to sub_43a360, sub_573040, sub_573610 (3 callees).

### sub_5735d0 at 0x5735d0 (16 instructions)

````text
0x5735d0: mov ecx,1
0x5735d5: call 004DB900h
0x5735da: test eax,eax
0x5735dc: je short 005735E4h
0x5735de: mov dword ptr [eax],0
0x5735e4: lea ecx,[eax+4]
0x5735e7: test ecx,ecx
0x5735e9: je short 005735F1h
0x5735eb: mov dword ptr [ecx],0
0x5735f1: lea ecx,[eax+8]
0x5735f4: test ecx,ecx
0x5735f6: je short 005735FEh
0x5735f8: mov dword ptr [ecx],0
0x5735fe: mov byte ptr [eax+2Ch],1
0x573602: mov byte ptr [eax+2Dh],0
0x573606: ret
````

`sub_5735d0` is called by sub_5734c0, sub_624350. It delegates to sub_4db900 (1 callees).

### sub_573610 at 0x573610 (25 instructions)

````text
0x573610: push ebx
0x573611: push esi
0x573612: push edi
0x573613: mov edi,[esp+10h]
0x573617: cmp byte ptr [edi+2Dh],0
0x57361b: mov ebx,ecx
0x57361d: mov esi,edi
0x57361f: jne short 00573648h
0x573621: mov eax,[esi+8]
0x573624: push eax
0x573625: mov ecx,ebx
0x573627: call 00573610h
0x57362c: mov esi,[esi]
0x57362e: lea ecx,[edi+0Ch]
0x573631: call dword ptr ds:[77CD74h]
0x573637: push edi
0x573638: call 006516BAh
0x57363d: add esp,4
0x573640: cmp byte ptr [esi+2Dh],0
0x573644: mov edi,esi
0x573646: je short 00573621h
0x573648: pop edi
0x573649: pop esi
0x57364a: pop ebx
0x57364b: ret 4
````

`sub_573610` is called by sub_4b4590, sub_573500, sub_573610, sub_60f730. It delegates to sub_573610, j_ORDINAL 764 (2 callees).

### sub_575110 at 0x575110 (23 instructions)

````text
0x575110: push esi
0x575111: mov esi,[ebx+4]
0x575114: test esi,esi
0x575116: je short 0057513Dh
0x575118: push edi
0x575119: mov edi,[ebx+8]
0x57511c: cmp esi,edi
0x57511e: je short 00575130h
0x575120: lea ecx,[esi+4]
0x575123: call dword ptr ds:[77CD74h]
0x575129: add esi,20h
0x57512c: cmp esi,edi
0x57512e: jne short 00575120h
0x575130: mov eax,[ebx+4]
0x575133: push eax
0x575134: call 006516BAh
0x575139: add esp,4
0x57513c: pop edi
0x57513d: mov dword ptr [ebx+4],0
0x575144: mov dword ptr [ebx+8],0
0x57514b: mov dword ptr [ebx+0Ch],0
0x575152: pop esi
0x575153: ret
````

`sub_575110` is called by sub_585a40, sub_610c30, sub_615070. It delegates to j_ORDINAL 764 (1 callees).

### sub_580be0 at 0x580be0 (44 instructions)

````text
0x580be0: push 0FFFFFFFFh
0x580be2: push 76275Fh
0x580be7: mov eax,fs:[0]
0x580bed: push eax
0x580bee: push ecx
0x580bef: mov eax,ds:[858220h]
0x580bf4: xor eax,esp
0x580bf6: push eax
0x580bf7: lea eax,[esp+8]
0x580bfb: mov fs:[0],eax
0x580c01: mov ecx,876378h
0x580c06: mov dword ptr [esp+4],876378h
0x580c0e: call dword ptr ds:[77DF80h]
0x580c14: mov dword ptr [esp+10h],0
0x580c1c: call 00585350h
0x580c21: mov ds:[876384h],eax
0x580c26: mov byte ptr [eax+19h],1
0x580c2a: mov eax,ds:[876384h]
0x580c2f: mov [eax+4],eax
0x580c32: mov eax,ds:[876384h]
0x580c37: mov [eax],eax
0x580c39: mov eax,ds:[876384h]
0x580c3e: mov [eax+8],eax
0x580c41: mov dword ptr ds:[876388h],0
0x580c4b: mov byte ptr [esp+10h],1
0x580c50: call 00585350h
0x580c55: mov ds:[876390h],eax
0x580c5a: mov byte ptr [eax+19h],1
0x580c5e: mov eax,ds:[876390h]
0x580c63: mov [eax+4],eax
0x580c66: mov eax,ds:[876390h]
0x580c6b: mov [eax],eax
0x580c6d: mov eax,ds:[876390h]
0x580c72: mov [eax+8],eax
0x580c75: mov dword ptr ds:[876394h],0
0x580c7f: push 876398h
0x580c84: mov byte ptr [esp+14h],2
0x580c89: call 005859C0h
0x580c8e: mov eax,876378h
0x580c93: mov ecx,[esp+8]
0x580c97: mov fs:[0],ecx
0x580c9e: pop ecx
0x580c9f: add esp,10h
0x580ca2: ret
````

`sub_580be0` is called by ?get_instance@?$singleton@VCSymbolManager@@@serialization@boost@@CAAAVCSymbolManager@@XZ. It delegates to sub_585350, sub_5859c0 (2 callees).

### sub_580cc0 at 0x580cc0 (28 instructions)

````text
0x580cc0: push 0FFFFFFFFh
0x580cc2: push 76275Fh
0x580cc7: mov eax,fs:[0]
0x580ccd: push eax
0x580cce: push ecx
0x580ccf: mov eax,ds:[858220h]
0x580cd4: xor eax,esp
0x580cd6: push eax
0x580cd7: lea eax,[esp+8]
0x580cdb: mov fs:[0],eax
0x580ce1: mov dword ptr [esp+4],876378h
0x580ce9: push 876398h
0x580cee: mov dword ptr [esp+14h],2
0x580cf6: call 00585A40h
0x580cfb: mov eax,87638Ch
0x580d00: mov byte ptr [esp+10h],1
0x580d05: call 00584F40h
0x580d0a: mov eax,876380h
0x580d0f: mov byte ptr [esp+10h],0
0x580d14: call 00584F40h
0x580d19: mov ecx,876378h
0x580d1e: mov dword ptr [esp+10h],0FFFFFFFFh
0x580d26: call dword ptr ds:[77DF7Ch]
0x580d2c: mov ecx,[esp+8]
0x580d30: mov fs:[0],ecx
0x580d37: pop ecx
0x580d38: add esp,10h
0x580d3b: ret
````

`sub_580cc0` is called by sub_77b3c0. It delegates to sub_584f40, sub_585a40 (2 callees).

### sub_584970 at 0x584970 (263 instructions)

````text
0x584970: push 0FFFFFFFFh
0x584972: push 7410D9h
0x584977: mov eax,fs:[0]
0x58497d: push eax
0x58497e: sub esp,44h
0x584981: push ebx
0x584982: push ebp
0x584983: push esi
0x584984: push edi
0x584985: mov eax,ds:[858220h]
0x58498a: xor eax,esp
0x58498c: push eax
0x58498d: lea eax,[esp+58h]
0x584991: mov fs:[0],eax
0x584997: mov eax,[esp+74h]
0x58499b: cmp byte ptr [eax+19h],0
0x58499f: je short 005849DDh
0x5849a1: push 7C5AECh
0x5849a6: lea ecx,[esp+18h]
0x5849aa: call dword ptr ds:[77CD7Ch]
0x5849b0: lea eax,[esp+14h]
0x5849b4: push eax
0x5849b5: lea ecx,[esp+34h]
0x5849b9: mov dword ptr [esp+64h],0
0x5849c1: call 00401230h
0x5849c6: push 80A4F8h
0x5849cb: lea ecx,[esp+34h]
0x5849cf: push ecx
0x5849d0: mov dword ptr [esp+38h],790F90h
0x5849d8: call 00652AC4h
0x5849dd: lea esi,[esp+70h]
0x5849e1: mov ebp,eax
0x5849e3: call 005853F0h
0x5849e8: mov eax,[ebp]
0x5849eb: cmp byte ptr [eax+19h],0
0x5849ef: je short 005849F6h
0x5849f1: mov edi,[ebp+8]
0x5849f4: jmp short 00584A0Eh
0x5849f6: mov edx,[ebp+8]
0x5849f9: cmp byte ptr [edx+19h],0
0x5849fd: je short 00584A03h
0x5849ff: mov edi,eax
0x584a01: jmp short 00584A0Eh
0x584a03: mov ecx,[esp+74h]
0x584a07: cmp ecx,ebp
0x584a09: mov edi,[ecx+8]
0x584a0c: jne short 00584A82h
0x584a0e: cmp byte ptr [edi+19h],0
0x584a12: mov esi,[ebp+4]
0x584a15: jne short 00584A1Ah
0x584a17: mov [edi+4],esi
0x584a1a: mov ecx,[esp+68h]
0x584a1e: mov eax,[ecx+4]
0x584a21: cmp [eax+4],ebp
0x584a24: jne short 00584A2Bh
0x584a26: mov [eax+4],edi
0x584a29: jmp short 00584A36h
0x584a2b: cmp [esi],ebp
0x584a2d: jne short 00584A33h
0x584a2f: mov [esi],edi
0x584a31: jmp short 00584A36h
0x584a33: mov [esi+8],edi
0x584a36: mov edx,[ecx+4]
0x584a39: cmp [edx],ebp
0x584a3b: jne short 00584A5Dh
0x584a3d: cmp byte ptr [edi+19h],0
0x584a41: je short 00584A47h
0x584a43: mov ecx,esi
0x584a45: jmp short 00584A5Bh
0x584a47: mov eax,[edi]
0x584a49: cmp byte ptr [eax+19h],0
0x584a4d: mov ecx,edi
0x584a4f: jne short 00584A5Bh
0x584a51: mov ecx,eax
0x584a53: mov eax,[ecx]
0x584a55: cmp byte ptr [eax+19h],0
0x584a59: je short 00584A51h
0x584a5b: mov [edx],ecx
0x584a5d: mov eax,[esp+68h]
0x584a61: mov ebx,[eax+4]
0x584a64: cmp [ebx+8],ebp
0x584a67: jne short 00584ADEh
0x584a69: cmp byte ptr [edi+19h],0
0x584a6d: je short 00584A76h
0x584a6f: mov eax,esi
0x584a71: mov [ebx+8],eax
0x584a74: jmp short 00584ADEh
0x584a76: mov eax,edi
0x584a78: call 00585460h
0x584a7d: mov [ebx+8],eax
0x584a80: jmp short 00584ADEh
0x584a82: mov [eax+4],ecx
0x584a85: mov edx,[ebp]
0x584a88: mov [ecx],edx
0x584a8a: cmp ecx,[ebp+8]
0x584a8d: jne short 00584A93h
0x584a8f: mov esi,ecx
0x584a91: jmp short 00584AADh
0x584a93: cmp byte ptr [edi+19h],0
0x584a97: mov esi,[ecx+4]
0x584a9a: jne short 00584A9Fh
0x584a9c: mov [edi+4],esi
0x584a9f: mov [esi],edi
0x584aa1: mov eax,[ebp+8]
0x584aa4: mov [ecx+8],eax
0x584aa7: mov edx,[ebp+8]
0x584aaa: mov [edx+4],ecx
0x584aad: mov eax,[esp+68h]
0x584ab1: mov eax,[eax+4]
0x584ab4: cmp [eax+4],ebp
0x584ab7: jne short 00584ABEh
0x584ab9: mov [eax+4],ecx
0x584abc: jmp short 00584ACCh
0x584abe: mov eax,[ebp+4]
0x584ac1: cmp [eax],ebp
0x584ac3: jne short 00584AC9h
0x584ac5: mov [eax],ecx
0x584ac7: jmp short 00584ACCh
0x584ac9: mov [eax+8],ecx
0x584acc: mov edx,[ebp+4]
0x584acf: mov [ecx+4],edx
0x584ad2: mov dl,[ebp+18h]
0x584ad5: mov al,[ecx+18h]
0x584ad8: mov [ecx+18h],dl
0x584adb: mov [ebp+18h],al
0x584ade: mov bl,1
0x584ae0: cmp [ebp+18h],bl
0x584ae3: jne near ptr 00584C0Ah
0x584ae9: mov eax,[esp+68h]
0x584aed: mov ecx,[eax+4]
0x584af0: cmp edi,[ecx+4]
0x584af3: je near ptr 00584C07h
0x584af9: lea esp,[esp]
0x584b00: cmp [edi+18h],bl
0x584b03: jne near ptr 00584C07h
0x584b09: mov ecx,[esi]
0x584b0b: cmp edi,ecx
0x584b0d: jne short 00584B85h
0x584b0f: mov ecx,[esi+8]
0x584b12: cmp byte ptr [ecx+18h],0
0x584b16: jne short 00584B2Eh
0x584b18: mov edx,[esp+68h]
0x584b1c: mov [ecx+18h],bl
0x584b1f: push edx
0x584b20: mov ecx,esi
0x584b22: mov byte ptr [esi+18h],0
0x584b26: call 005070E0h
0x584b2b: mov ecx,[esi+8]
0x584b2e: cmp byte ptr [ecx+19h],0
0x584b32: jne near ptr 00584BB9h
0x584b38: mov eax,[ecx]
0x584b3a: cmp [eax+18h],bl
0x584b3d: jne short 00584B47h
0x584b3f: mov edx,[ecx+8]
0x584b42: cmp [edx+18h],bl
0x584b45: je short 00584BB5h
0x584b47: mov eax,[ecx+8]
0x584b4a: cmp [eax+18h],bl
0x584b4d: jne short 00584B65h
0x584b4f: mov edx,[ecx]
0x584b51: mov eax,[esp+68h]
0x584b55: mov [edx+18h],bl
0x584b58: push eax
0x584b59: mov byte ptr [ecx+18h],0
0x584b5d: call 005F0770h
0x584b62: mov ecx,[esi+8]
0x584b65: mov dl,[esi+18h]
0x584b68: mov [ecx+18h],dl
0x584b6b: mov [esi+18h],bl
0x584b6e: mov eax,[ecx+8]
0x584b71: mov ecx,[esp+68h]
0x584b75: push ecx
0x584b76: mov ecx,esi
0x584b78: mov [eax+18h],bl
0x584b7b: call 005070E0h
0x584b80: jmp near ptr 00584C07h
0x584b85: cmp byte ptr [ecx+18h],0
0x584b89: jne short 00584BA0h
0x584b8b: mov eax,[esp+68h]
0x584b8f: mov [ecx+18h],bl
0x584b92: push eax
0x584b93: mov ecx,esi
0x584b95: mov byte ptr [esi+18h],0
0x584b99: call 005F0770h
0x584b9e: mov ecx,[esi]
0x584ba0: cmp byte ptr [ecx+19h],0
0x584ba4: jne short 00584BB9h
0x584ba6: mov edx,[ecx+8]
0x584ba9: cmp [edx+18h],bl
0x584bac: jne short 00584BD0h
0x584bae: mov eax,[ecx]
0x584bb0: cmp [eax+18h],bl
0x584bb3: jne short 00584BD0h
0x584bb5: mov byte ptr [ecx+18h],0
0x584bb9: mov ecx,[esp+68h]
0x584bbd: mov edx,[ecx+4]
0x584bc0: mov edi,esi
0x584bc2: cmp edi,[edx+4]
0x584bc5: mov esi,[esi+4]
0x584bc8: jne near ptr 00584B00h
0x584bce: jmp short 00584C07h
0x584bd0: mov edx,[ecx]
0x584bd2: cmp [edx+18h],bl
0x584bd5: jne short 00584BEDh
0x584bd7: mov eax,[ecx+8]
0x584bda: mov edx,[esp+68h]
0x584bde: mov [eax+18h],bl
0x584be1: push edx
0x584be2: mov byte ptr [ecx+18h],0
0x584be6: call 005070E0h
0x584beb: mov ecx,[esi]
0x584bed: mov al,[esi+18h]
0x584bf0: mov edx,[esp+68h]
0x584bf4: mov [ecx+18h],al
0x584bf7: mov [esi+18h],bl
0x584bfa: mov ecx,[ecx]
0x584bfc: mov [ecx+18h],bl
0x584bff: push edx
0x584c00: mov ecx,esi
0x584c02: call 005F0770h
0x584c07: mov [edi+18h],bl
0x584c0a: mov esi,[ebp+14h]
0x584c0d: test esi,esi
0x584c0f: je short 00584C3Bh
0x584c11: lea eax,[esi+4]
0x584c14: or ecx,0FFFFFFFFh
0x584c17: lock xadd [eax],ecx
0x584c1b: jne short 00584C3Bh
0x584c1d: mov edx,[esi]
0x584c1f: mov eax,[edx+4]
0x584c22: mov ecx,esi
0x584c24: call eax
0x584c26: lea ecx,[esi+8]
0x584c29: or edx,0FFFFFFFFh
0x584c2c: lock xadd [ecx],edx
0x584c30: jne short 00584C3Bh
0x584c32: mov eax,[esi]
0x584c34: mov edx,[eax+8]
0x584c37: mov ecx,esi
0x584c39: call edx
0x584c3b: push ebp
0x584c3c: call 006516BAh
0x584c41: mov ecx,[esp+6Ch]
0x584c45: mov eax,[ecx+8]
0x584c48: add esp,4
0x584c4b: test eax,eax
0x584c4d: jbe short 00584C55h
0x584c4f: add eax,0FFFFFFFFh
0x584c52: mov [ecx+8],eax
0x584c55: mov eax,[esp+6Ch]
0x584c59: mov ecx,[esp+70h]
0x584c5d: mov edx,[esp+74h]
0x584c61: mov [eax],ecx
0x584c63: mov [eax+4],edx
0x584c66: mov ecx,[esp+58h]
0x584c6a: mov fs:[0],ecx
0x584c71: pop ecx
0x584c72: pop edi
0x584c73: pop esi
0x584c74: pop ebp
0x584c75: pop ebx
0x584c76: add esp,50h
0x584c79: ret 10h
````

`sub_584970` is called by sub_584ff0. It delegates to sub_401230, sub_5070e0, sub_5853f0 (7 callees).

### ?get_mutable_instance@?$singleton@VCSymbolManager@@@serialization@boost@@SAAAVCSymbolManager@@XZ at 0x584cf0 (4 instructions)

````text
0x584cf0: push ecx
0x584cf1: call 00584F80h
0x584cf6: pop ecx
0x584cf7: ret
````

`?get_mutable_instance@?$singleton@VCSymbolManager@@@serialization@boost@@SAAAVCSymbolManager@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VCSymbolManager@@@serialization@boost@@CAAAVCSymbolManager@@XZ (1 callees).

### sub_584ed0 at 0x584ed0 (44 instructions)

````text
0x584ed0: push ebx
0x584ed1: mov ebx,[esp+8]
0x584ed5: cmp byte ptr [ebx+19h],0
0x584ed9: push ebp
0x584eda: push esi
0x584edb: mov ebp,ecx
0x584edd: mov esi,ebx
0x584edf: jne short 00584F32h
0x584ee1: push edi
0x584ee2: mov eax,[esi+8]
0x584ee5: push eax
0x584ee6: mov ecx,ebp
0x584ee8: call 00584ED0h
0x584eed: mov edi,[ebx+14h]
0x584ef0: test edi,edi
0x584ef2: mov esi,[esi]
0x584ef4: je short 00584F20h
0x584ef6: lea ecx,[edi+4]
0x584ef9: or edx,0FFFFFFFFh
0x584efc: lock xadd [ecx],edx
0x584f00: jne short 00584F20h
0x584f02: mov eax,[edi]
0x584f04: mov edx,[eax+4]
0x584f07: mov ecx,edi
0x584f09: call edx
0x584f0b: lea eax,[edi+8]
0x584f0e: or ecx,0FFFFFFFFh
0x584f11: lock xadd [eax],ecx
0x584f15: jne short 00584F20h
0x584f17: mov edx,[edi]
0x584f19: mov eax,[edx+8]
0x584f1c: mov ecx,edi
0x584f1e: call eax
0x584f20: push ebx
0x584f21: call 006516BAh
0x584f26: add esp,4
0x584f29: cmp byte ptr [esi+19h],0
0x584f2d: mov ebx,esi
0x584f2f: je short 00584EE2h
0x584f31: pop edi
0x584f32: pop esi
0x584f33: pop ebp
0x584f34: pop ebx
0x584f35: ret 4
````

`sub_584ed0` is called by sub_506680, sub_584ed0, sub_584ff0. It delegates to sub_584ed0, j_ORDINAL 764 (2 callees).

### sub_584f40 at 0x584f40 (26 instructions)

````text
0x584f40: push ebp
0x584f41: mov ebp,esp
0x584f43: and esp,0FFFFFFF8h
0x584f46: sub esp,0Ch
0x584f49: push edi
0x584f4a: mov edi,eax
0x584f4c: mov eax,[edi+4]
0x584f4f: mov ecx,[eax]
0x584f51: push eax
0x584f52: push edi
0x584f53: push ecx
0x584f54: push edi
0x584f55: lea eax,[esp+18h]
0x584f59: push eax
0x584f5a: call 00584FF0h
0x584f5f: mov ecx,[edi+4]
0x584f62: push ecx
0x584f63: call 006516BAh
0x584f68: add esp,4
0x584f6b: xor eax,eax
0x584f6d: mov [edi+4],eax
0x584f70: mov [edi+8],eax
0x584f73: pop edi
0x584f74: mov esp,ebp
0x584f76: pop ebp
0x584f77: ret
````

`sub_584f40` is called by sub_580cc0. It delegates to sub_584ff0, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@VCSymbolManager@@@serialization@boost@@CAAAVCSymbolManager@@XZ at 0x584f80 (25 instructions)

````text
0x584f80: push 0FFFFFFFFh
0x584f82: push 76992Eh
0x584f87: mov eax,fs:[0]
0x584f8d: push eax
0x584f8e: mov eax,ds:[858220h]
0x584f93: push ecx
0x584f94: xor eax,esp
0x584f96: push eax
0x584f97: lea eax,[esp+8]
0x584f9b: mov fs:[0],eax
0x584fa1: mov eax,1
0x584fa6: test ds:[876544h],al
0x584fac: jne short 00584FCEh
0x584fae: or ds:[876544h],eax
0x584fb4: mov dword ptr [esp+10h],0
0x584fbc: call 00580BE0h
0x584fc1: push 77B3C0h
0x584fc6: call 006527EDh
0x584fcb: add esp,4
0x584fce: mov eax,876378h
0x584fd3: mov ecx,[esp+8]
0x584fd7: mov fs:[0],ecx
0x584fde: pop ecx
0x584fdf: add esp,10h
0x584fe2: ret
````

`?get_instance@?$singleton@VCSymbolManager@@@serialization@boost@@CAAAVCSymbolManager@@XZ` is called by ?get_mutable_instance@?$singleton@VCSymbolManager@@@serialization@boost@@SAAAVCSymbolManager@@XZ. It delegates to sub_580be0, sub_6527ed (2 callees).

### sub_584ff0 at 0x584ff0 (72 instructions)

````text
0x584ff0: mov eax,[edi+4]
0x584ff3: sub esp,0Ch
0x584ff6: push ebx
0x584ff7: mov ebx,[esp+18h]
0x584ffb: test ebx,ebx
0x584ffd: push ebp
0x584ffe: push esi
0x584fff: mov esi,[eax]
0x585001: je short 00585007h
0x585003: cmp ebx,edi
0x585005: je short 0058500Dh
0x585007: call dword ptr ds:[77D0E4h]
0x58500d: mov ebp,[esp+24h]
0x585011: cmp ebp,esi
0x585013: jne short 00585070h
0x585015: mov eax,[esp+28h]
0x585019: test eax,eax
0x58501b: mov esi,[edi+4]
0x58501e: je short 00585024h
0x585020: cmp eax,edi
0x585022: je short 0058502Ah
0x585024: call dword ptr ds:[77D0E4h]
0x58502a: cmp [esp+2Ch],esi
0x58502e: jne short 00585070h
0x585030: mov ecx,[edi+4]
0x585033: mov edx,[ecx+4]
0x585036: push edx
0x585037: mov ecx,edi
0x585039: call 00584ED0h
0x58503e: mov eax,[edi+4]
0x585041: mov [eax+4],eax
0x585044: mov eax,[edi+4]
0x585047: mov dword ptr [edi+8],0
0x58504e: mov [eax],eax
0x585050: mov eax,[edi+4]
0x585053: mov [eax+8],eax
0x585056: mov eax,[edi+4]
0x585059: mov ecx,[eax]
0x58505b: mov eax,[esp+1Ch]
0x58505f: mov [eax+4],ecx
0x585062: mov [eax],edi
0x585064: pop esi
0x585065: pop ebp
0x585066: pop ebx
0x585067: add esp,0Ch
0x58506a: ret 14h
0x585070: test ebx,ebx
0x585072: je short 0058507Ah
0x585074: cmp ebx,[esp+28h]
0x585078: je short 00585080h
0x58507a: call dword ptr ds:[77D0E4h]
0x585080: cmp ebp,[esp+2Ch]
0x585084: je short 005850A6h
0x585086: lea esi,[esp+20h]
0x58508a: call 005853F0h
0x58508f: push ebp
0x585090: push ebx
0x585091: lea edx,[esp+18h]
0x585095: push edx
0x585096: push edi
0x585097: call 00584970h
0x58509c: mov ebp,[esp+24h]
0x5850a0: mov ebx,[esp+20h]
0x5850a4: jmp short 00585070h
0x5850a6: mov eax,[esp+1Ch]
0x5850aa: pop esi
0x5850ab: mov [eax+4],ebp
0x5850ae: pop ebp
0x5850af: mov [eax],ebx
0x5850b1: pop ebx
0x5850b2: add esp,0Ch
0x5850b5: ret 14h
````

`sub_584ff0` is called by sub_584f40. It delegates to sub_584970, sub_584ed0, sub_5853f0 (3 callees).

### sub_585350 at 0x585350 (16 instructions)

````text
0x585350: mov ecx,1
0x585355: call 0042D470h
0x58535a: test eax,eax
0x58535c: je short 00585364h
0x58535e: mov dword ptr [eax],0
0x585364: lea ecx,[eax+4]
0x585367: test ecx,ecx
0x585369: je short 00585371h
0x58536b: mov dword ptr [ecx],0
0x585371: lea ecx,[eax+8]
0x585374: test ecx,ecx
0x585376: je short 0058537Eh
0x585378: mov dword ptr [ecx],0
0x58537e: mov byte ptr [eax+18h],1
0x585382: mov byte ptr [eax+19h],0
0x585386: ret
````

`sub_585350` is called by sub_580be0, sub_619e20. It delegates to sub_42d470 (1 callees).

### sub_5853f0 at 0x5853f0 (39 instructions)

````text
0x5853f0: cmp dword ptr [esi],0
0x5853f3: push edi
0x5853f4: mov edi,ds:[77D0E4h]
0x5853fa: jne short 005853FEh
0x5853fc: call edi
0x5853fe: mov eax,[esi+4]
0x585401: cmp byte ptr [eax+19h],0
0x585405: je short 0058540Bh
0x585407: call edi
0x585409: pop edi
0x58540a: ret
0x58540b: mov ecx,[eax+8]
0x58540e: cmp byte ptr [ecx+19h],0
0x585412: jne short 0058542Fh
0x585414: mov eax,[ecx]
0x585416: cmp byte ptr [eax+19h],0
0x58541a: jne short 0058542Ah
0x58541c: lea esp,[esp]
0x585420: mov ecx,eax
0x585422: mov eax,[ecx]
0x585424: cmp byte ptr [eax+19h],0
0x585428: je short 00585420h
0x58542a: mov [esi+4],ecx
0x58542d: pop edi
0x58542e: ret
0x58542f: mov eax,[eax+4]
0x585432: cmp byte ptr [eax+19h],0
0x585436: jne short 0058544Eh
0x585438: mov ecx,[esi+4]
0x58543b: cmp ecx,[eax+8]
0x58543e: jne short 0058544Eh
0x585440: mov [esi+4],eax
0x585443: mov edx,eax
0x585445: mov eax,[edx+4]
0x585448: cmp byte ptr [eax+19h],0
0x58544c: je short 00585438h
0x58544e: mov [esi+4],eax
0x585451: pop edi
0x585452: ret
````

`sub_5853f0` is called by sub_506680, sub_5069d0, sub_584970, sub_584ff0, sub_5f06a0, sub_5f08a0. It calls nothing else.

### sub_585460 at 0x585460 (9 instructions)

````text
0x585460: mov ecx,[eax+8]
0x585463: cmp byte ptr [ecx+19h],0
0x585467: jne short 0058547Bh
0x585469: lea esp,[esp]
0x585470: mov eax,ecx
0x585472: mov ecx,[eax+8]
0x585475: cmp byte ptr [ecx+19h],0
0x585479: je short 00585470h
0x58547b: ret
````

`sub_585460` is called by sub_5069d0, sub_584970, sub_5f08a0. It calls nothing else.

### sub_5859c0 at 0x5859c0 (38 instructions)

````text
0x5859c0: push 0FFFFFFFFh
0x5859c2: push 7551FFh
0x5859c7: mov eax,fs:[0]
0x5859cd: push eax
0x5859ce: push esi
0x5859cf: push edi
0x5859d0: mov eax,ds:[858220h]
0x5859d5: xor eax,esp
0x5859d7: push eax
0x5859d8: lea eax,[esp+0Ch]
0x5859dc: mov fs:[0],eax
0x5859e2: mov esi,[esp+1Ch]
0x5859e6: xor edi,edi
0x5859e8: push edi
0x5859e9: push esi
0x5859ea: call 004DDD40h
0x5859ef: lea ecx,[esi+3Ch]
0x5859f2: mov [esp+14h],edi
0x5859f6: call dword ptr ds:[77DF80h]
0x5859fc: mov [esi+48h],edi
0x5859ff: mov [esi+4Ch],edi
0x585a02: mov [esi+50h],edi
0x585a05: mov [esi+58h],edi
0x585a08: mov [esi+5Ch],edi
0x585a0b: mov [esi+60h],edi
0x585a0e: mov [esi+68h],edi
0x585a11: mov [esi+6Ch],edi
0x585a14: mov [esi+70h],edi
0x585a17: mov [esi+74h],edi
0x585a1a: mov [esi+80h],edi
0x585a20: mov eax,esi
0x585a22: mov ecx,[esp+0Ch]
0x585a26: mov fs:[0],ecx
0x585a2d: pop ecx
0x585a2e: pop edi
0x585a2f: pop esi
0x585a30: add esp,0Ch
0x585a33: ret 4
````

`sub_5859c0` is called by sub_580be0. It delegates to sub_4ddd40 (1 callees).

### sub_585a40 at 0x585a40 (69 instructions)

````text
0x585a40: push 0FFFFFFFFh
0x585a42: push 762525h
0x585a47: mov eax,fs:[0]
0x585a4d: push eax
0x585a4e: push ecx
0x585a4f: push ebx
0x585a50: push esi
0x585a51: push edi
0x585a52: mov eax,ds:[858220h]
0x585a57: xor eax,esp
0x585a59: push eax
0x585a5a: lea eax,[esp+14h]
0x585a5e: mov fs:[0],eax
0x585a64: mov edi,[esp+24h]
0x585a68: mov dword ptr [esp+1Ch],4
0x585a70: mov esi,[edi+80h]
0x585a76: xor ebx,ebx
0x585a78: cmp esi,ebx
0x585a7a: je short 00585A81h
0x585a7c: call 00401080h
0x585a81: push edi
0x585a82: push ecx
0x585a83: call 004DD270h
0x585a88: add esp,4
0x585a8b: mov ecx,eax
0x585a8d: call 004DC780h
0x585a92: mov ecx,[edi+80h]
0x585a98: cmp ecx,ebx
0x585a9a: je short 00585AA4h
0x585a9c: mov eax,[ecx]
0x585a9e: mov edx,[eax]
0x585aa0: push 1
0x585aa2: call edx
0x585aa4: lea esi,[edi+64h]
0x585aa7: call 0058E330h
0x585aac: mov byte ptr [esp+1Ch],2
0x585ab1: mov eax,[edi+58h]
0x585ab4: cmp eax,ebx
0x585ab6: je short 00585AD6h
0x585ab8: mov ecx,[esp+24h]
0x585abc: mov ebx,[edi+5Ch]
0x585abf: push ecx
0x585ac0: call 0044D400h
0x585ac5: mov eax,[edi+58h]
0x585ac8: add esp,4
0x585acb: push eax
0x585acc: call 006516BAh
0x585ad1: add esp,4
0x585ad4: xor ebx,ebx
0x585ad6: mov [edi+58h],ebx
0x585ad9: mov [edi+5Ch],ebx
0x585adc: mov [edi+60h],ebx
0x585adf: lea ebx,[edi+44h]
0x585ae2: mov byte ptr [esp+1Ch],1
0x585ae7: call 00575110h
0x585aec: lea ecx,[edi+3Ch]
0x585aef: mov byte ptr [esp+1Ch],0
0x585af4: call dword ptr ds:[77DF7Ch]
0x585afa: mov ecx,edi
0x585afc: mov dword ptr [esp+1Ch],0FFFFFFFFh
0x585b04: call 004DDE10h
0x585b09: mov ecx,[esp+14h]
0x585b0d: mov fs:[0],ecx
0x585b14: pop ecx
0x585b15: pop edi
0x585b16: pop esi
0x585b17: pop ebx
0x585b18: add esp,10h
0x585b1b: ret 4
````

`sub_585a40` is called by sub_580cc0. It delegates to sub_401080, sub_44d400, sub_4dc780 (8 callees).

### sub_58e330 at 0x58e330 (41 instructions)

````text
0x58e330: push ebx
0x58e331: xor ebx,ebx
0x58e333: cmp [esi+10h],ebx
0x58e336: je short 0058E351h
0x58e338: mov eax,[esi+10h]
0x58e33b: cmp eax,ebx
0x58e33d: je short 0058E34Ch
0x58e33f: add eax,0FFFFFFFFh
0x58e342: cmp eax,ebx
0x58e344: mov [esi+10h],eax
0x58e347: jne short 0058E34Ch
0x58e349: mov [esi+0Ch],ebx
0x58e34c: cmp [esi+10h],ebx
0x58e34f: jne short 0058E338h
0x58e351: push edi
0x58e352: mov edi,[esi+8]
0x58e355: cmp edi,ebx
0x58e357: jbe short 0058E37Dh
0x58e359: lea esp,[esp]
0x58e360: mov eax,[esi+4]
0x58e363: sub edi,1
0x58e366: cmp [eax+edi*4],ebx
0x58e369: lea eax,[eax+edi*4]
0x58e36c: je short 0058E379h
0x58e36e: mov ecx,[eax]
0x58e370: push ecx
0x58e371: call 006516BAh
0x58e376: add esp,4
0x58e379: cmp edi,ebx
0x58e37b: ja short 0058E360h
0x58e37d: mov eax,[esi+4]
0x58e380: cmp eax,ebx
0x58e382: pop edi
0x58e383: je short 0058E38Eh
0x58e385: push eax
0x58e386: call 006516BAh
0x58e38b: add esp,4
0x58e38e: mov [esi+4],ebx
0x58e391: mov [esi+8],ebx
0x58e394: pop ebx
0x58e395: ret
````

`sub_58e330` is called by sub_585a40. It delegates to j_ORDINAL 764 (1 callees).

### sub_5919d0 at 0x5919d0 (39 instructions)

````text
0x5919d0: cmp dword ptr [esi],0
0x5919d3: push edi
0x5919d4: mov edi,ds:[77D0E4h]
0x5919da: jne short 005919DEh
0x5919dc: call edi
0x5919de: mov eax,[esi+4]
0x5919e1: cmp byte ptr [eax+31h],0
0x5919e5: je short 005919EBh
0x5919e7: call edi
0x5919e9: pop edi
0x5919ea: ret
0x5919eb: mov ecx,[eax+8]
0x5919ee: cmp byte ptr [ecx+31h],0
0x5919f2: jne short 00591A0Fh
0x5919f4: mov eax,[ecx]
0x5919f6: cmp byte ptr [eax+31h],0
0x5919fa: jne short 00591A0Ah
0x5919fc: lea esp,[esp]
0x591a00: mov ecx,eax
0x591a02: mov eax,[ecx]
0x591a04: cmp byte ptr [eax+31h],0
0x591a08: je short 00591A00h
0x591a0a: mov [esi+4],ecx
0x591a0d: pop edi
0x591a0e: ret
0x591a0f: mov eax,[eax+4]
0x591a12: cmp byte ptr [eax+31h],0
0x591a16: jne short 00591A2Eh
0x591a18: mov ecx,[esi+4]
0x591a1b: cmp ecx,[eax+8]
0x591a1e: jne short 00591A2Eh
0x591a20: mov [esi+4],eax
0x591a23: mov edx,eax
0x591a25: mov eax,[edx+4]
0x591a28: cmp byte ptr [eax+31h],0
0x591a2c: je short 00591A18h
0x591a2e: mov [esi+4],eax
0x591a31: pop edi
0x591a32: ret
````

`sub_5919d0` is called by sub_5e3990, sub_5e5800. It calls nothing else.

### sub_591fd0 at 0x591fd0 (24 instructions)

````text
0x591fd0: or eax,0FFFFFFFFh
0x591fd3: xor edx,edx
0x591fd5: div ecx
0x591fd7: sub esp,10h
0x591fda: cmp eax,24h
0x591fdd: jae short 0059200Ch
0x591fdf: lea eax,[esp]
0x591fe2: push eax
0x591fe3: lea ecx,[esp+8]
0x591fe7: mov dword ptr [esp+4],0
0x591fef: call dword ptr ds:[77D0DCh]
0x591ff5: push 80A2ACh
0x591ffa: lea ecx,[esp+8]
0x591ffe: push ecx
0x591fff: mov dword ptr [esp+0Ch],78FFD4h
0x592007: call 00652AC4h
0x59200c: lea edx,[ecx+ecx*8]
0x59200f: add edx,edx
0x592011: add edx,edx
0x592013: push edx
0x592014: call 006516C0h
0x592019: add esp,4
0x59201c: add esp,10h
0x59201f: ret
````

`sub_591fd0` is called by sub_50fcb0. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_5af9c0 at 0x5af9c0 (35 instructions)

````text
0x5af9c0: push ebx
0x5af9c1: push ebp
0x5af9c2: push esi
0x5af9c3: mov esi,[esp+10h]
0x5af9c7: xor ebx,ebx
0x5af9c9: cmp [esi+21h],bl
0x5af9cc: push edi
0x5af9cd: mov ebp,ecx
0x5af9cf: mov edi,esi
0x5af9d1: jne short 005AFA09h
0x5af9d3: mov eax,[edi+8]
0x5af9d6: push eax
0x5af9d7: mov ecx,ebp
0x5af9d9: call 005AF9C0h
0x5af9de: mov eax,[esi+14h]
0x5af9e1: cmp eax,ebx
0x5af9e3: mov edi,[edi]
0x5af9e5: je short 005AF9F0h
0x5af9e7: push eax
0x5af9e8: call 006516BAh
0x5af9ed: add esp,4
0x5af9f0: push esi
0x5af9f1: mov [esi+14h],ebx
0x5af9f4: mov [esi+18h],ebx
0x5af9f7: mov [esi+1Ch],ebx
0x5af9fa: call 006516BAh
0x5af9ff: add esp,4
0x5afa02: cmp [edi+21h],bl
0x5afa05: mov esi,edi
0x5afa07: je short 005AF9D3h
0x5afa09: pop edi
0x5afa0a: pop esi
0x5afa0b: pop ebp
0x5afa0c: pop ebx
0x5afa0d: ret 4
````

`sub_5af9c0` is called by sub_5af9c0, sub_5afd00. It delegates to sub_5af9c0, j_ORDINAL 764 (2 callees).

### sub_5afa10 at 0x5afa10 (26 instructions)

````text
0x5afa10: push ebp
0x5afa11: mov ebp,esp
0x5afa13: and esp,0FFFFFFF8h
0x5afa16: sub esp,0Ch
0x5afa19: push edi
0x5afa1a: mov edi,eax
0x5afa1c: mov eax,[edi+4]
0x5afa1f: mov ecx,[eax]
0x5afa21: push eax
0x5afa22: push edi
0x5afa23: push ecx
0x5afa24: push edi
0x5afa25: lea eax,[esp+18h]
0x5afa29: push eax
0x5afa2a: call 005AFD00h
0x5afa2f: mov ecx,[edi+4]
0x5afa32: push ecx
0x5afa33: call 006516BAh
0x5afa38: add esp,4
0x5afa3b: xor eax,eax
0x5afa3d: mov [edi+4],eax
0x5afa40: mov [edi+8],eax
0x5afa43: pop edi
0x5afa44: mov esp,ebp
0x5afa46: pop ebp
0x5afa47: ret
````

`sub_5afa10` is called by sub_609f20. It delegates to sub_5afd00, j_ORDINAL 764 (2 callees).

### sub_5afd00 at 0x5afd00 (72 instructions)

````text
0x5afd00: mov eax,[edi+4]
0x5afd03: sub esp,0Ch
0x5afd06: push ebx
0x5afd07: mov ebx,[esp+18h]
0x5afd0b: test ebx,ebx
0x5afd0d: push ebp
0x5afd0e: push esi
0x5afd0f: mov esi,[eax]
0x5afd11: je short 005AFD17h
0x5afd13: cmp ebx,edi
0x5afd15: je short 005AFD1Dh
0x5afd17: call dword ptr ds:[77D0E4h]
0x5afd1d: mov ebp,[esp+24h]
0x5afd21: cmp ebp,esi
0x5afd23: jne short 005AFD80h
0x5afd25: mov eax,[esp+28h]
0x5afd29: test eax,eax
0x5afd2b: mov esi,[edi+4]
0x5afd2e: je short 005AFD34h
0x5afd30: cmp eax,edi
0x5afd32: je short 005AFD3Ah
0x5afd34: call dword ptr ds:[77D0E4h]
0x5afd3a: cmp [esp+2Ch],esi
0x5afd3e: jne short 005AFD80h
0x5afd40: mov ecx,[edi+4]
0x5afd43: mov edx,[ecx+4]
0x5afd46: push edx
0x5afd47: mov ecx,edi
0x5afd49: call 005AF9C0h
0x5afd4e: mov eax,[edi+4]
0x5afd51: mov [eax+4],eax
0x5afd54: mov eax,[edi+4]
0x5afd57: mov dword ptr [edi+8],0
0x5afd5e: mov [eax],eax
0x5afd60: mov eax,[edi+4]
0x5afd63: mov [eax+8],eax
0x5afd66: mov eax,[edi+4]
0x5afd69: mov ecx,[eax]
0x5afd6b: mov eax,[esp+1Ch]
0x5afd6f: mov [eax+4],ecx
0x5afd72: mov [eax],edi
0x5afd74: pop esi
0x5afd75: pop ebp
0x5afd76: pop ebx
0x5afd77: add esp,0Ch
0x5afd7a: ret 14h
0x5afd80: test ebx,ebx
0x5afd82: je short 005AFD8Ah
0x5afd84: cmp ebx,[esp+28h]
0x5afd88: je short 005AFD90h
0x5afd8a: call dword ptr ds:[77D0E4h]
0x5afd90: cmp ebp,[esp+2Ch]
0x5afd94: je short 005AFDB6h
0x5afd96: lea esi,[esp+20h]
0x5afd9a: call 00415E60h
0x5afd9f: push ebp
0x5afda0: push ebx
0x5afda1: lea edx,[esp+18h]
0x5afda5: push edx
0x5afda6: push edi
0x5afda7: call 005B0180h
0x5afdac: mov ebp,[esp+24h]
0x5afdb0: mov ebx,[esp+20h]
0x5afdb4: jmp short 005AFD80h
0x5afdb6: mov eax,[esp+1Ch]
0x5afdba: pop esi
0x5afdbb: mov [eax+4],ebp
0x5afdbe: pop ebp
0x5afdbf: mov [eax],ebx
0x5afdc1: pop ebx
0x5afdc2: add esp,0Ch
0x5afdc5: ret 14h
````

`sub_5afd00` is called by sub_5afa10. It delegates to sub_415e60, sub_5af9c0, sub_5b0180 (3 callees).

### sub_5b0180 at 0x5b0180 (254 instructions)

````text
0x5b0180: push 0FFFFFFFFh
0x5b0182: push 7410D9h
0x5b0187: mov eax,fs:[0]
0x5b018d: push eax
0x5b018e: sub esp,44h
0x5b0191: push ebx
0x5b0192: push ebp
0x5b0193: push esi
0x5b0194: push edi
0x5b0195: mov eax,ds:[858220h]
0x5b019a: xor eax,esp
0x5b019c: push eax
0x5b019d: lea eax,[esp+58h]
0x5b01a1: mov fs:[0],eax
0x5b01a7: mov eax,[esp+74h]
0x5b01ab: cmp byte ptr [eax+21h],0
0x5b01af: je short 005B01EDh
0x5b01b1: push 7C5AECh
0x5b01b6: lea ecx,[esp+18h]
0x5b01ba: call dword ptr ds:[77CD7Ch]
0x5b01c0: lea eax,[esp+14h]
0x5b01c4: push eax
0x5b01c5: lea ecx,[esp+34h]
0x5b01c9: mov dword ptr [esp+64h],0
0x5b01d1: call 00401230h
0x5b01d6: push 80A4F8h
0x5b01db: lea ecx,[esp+34h]
0x5b01df: push ecx
0x5b01e0: mov dword ptr [esp+38h],790F90h
0x5b01e8: call 00652AC4h
0x5b01ed: lea esi,[esp+70h]
0x5b01f1: mov ebp,eax
0x5b01f3: call 00415E60h
0x5b01f8: mov eax,[ebp]
0x5b01fb: cmp byte ptr [eax+21h],0
0x5b01ff: je short 005B0206h
0x5b0201: mov edi,[ebp+8]
0x5b0204: jmp short 005B021Eh
0x5b0206: mov edx,[ebp+8]
0x5b0209: cmp byte ptr [edx+21h],0
0x5b020d: je short 005B0213h
0x5b020f: mov edi,eax
0x5b0211: jmp short 005B021Eh
0x5b0213: mov ecx,[esp+74h]
0x5b0217: cmp ecx,ebp
0x5b0219: mov edi,[ecx+8]
0x5b021c: jne short 005B0292h
0x5b021e: cmp byte ptr [edi+21h],0
0x5b0222: mov esi,[ebp+4]
0x5b0225: jne short 005B022Ah
0x5b0227: mov [edi+4],esi
0x5b022a: mov ecx,[esp+68h]
0x5b022e: mov eax,[ecx+4]
0x5b0231: cmp [eax+4],ebp
0x5b0234: jne short 005B023Bh
0x5b0236: mov [eax+4],edi
0x5b0239: jmp short 005B0246h
0x5b023b: cmp [esi],ebp
0x5b023d: jne short 005B0243h
0x5b023f: mov [esi],edi
0x5b0241: jmp short 005B0246h
0x5b0243: mov [esi+8],edi
0x5b0246: mov edx,[ecx+4]
0x5b0249: cmp [edx],ebp
0x5b024b: jne short 005B026Dh
0x5b024d: cmp byte ptr [edi+21h],0
0x5b0251: je short 005B0257h
0x5b0253: mov ecx,esi
0x5b0255: jmp short 005B026Bh
0x5b0257: mov eax,[edi]
0x5b0259: cmp byte ptr [eax+21h],0
0x5b025d: mov ecx,edi
0x5b025f: jne short 005B026Bh
0x5b0261: mov ecx,eax
0x5b0263: mov eax,[ecx]
0x5b0265: cmp byte ptr [eax+21h],0
0x5b0269: je short 005B0261h
0x5b026b: mov [edx],ecx
0x5b026d: mov eax,[esp+68h]
0x5b0271: mov ebx,[eax+4]
0x5b0274: cmp [ebx+8],ebp
0x5b0277: jne short 005B02EEh
0x5b0279: cmp byte ptr [edi+21h],0
0x5b027d: je short 005B0286h
0x5b027f: mov eax,esi
0x5b0281: mov [ebx+8],eax
0x5b0284: jmp short 005B02EEh
0x5b0286: mov eax,edi
0x5b0288: call 005B0480h
0x5b028d: mov [ebx+8],eax
0x5b0290: jmp short 005B02EEh
0x5b0292: mov [eax+4],ecx
0x5b0295: mov edx,[ebp]
0x5b0298: mov [ecx],edx
0x5b029a: cmp ecx,[ebp+8]
0x5b029d: jne short 005B02A3h
0x5b029f: mov esi,ecx
0x5b02a1: jmp short 005B02BDh
0x5b02a3: cmp byte ptr [edi+21h],0
0x5b02a7: mov esi,[ecx+4]
0x5b02aa: jne short 005B02AFh
0x5b02ac: mov [edi+4],esi
0x5b02af: mov [esi],edi
0x5b02b1: mov eax,[ebp+8]
0x5b02b4: mov [ecx+8],eax
0x5b02b7: mov edx,[ebp+8]
0x5b02ba: mov [edx+4],ecx
0x5b02bd: mov eax,[esp+68h]
0x5b02c1: mov eax,[eax+4]
0x5b02c4: cmp [eax+4],ebp
0x5b02c7: jne short 005B02CEh
0x5b02c9: mov [eax+4],ecx
0x5b02cc: jmp short 005B02DCh
0x5b02ce: mov eax,[ebp+4]
0x5b02d1: cmp [eax],ebp
0x5b02d3: jne short 005B02D9h
0x5b02d5: mov [eax],ecx
0x5b02d7: jmp short 005B02DCh
0x5b02d9: mov [eax+8],ecx
0x5b02dc: mov edx,[ebp+4]
0x5b02df: mov [ecx+4],edx
0x5b02e2: mov dl,[ebp+20h]
0x5b02e5: mov al,[ecx+20h]
0x5b02e8: mov [ecx+20h],dl
0x5b02eb: mov [ebp+20h],al
0x5b02ee: mov bl,1
0x5b02f0: cmp [ebp+20h],bl
0x5b02f3: jne near ptr 005B041Ah
0x5b02f9: mov eax,[esp+68h]
0x5b02fd: mov ecx,[eax+4]
0x5b0300: cmp edi,[ecx+4]
0x5b0303: je near ptr 005B0417h
0x5b0309: lea esp,[esp]
0x5b0310: cmp [edi+20h],bl
0x5b0313: jne near ptr 005B0417h
0x5b0319: mov ecx,[esi]
0x5b031b: cmp edi,ecx
0x5b031d: jne short 005B0395h
0x5b031f: mov ecx,[esi+8]
0x5b0322: cmp byte ptr [ecx+20h],0
0x5b0326: jne short 005B033Eh
0x5b0328: mov edx,[esp+68h]
0x5b032c: mov [ecx+20h],bl
0x5b032f: push edx
0x5b0330: mov ecx,esi
0x5b0332: mov byte ptr [esi+20h],0
0x5b0336: call 005484D0h
0x5b033b: mov ecx,[esi+8]
0x5b033e: cmp byte ptr [ecx+21h],0
0x5b0342: jne near ptr 005B03C9h
0x5b0348: mov eax,[ecx]
0x5b034a: cmp [eax+20h],bl
0x5b034d: jne short 005B0357h
0x5b034f: mov edx,[ecx+8]
0x5b0352: cmp [edx+20h],bl
0x5b0355: je short 005B03C5h
0x5b0357: mov eax,[ecx+8]
0x5b035a: cmp [eax+20h],bl
0x5b035d: jne short 005B0375h
0x5b035f: mov edx,[ecx]
0x5b0361: mov eax,[esp+68h]
0x5b0365: mov [edx+20h],bl
0x5b0368: push eax
0x5b0369: mov byte ptr [ecx+20h],0
0x5b036d: call 0050F8B0h
0x5b0372: mov ecx,[esi+8]
0x5b0375: mov dl,[esi+20h]
0x5b0378: mov [ecx+20h],dl
0x5b037b: mov [esi+20h],bl
0x5b037e: mov eax,[ecx+8]
0x5b0381: mov ecx,[esp+68h]
0x5b0385: push ecx
0x5b0386: mov ecx,esi
0x5b0388: mov [eax+20h],bl
0x5b038b: call 005484D0h
0x5b0390: jmp near ptr 005B0417h
0x5b0395: cmp byte ptr [ecx+20h],0
0x5b0399: jne short 005B03B0h
0x5b039b: mov eax,[esp+68h]
0x5b039f: mov [ecx+20h],bl
0x5b03a2: push eax
0x5b03a3: mov ecx,esi
0x5b03a5: mov byte ptr [esi+20h],0
0x5b03a9: call 0050F8B0h
0x5b03ae: mov ecx,[esi]
0x5b03b0: cmp byte ptr [ecx+21h],0
0x5b03b4: jne short 005B03C9h
0x5b03b6: mov edx,[ecx+8]
0x5b03b9: cmp [edx+20h],bl
0x5b03bc: jne short 005B03E0h
0x5b03be: mov eax,[ecx]
0x5b03c0: cmp [eax+20h],bl
0x5b03c3: jne short 005B03E0h
0x5b03c5: mov byte ptr [ecx+20h],0
0x5b03c9: mov ecx,[esp+68h]
0x5b03cd: mov edx,[ecx+4]
0x5b03d0: mov edi,esi
0x5b03d2: cmp edi,[edx+4]
0x5b03d5: mov esi,[esi+4]
0x5b03d8: jne near ptr 005B0310h
0x5b03de: jmp short 005B0417h
0x5b03e0: mov edx,[ecx]
0x5b03e2: cmp [edx+20h],bl
0x5b03e5: jne short 005B03FDh
0x5b03e7: mov eax,[ecx+8]
0x5b03ea: mov edx,[esp+68h]
0x5b03ee: mov [eax+20h],bl
0x5b03f1: push edx
0x5b03f2: mov byte ptr [ecx+20h],0
0x5b03f6: call 005484D0h
0x5b03fb: mov ecx,[esi]
0x5b03fd: mov al,[esi+20h]
0x5b0400: mov edx,[esp+68h]
0x5b0404: mov [ecx+20h],al
0x5b0407: mov [esi+20h],bl
0x5b040a: mov ecx,[ecx]
0x5b040c: mov [ecx+20h],bl
0x5b040f: push edx
0x5b0410: mov ecx,esi
0x5b0412: call 0050F8B0h
0x5b0417: mov [edi+20h],bl
0x5b041a: mov eax,[ebp+14h]
0x5b041d: xor esi,esi
0x5b041f: cmp eax,esi
0x5b0421: je short 005B042Ch
0x5b0423: push eax
0x5b0424: call 006516BAh
0x5b0429: add esp,4
0x5b042c: push ebp
0x5b042d: mov [ebp+14h],esi
0x5b0430: mov [ebp+18h],esi
0x5b0433: mov [ebp+1Ch],esi
0x5b0436: call 006516BAh
0x5b043b: mov ecx,[esp+6Ch]
0x5b043f: mov eax,[ecx+8]
0x5b0442: add esp,4
0x5b0445: cmp eax,esi
0x5b0447: jbe short 005B044Fh
0x5b0449: add eax,0FFFFFFFFh
0x5b044c: mov [ecx+8],eax
0x5b044f: mov eax,[esp+6Ch]
0x5b0453: mov ecx,[esp+70h]
0x5b0457: mov edx,[esp+74h]
0x5b045b: mov [eax],ecx
0x5b045d: mov [eax+4],edx
0x5b0460: mov ecx,[esp+58h]
0x5b0464: mov fs:[0],ecx
0x5b046b: pop ecx
0x5b046c: pop edi
0x5b046d: pop esi
0x5b046e: pop ebp
0x5b046f: pop ebx
0x5b0470: add esp,50h
0x5b0473: ret 10h
````

`sub_5b0180` is called by sub_5afd00. It delegates to sub_401230, sub_415e60, sub_50f8b0 (7 callees).

### sub_5b0480 at 0x5b0480 (9 instructions)

````text
0x5b0480: mov ecx,[eax+8]
0x5b0483: cmp byte ptr [ecx+21h],0
0x5b0487: jne short 005B049Bh
0x5b0489: lea esp,[esp]
0x5b0490: mov eax,ecx
0x5b0492: mov ecx,[eax+8]
0x5b0495: cmp byte ptr [ecx+21h],0
0x5b0499: je short 005B0490h
0x5b049b: ret
````

`sub_5b0480` is called by sub_5b0180, sub_627940. It calls nothing else.

### sub_5c2e10 at 0x5c2e10 (30 instructions)

````text
0x5c2e10: push 0FFFFFFFFh
0x5c2e12: push 750535h
0x5c2e17: mov eax,fs:[0]
0x5c2e1d: push eax
0x5c2e1e: mov eax,ds:[858220h]
0x5c2e23: xor eax,esp
0x5c2e25: push eax
0x5c2e26: lea eax,[esp+4]
0x5c2e2a: mov fs:[0],eax
0x5c2e30: call 005C5920h
0x5c2e35: mov ds:[8749B4h],eax
0x5c2e3a: mov byte ptr [eax+69h],1
0x5c2e3e: mov eax,ds:[8749B4h]
0x5c2e43: mov [eax+4],eax
0x5c2e46: mov eax,ds:[8749B4h]
0x5c2e4b: mov [eax],eax
0x5c2e4d: mov eax,ds:[8749B4h]
0x5c2e52: mov [eax+8],eax
0x5c2e55: xor eax,eax
0x5c2e57: mov ds:[8749B8h],eax
0x5c2e5c: mov ecx,8749BCh
0x5c2e61: mov [esp+0Ch],eax
0x5c2e65: call dword ptr ds:[77DF80h]
0x5c2e6b: mov byte ptr ds:[8749C4h],1
0x5c2e72: mov eax,8749B0h
0x5c2e77: mov ecx,[esp+4]
0x5c2e7b: mov fs:[0],ecx
0x5c2e82: pop ecx
0x5c2e83: add esp,0Ch
0x5c2e86: ret
````

`sub_5c2e10` is called by ?get_mutable_instance@?$singleton@VComboSymbol@@@serialization@boost@@SAAAVComboSymbol@@XZ, ?get_instance@?$singleton@VComboSymbol@@@serialization@boost@@CAAAVComboSymbol@@XZ. It delegates to sub_5c5920 (1 callees).

### ?get_mutable_instance@?$singleton@VComboSymbol@@@serialization@boost@@SAAAVComboSymbol@@XZ at 0x5c4e00 (25 instructions)

````text
0x5c4e00: jmp near ptr 005C51D0h
0x5c51d0: push 0FFFFFFFFh
0x5c51d2: push 75913Eh
0x5c51d7: mov eax,fs:[0]
0x5c51dd: push eax
0x5c51de: mov eax,ds:[858220h]
0x5c51e3: xor eax,esp
0x5c51e5: push eax
0x5c51e6: lea eax,[esp+4]
0x5c51ea: mov fs:[0],eax
0x5c51f0: mov eax,1
0x5c51f5: test ds:[875F34h],al
0x5c51fb: jne short 005C521Dh
0x5c51fd: or ds:[875F34h],eax
0x5c5203: mov dword ptr [esp+0Ch],0
0x5c520b: call 005C2E10h
0x5c5210: push 77B3D0h
0x5c5215: call 006527EDh
0x5c521a: add esp,4
0x5c521d: mov eax,8749B0h
0x5c5222: mov ecx,[esp+4]
0x5c5226: mov fs:[0],ecx
0x5c522d: pop ecx
0x5c522e: add esp,0Ch
0x5c5231: ret
````

`?get_mutable_instance@?$singleton@VComboSymbol@@@serialization@boost@@SAAAVComboSymbol@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5c2e10, sub_6527ed (2 callees).

### sub_5c4e10 at 0x5c4e10 (42 instructions)

````text
0x5c4e10: push 0FFFFFFFFh
0x5c4e12: push 74463Ah
0x5c4e17: mov eax,fs:[0]
0x5c4e1d: push eax
0x5c4e1e: push esi
0x5c4e1f: push edi
0x5c4e20: mov eax,ds:[858220h]
0x5c4e25: xor eax,esp
0x5c4e27: push eax
0x5c4e28: lea eax,[esp+0Ch]
0x5c4e2c: mov fs:[0],eax
0x5c4e32: mov edi,[esp+1Ch]
0x5c4e36: mov dword ptr [esp+14h],0
0x5c4e3e: mov esi,[edi+58h]
0x5c4e41: test esi,esi
0x5c4e43: je short 005C4E6Fh
0x5c4e45: lea eax,[esi+4]
0x5c4e48: or ecx,0FFFFFFFFh
0x5c4e4b: lock xadd [eax],ecx
0x5c4e4f: jne short 005C4E6Fh
0x5c4e51: mov edx,[esi]
0x5c4e53: mov eax,[edx+4]
0x5c4e56: mov ecx,esi
0x5c4e58: call eax
0x5c4e5a: lea ecx,[esi+8]
0x5c4e5d: or edx,0FFFFFFFFh
0x5c4e60: lock xadd [ecx],edx
0x5c4e64: jne short 005C4E6Fh
0x5c4e66: mov eax,[esi]
0x5c4e68: mov edx,[eax+8]
0x5c4e6b: mov ecx,esi
0x5c4e6d: call edx
0x5c4e6f: push edi
0x5c4e70: mov dword ptr [esp+18h],0FFFFFFFFh
0x5c4e78: call 00407C40h
0x5c4e7d: mov ecx,[esp+0Ch]
0x5c4e81: mov fs:[0],ecx
0x5c4e88: pop ecx
0x5c4e89: pop edi
0x5c4e8a: pop esi
0x5c4e8b: add esp,0Ch
0x5c4e8e: ret 4
````

`sub_5c4e10` is called by sub_5c5310, sub_5c5820. It delegates to sub_407c40 (1 callees).

### sub_5c50c0 at 0x5c50c0 (64 instructions)

````text
0x5c50c0: mov eax,ds:[8749B4h]
0x5c50c5: sub esp,8
0x5c50c8: push ebx
0x5c50c9: push ebp
0x5c50ca: push esi
0x5c50cb: mov esi,[esp+1Ch]
0x5c50cf: test esi,esi
0x5c50d1: push edi
0x5c50d2: mov edi,[eax]
0x5c50d4: je short 005C50DEh
0x5c50d6: cmp esi,8749B0h
0x5c50dc: je short 005C50E4h
0x5c50de: call dword ptr ds:[77D0E4h]
0x5c50e4: mov ebx,[esp+24h]
0x5c50e8: cmp ebx,edi
0x5c50ea: mov ebp,[esp+28h]
0x5c50ee: jne short 005C5132h
0x5c50f0: test ebp,ebp
0x5c50f2: mov edi,ds:[8749B4h]
0x5c50f8: je short 005C5102h
0x5c50fa: cmp ebp,8749B0h
0x5c5100: je short 005C5108h
0x5c5102: call dword ptr ds:[77D0E4h]
0x5c5108: cmp [esp+2Ch],edi
0x5c510c: jne short 005C5132h
0x5c510e: call 005C5600h
0x5c5113: mov ecx,ds:[8749B4h]
0x5c5119: mov eax,[esp+1Ch]
0x5c511d: mov edx,[ecx]
0x5c511f: mov [eax+4],edx
0x5c5122: mov dword ptr [eax],8749B0h
0x5c5128: pop edi
0x5c5129: pop esi
0x5c512a: pop ebp
0x5c512b: pop ebx
0x5c512c: add esp,8
0x5c512f: ret 14h
0x5c5132: test esi,esi
0x5c5134: je short 005C513Ah
0x5c5136: cmp esi,ebp
0x5c5138: je short 005C5140h
0x5c513a: call dword ptr ds:[77D0E4h]
0x5c5140: cmp ebx,[esp+2Ch]
0x5c5144: je short 005C5167h
0x5c5146: mov edi,esi
0x5c5148: lea esi,[esp+20h]
0x5c514c: call 005C5AB0h
0x5c5151: push ebx
0x5c5152: push edi
0x5c5153: lea eax,[esp+18h]
0x5c5157: push eax
0x5c5158: call 005C5310h
0x5c515d: mov ebx,[esp+24h]
0x5c5161: mov esi,[esp+20h]
0x5c5165: jmp short 005C5132h
0x5c5167: mov eax,[esp+1Ch]
0x5c516b: pop edi
0x5c516c: mov [eax],esi
0x5c516e: pop esi
0x5c516f: pop ebp
0x5c5170: mov [eax+4],ebx
0x5c5173: pop ebx
0x5c5174: add esp,8
0x5c5177: ret 14h
````

`sub_5c50c0` is called by sub_5c5180. It delegates to sub_5c5310, sub_5c5600, sub_5c5ab0 (3 callees).

### sub_5c5180 at 0x5c5180 (27 instructions)

````text
0x5c5180: push ebp
0x5c5181: mov ebp,esp
0x5c5183: and esp,0FFFFFFF8h
0x5c5186: mov eax,ds:[8749B4h]
0x5c518b: mov edx,[eax]
0x5c518d: sub esp,0Ch
0x5c5190: push esi
0x5c5191: push eax
0x5c5192: mov ecx,8749B0h
0x5c5197: push ecx
0x5c5198: push edx
0x5c5199: mov esi,ecx
0x5c519b: push esi
0x5c519c: lea eax,[esp+18h]
0x5c51a0: push eax
0x5c51a1: call 005C50C0h
0x5c51a6: mov ecx,ds:[8749B4h]
0x5c51ac: push ecx
0x5c51ad: call 006516BAh
0x5c51b2: add esp,4
0x5c51b5: xor eax,eax
0x5c51b7: mov ds:[8749B4h],eax
0x5c51bc: mov ds:[8749B8h],eax
0x5c51c1: pop esi
0x5c51c2: mov esp,ebp
0x5c51c4: pop ebp
0x5c51c5: ret
````

`sub_5c5180` is called by sub_77b3d0. It delegates to sub_5c50c0, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@VComboSymbol@@@serialization@boost@@CAAAVComboSymbol@@XZ at 0x5c51d0 (24 instructions)

````text
0x5c51d0: push 0FFFFFFFFh
0x5c51d2: push 75913Eh
0x5c51d7: mov eax,fs:[0]
0x5c51dd: push eax
0x5c51de: mov eax,ds:[858220h]
0x5c51e3: xor eax,esp
0x5c51e5: push eax
0x5c51e6: lea eax,[esp+4]
0x5c51ea: mov fs:[0],eax
0x5c51f0: mov eax,1
0x5c51f5: test ds:[875F34h],al
0x5c51fb: jne short 005C521Dh
0x5c51fd: or ds:[875F34h],eax
0x5c5203: mov dword ptr [esp+0Ch],0
0x5c520b: call 005C2E10h
0x5c5210: push 77B3D0h
0x5c5215: call 006527EDh
0x5c521a: add esp,4
0x5c521d: mov eax,8749B0h
0x5c5222: mov ecx,[esp+4]
0x5c5226: mov fs:[0],ecx
0x5c522d: pop ecx
0x5c522e: add esp,0Ch
0x5c5231: ret
````

`?get_instance@?$singleton@VComboSymbol@@@serialization@boost@@CAAAVComboSymbol@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5c2e10, sub_6527ed (2 callees).

### sub_5c5310 at 0x5c5310 (234 instructions)

````text
0x5c5310: push 0FFFFFFFFh
0x5c5312: push 740349h
0x5c5317: mov eax,fs:[0]
0x5c531d: push eax
0x5c531e: sub esp,48h
0x5c5321: push ebx
0x5c5322: push ebp
0x5c5323: push esi
0x5c5324: push edi
0x5c5325: mov eax,ds:[858220h]
0x5c532a: xor eax,esp
0x5c532c: push eax
0x5c532d: lea eax,[esp+5Ch]
0x5c5331: mov fs:[0],eax
0x5c5337: mov eax,[esp+74h]
0x5c533b: cmp byte ptr [eax+69h],0
0x5c533f: je short 005C537Dh
0x5c5341: push 7C5AECh
0x5c5346: lea ecx,[esp+18h]
0x5c534a: call dword ptr ds:[77CD7Ch]
0x5c5350: lea eax,[esp+14h]
0x5c5354: push eax
0x5c5355: lea ecx,[esp+34h]
0x5c5359: mov dword ptr [esp+68h],0
0x5c5361: call 00401230h
0x5c5366: push 80A4F8h
0x5c536b: lea ecx,[esp+34h]
0x5c536f: push ecx
0x5c5370: mov dword ptr [esp+38h],790F90h
0x5c5378: call 00652AC4h
0x5c537d: lea esi,[esp+70h]
0x5c5381: mov ebp,eax
0x5c5383: call 005C5AB0h
0x5c5388: mov eax,[ebp]
0x5c538b: cmp byte ptr [eax+69h],0
0x5c538f: je short 005C5396h
0x5c5391: mov edi,[ebp+8]
0x5c5394: jmp short 005C53AEh
0x5c5396: mov edx,[ebp+8]
0x5c5399: cmp byte ptr [edx+69h],0
0x5c539d: je short 005C53A3h
0x5c539f: mov edi,eax
0x5c53a1: jmp short 005C53AEh
0x5c53a3: mov ecx,[esp+74h]
0x5c53a7: cmp ecx,ebp
0x5c53a9: mov edi,[ecx+8]
0x5c53ac: jne short 005C542Dh
0x5c53ae: cmp byte ptr [edi+69h],0
0x5c53b2: mov esi,[ebp+4]
0x5c53b5: jne short 005C53BAh
0x5c53b7: mov [edi+4],esi
0x5c53ba: mov eax,ds:[8749B4h]
0x5c53bf: cmp [eax+4],ebp
0x5c53c2: jne short 005C53C9h
0x5c53c4: mov [eax+4],edi
0x5c53c7: jmp short 005C53D4h
0x5c53c9: cmp [esi],ebp
0x5c53cb: jne short 005C53D1h
0x5c53cd: mov [esi],edi
0x5c53cf: jmp short 005C53D4h
0x5c53d1: mov [esi+8],edi
0x5c53d4: mov edx,ds:[8749B4h]
0x5c53da: cmp [edx],ebp
0x5c53dc: jne short 005C53FEh
0x5c53de: cmp byte ptr [edi+69h],0
0x5c53e2: je short 005C53E8h
0x5c53e4: mov ecx,esi
0x5c53e6: jmp short 005C53FCh
0x5c53e8: mov eax,[edi]
0x5c53ea: cmp byte ptr [eax+69h],0
0x5c53ee: mov ecx,edi
0x5c53f0: jne short 005C53FCh
0x5c53f2: mov ecx,eax
0x5c53f4: mov eax,[ecx]
0x5c53f6: cmp byte ptr [eax+69h],0
0x5c53fa: je short 005C53F2h
0x5c53fc: mov [edx],ecx
0x5c53fe: mov eax,ds:[8749B4h]
0x5c5403: cmp [eax+8],ebp
0x5c5406: jne short 005C5487h
0x5c5408: cmp byte ptr [edi+69h],0
0x5c540c: je short 005C541Bh
0x5c540e: mov ecx,ds:[8749B4h]
0x5c5414: mov eax,esi
0x5c5416: mov [ecx+8],eax
0x5c5419: jmp short 005C5487h
0x5c541b: mov eax,edi
0x5c541d: call 005C58B0h
0x5c5422: mov ecx,ds:[8749B4h]
0x5c5428: mov [ecx+8],eax
0x5c542b: jmp short 005C5487h
0x5c542d: mov [eax+4],ecx
0x5c5430: mov edx,[ebp]
0x5c5433: mov [ecx],edx
0x5c5435: cmp ecx,[ebp+8]
0x5c5438: jne short 005C543Eh
0x5c543a: mov esi,ecx
0x5c543c: jmp short 005C5458h
0x5c543e: cmp byte ptr [edi+69h],0
0x5c5442: mov esi,[ecx+4]
0x5c5445: jne short 005C544Ah
0x5c5447: mov [edi+4],esi
0x5c544a: mov [esi],edi
0x5c544c: mov eax,[ebp+8]
0x5c544f: mov [ecx+8],eax
0x5c5452: mov edx,[ebp+8]
0x5c5455: mov [edx+4],ecx
0x5c5458: mov eax,ds:[8749B4h]
0x5c545d: cmp [eax+4],ebp
0x5c5460: jne short 005C5467h
0x5c5462: mov [eax+4],ecx
0x5c5465: jmp short 005C5475h
0x5c5467: mov eax,[ebp+4]
0x5c546a: cmp [eax],ebp
0x5c546c: jne short 005C5472h
0x5c546e: mov [eax],ecx
0x5c5470: jmp short 005C5475h
0x5c5472: mov [eax+8],ecx
0x5c5475: mov eax,[ebp+4]
0x5c5478: mov [ecx+4],eax
0x5c547b: mov dl,[ebp+68h]
0x5c547e: mov al,[ecx+68h]
0x5c5481: mov [ecx+68h],dl
0x5c5484: mov [ebp+68h],al
0x5c5487: mov ebx,1
0x5c548c: cmp [ebp+68h],bl
0x5c548f: jne near ptr 005C55ACh
0x5c5495: mov eax,ds:[8749B4h]
0x5c549a: cmp edi,[eax+4]
0x5c549d: je near ptr 005C55A9h
0x5c54a3: cmp [edi+68h],bl
0x5c54a6: jne near ptr 005C55A9h
0x5c54ac: mov ecx,[esi]
0x5c54ae: cmp edi,ecx
0x5c54b0: jne short 005C5528h
0x5c54b2: mov ecx,[esi+8]
0x5c54b5: cmp byte ptr [ecx+68h],0
0x5c54b9: jne short 005C54D1h
0x5c54bb: mov [ecx+68h],bl
0x5c54be: push 8749B0h
0x5c54c3: mov ecx,esi
0x5c54c5: mov byte ptr [esi+68h],0
0x5c54c9: call 005C5860h
0x5c54ce: mov ecx,[esi+8]
0x5c54d1: cmp byte ptr [ecx+69h],0
0x5c54d5: jne near ptr 005C555Ch
0x5c54db: mov edx,[ecx]
0x5c54dd: cmp [edx+68h],bl
0x5c54e0: jne short 005C54EAh
0x5c54e2: mov eax,[ecx+8]
0x5c54e5: cmp [eax+68h],bl
0x5c54e8: je short 005C5558h
0x5c54ea: mov edx,[ecx+8]
0x5c54ed: cmp [edx+68h],bl
0x5c54f0: jne short 005C5508h
0x5c54f2: mov eax,[ecx]
0x5c54f4: mov [eax+68h],bl
0x5c54f7: push 8749B0h
0x5c54fc: mov byte ptr [ecx+68h],0
0x5c5500: call 005C58D0h
0x5c5505: mov ecx,[esi+8]
0x5c5508: mov dl,[esi+68h]
0x5c550b: mov [ecx+68h],dl
0x5c550e: mov [esi+68h],bl
0x5c5511: mov eax,[ecx+8]
0x5c5514: push 8749B0h
0x5c5519: mov ecx,esi
0x5c551b: mov [eax+68h],bl
0x5c551e: call 005C5860h
0x5c5523: jmp near ptr 005C55A9h
0x5c5528: cmp byte ptr [ecx+68h],0
0x5c552c: jne short 005C5543h
0x5c552e: mov [ecx+68h],bl
0x5c5531: push 8749B0h
0x5c5536: mov ecx,esi
0x5c5538: mov byte ptr [esi+68h],0
0x5c553c: call 005C58D0h
0x5c5541: mov ecx,[esi]
0x5c5543: cmp byte ptr [ecx+69h],0
0x5c5547: jne short 005C555Ch
0x5c5549: mov edx,[ecx+8]
0x5c554c: cmp [edx+68h],bl
0x5c554f: jne short 005C5572h
0x5c5551: mov eax,[ecx]
0x5c5553: cmp [eax+68h],bl
0x5c5556: jne short 005C5572h
0x5c5558: mov byte ptr [ecx+68h],0
0x5c555c: mov ecx,ds:[8749B4h]
0x5c5562: mov edi,esi
0x5c5564: cmp edi,[ecx+4]
0x5c5567: mov esi,[esi+4]
0x5c556a: jne near ptr 005C54A3h
0x5c5570: jmp short 005C55A9h
0x5c5572: mov edx,[ecx]
0x5c5574: cmp [edx+68h],bl
0x5c5577: jne short 005C558Fh
0x5c5579: mov eax,[ecx+8]
0x5c557c: mov [eax+68h],bl
0x5c557f: push 8749B0h
0x5c5584: mov byte ptr [ecx+68h],0
0x5c5588: call 005C5860h
0x5c558d: mov ecx,[esi]
0x5c558f: mov dl,[esi+68h]
0x5c5592: mov [ecx+68h],dl
0x5c5595: mov [esi+68h],bl
0x5c5598: mov eax,[ecx]
0x5c559a: push 8749B0h
0x5c559f: mov ecx,esi
0x5c55a1: mov [eax+68h],bl
0x5c55a4: call 005C58D0h
0x5c55a9: mov [edi+68h],bl
0x5c55ac: lea ecx,[ebp+0Ch]
0x5c55af: push ecx
0x5c55b0: call 005C4E10h
0x5c55b5: push ebp
0x5c55b6: call 006516BAh
0x5c55bb: add esp,4
0x5c55be: cmp dword ptr ds:[8749B8h],0
0x5c55c5: jbe short 005C55CDh
0x5c55c7: sub ds:[8749B8h],ebx
0x5c55cd: mov eax,[esp+6Ch]
0x5c55d1: mov edx,[esp+70h]
0x5c55d5: mov ecx,[esp+74h]
0x5c55d9: mov [eax],edx
0x5c55db: mov [eax+4],ecx
0x5c55de: mov ecx,[esp+5Ch]
0x5c55e2: mov fs:[0],ecx
0x5c55e9: pop ecx
0x5c55ea: pop edi
0x5c55eb: pop esi
0x5c55ec: pop ebp
0x5c55ed: pop ebx
0x5c55ee: add esp,54h
0x5c55f1: ret 0Ch
````

`sub_5c5310` is called by sub_5c50c0. It delegates to sub_401230, sub_5c4e10, sub_5c5860 (8 callees).

### sub_5c5600 at 0x5c5600 (13 instructions)

````text
0x5c5600: mov eax,ds:[8749B4h]
0x5c5605: mov ecx,[eax+4]
0x5c5608: push ecx
0x5c5609: mov ecx,8749B0h
0x5c560e: call 005C5820h
0x5c5613: mov eax,ds:[8749B4h]
0x5c5618: mov [eax+4],eax
0x5c561b: mov eax,ds:[8749B4h]
0x5c5620: mov dword ptr ds:[8749B8h],0
0x5c562a: mov [eax],eax
0x5c562c: mov eax,ds:[8749B4h]
0x5c5631: mov [eax+8],eax
0x5c5634: ret
````

`sub_5c5600` is called by sub_5c50c0. It delegates to sub_5c5820 (1 callees).

### sub_5c5820 at 0x5c5820 (26 instructions)

````text
0x5c5820: push ebx
0x5c5821: push esi
0x5c5822: push edi
0x5c5823: mov edi,[esp+10h]
0x5c5827: cmp byte ptr [edi+69h],0
0x5c582b: mov ebx,ecx
0x5c582d: mov esi,edi
0x5c582f: jne short 005C5858h
0x5c5831: mov eax,[esi+8]
0x5c5834: push eax
0x5c5835: mov ecx,ebx
0x5c5837: call 005C5820h
0x5c583c: mov esi,[esi]
0x5c583e: lea ecx,[edi+0Ch]
0x5c5841: push ecx
0x5c5842: call 005C4E10h
0x5c5847: push edi
0x5c5848: call 006516BAh
0x5c584d: add esp,4
0x5c5850: cmp byte ptr [esi+69h],0
0x5c5854: mov edi,esi
0x5c5856: je short 005C5831h
0x5c5858: pop edi
0x5c5859: pop esi
0x5c585a: pop ebx
0x5c585b: ret 4
````

`sub_5c5820` is called by sub_5c5600, sub_5c5820. It delegates to sub_5c4e10, sub_5c5820, j_ORDINAL 764 (3 callees).

### sub_5c5860 at 0x5c5860 (28 instructions)

````text
0x5c5860: mov eax,[ecx+8]
0x5c5863: mov edx,[eax]
0x5c5865: mov [ecx+8],edx
0x5c5868: mov edx,[eax]
0x5c586a: cmp byte ptr [edx+69h],0
0x5c586e: jne short 005C5873h
0x5c5870: mov [edx+4],ecx
0x5c5873: mov edx,[ecx+4]
0x5c5876: mov [eax+4],edx
0x5c5879: mov edx,[esp+4]
0x5c587d: mov edx,[edx+4]
0x5c5880: cmp ecx,[edx+4]
0x5c5883: jne short 005C5890h
0x5c5885: mov [edx+4],eax
0x5c5888: mov [eax],ecx
0x5c588a: mov [ecx+4],eax
0x5c588d: ret 4
0x5c5890: mov edx,[ecx+4]
0x5c5893: cmp ecx,[edx]
0x5c5895: jne short 005C58A1h
0x5c5897: mov [edx],eax
0x5c5899: mov [eax],ecx
0x5c589b: mov [ecx+4],eax
0x5c589e: ret 4
0x5c58a1: mov [edx+8],eax
0x5c58a4: mov [eax],ecx
0x5c58a6: mov [ecx+4],eax
0x5c58a9: ret 4
````

`sub_5c5860` is called by sub_5c5310. It calls nothing else.

### sub_5c58b0 at 0x5c58b0 (9 instructions)

````text
0x5c58b0: mov ecx,[eax+8]
0x5c58b3: cmp byte ptr [ecx+69h],0
0x5c58b7: jne short 005C58CBh
0x5c58b9: lea esp,[esp]
0x5c58c0: mov eax,ecx
0x5c58c2: mov ecx,[eax+8]
0x5c58c5: cmp byte ptr [ecx+69h],0
0x5c58c9: je short 005C58C0h
0x5c58cb: ret
````

`sub_5c58b0` is called by sub_5c5310. It calls nothing else.

### sub_5c58d0 at 0x5c58d0 (28 instructions)

````text
0x5c58d0: mov eax,[ecx]
0x5c58d2: mov edx,[eax+8]
0x5c58d5: mov [ecx],edx
0x5c58d7: mov edx,[eax+8]
0x5c58da: cmp byte ptr [edx+69h],0
0x5c58de: jne short 005C58E3h
0x5c58e0: mov [edx+4],ecx
0x5c58e3: mov edx,[ecx+4]
0x5c58e6: mov [eax+4],edx
0x5c58e9: mov edx,[esp+4]
0x5c58ed: mov edx,[edx+4]
0x5c58f0: cmp ecx,[edx+4]
0x5c58f3: jne short 005C5901h
0x5c58f5: mov [edx+4],eax
0x5c58f8: mov [eax+8],ecx
0x5c58fb: mov [ecx+4],eax
0x5c58fe: ret 4
0x5c5901: mov edx,[ecx+4]
0x5c5904: cmp ecx,[edx+8]
0x5c5907: jne short 005C5915h
0x5c5909: mov [edx+8],eax
0x5c590c: mov [eax+8],ecx
0x5c590f: mov [ecx+4],eax
0x5c5912: ret 4
0x5c5915: mov [edx],eax
0x5c5917: mov [eax+8],ecx
0x5c591a: mov [ecx+4],eax
0x5c591d: ret 4
````

`sub_5c58d0` is called by sub_5c5310. It calls nothing else.

### sub_5c5920 at 0x5c5920 (16 instructions)

````text
0x5c5920: mov ecx,1
0x5c5925: call 005C5B80h
0x5c592a: test eax,eax
0x5c592c: je short 005C5934h
0x5c592e: mov dword ptr [eax],0
0x5c5934: lea ecx,[eax+4]
0x5c5937: test ecx,ecx
0x5c5939: je short 005C5941h
0x5c593b: mov dword ptr [ecx],0
0x5c5941: lea ecx,[eax+8]
0x5c5944: test ecx,ecx
0x5c5946: je short 005C594Eh
0x5c5948: mov dword ptr [ecx],0
0x5c594e: mov byte ptr [eax+68h],1
0x5c5952: mov byte ptr [eax+69h],0
0x5c5956: ret
````

`sub_5c5920` is called by sub_5c2e10. It delegates to sub_5c5b80 (1 callees).

### sub_5c5ab0 at 0x5c5ab0 (39 instructions)

````text
0x5c5ab0: cmp dword ptr [esi],0
0x5c5ab3: push edi
0x5c5ab4: mov edi,ds:[77D0E4h]
0x5c5aba: jne short 005C5ABEh
0x5c5abc: call edi
0x5c5abe: mov eax,[esi+4]
0x5c5ac1: cmp byte ptr [eax+69h],0
0x5c5ac5: je short 005C5ACBh
0x5c5ac7: call edi
0x5c5ac9: pop edi
0x5c5aca: ret
0x5c5acb: mov ecx,[eax+8]
0x5c5ace: cmp byte ptr [ecx+69h],0
0x5c5ad2: jne short 005C5AEFh
0x5c5ad4: mov eax,[ecx]
0x5c5ad6: cmp byte ptr [eax+69h],0
0x5c5ada: jne short 005C5AEAh
0x5c5adc: lea esp,[esp]
0x5c5ae0: mov ecx,eax
0x5c5ae2: mov eax,[ecx]
0x5c5ae4: cmp byte ptr [eax+69h],0
0x5c5ae8: je short 005C5AE0h
0x5c5aea: mov [esi+4],ecx
0x5c5aed: pop edi
0x5c5aee: ret
0x5c5aef: mov eax,[eax+4]
0x5c5af2: cmp byte ptr [eax+69h],0
0x5c5af6: jne short 005C5B0Eh
0x5c5af8: mov ecx,[esi+4]
0x5c5afb: cmp ecx,[eax+8]
0x5c5afe: jne short 005C5B0Eh
0x5c5b00: mov [esi+4],eax
0x5c5b03: mov edx,eax
0x5c5b05: mov eax,[edx+4]
0x5c5b08: cmp byte ptr [eax+69h],0
0x5c5b0c: je short 005C5AF8h
0x5c5b0e: mov [esi+4],eax
0x5c5b11: pop edi
0x5c5b12: ret
````

`sub_5c5ab0` is called by sub_5c50c0, sub_5c5310. It calls nothing else.

### sub_5c5b80 at 0x5c5b80 (22 instructions)

````text
0x5c5b80: or eax,0FFFFFFFFh
0x5c5b83: xor edx,edx
0x5c5b85: div ecx
0x5c5b87: sub esp,10h
0x5c5b8a: cmp eax,6Ch
0x5c5b8d: jae short 005C5BBCh
0x5c5b8f: lea eax,[esp]
0x5c5b92: push eax
0x5c5b93: lea ecx,[esp+8]
0x5c5b97: mov dword ptr [esp+4],0
0x5c5b9f: call dword ptr ds:[77D0DCh]
0x5c5ba5: push 80A2ACh
0x5c5baa: lea ecx,[esp+8]
0x5c5bae: push ecx
0x5c5baf: mov dword ptr [esp+0Ch],78FFD4h
0x5c5bb7: call 00652AC4h
0x5c5bbc: imul ecx,6Ch
0x5c5bbf: push ecx
0x5c5bc0: call 006516C0h
0x5c5bc5: add esp,4
0x5c5bc8: add esp,10h
0x5c5bcb: ret
````

`sub_5c5b80` is called by sub_5c5920. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_5c5d60 at 0x5c5d60 (34 instructions)

````text
0x5c5d60: push 0FFFFFFFFh
0x5c5d62: push 744611h
0x5c5d67: mov eax,fs:[0]
0x5c5d6d: push eax
0x5c5d6e: push ecx
0x5c5d6f: push esi
0x5c5d70: mov eax,ds:[858220h]
0x5c5d75: xor eax,esp
0x5c5d77: push eax
0x5c5d78: lea eax,[esp+0Ch]
0x5c5d7c: mov fs:[0],eax
0x5c5d82: xor esi,esi
0x5c5d84: mov dword ptr [esp+8],874968h
0x5c5d8c: mov ds:[87496Ch],esi
0x5c5d92: mov ds:[874970h],esi
0x5c5d98: mov ds:[874974h],esi
0x5c5d9e: mov ds:[874978h],esi
0x5c5da4: mov ecx,87497Ch
0x5c5da9: mov [esp+14h],esi
0x5c5dad: call dword ptr ds:[77DF80h]
0x5c5db3: mov byte ptr [esp+14h],1
0x5c5db8: mov ecx,874990h
0x5c5dbd: mov ds:[874984h],esi
0x5c5dc3: mov ds:[874988h],esi
0x5c5dc9: mov ds:[87498Ch],esi
0x5c5dcf: call dword ptr ds:[77CD80h]
0x5c5dd5: mov ds:[8749ACh],esi
0x5c5ddb: mov eax,874968h
0x5c5de0: mov ecx,[esp+0Ch]
0x5c5de4: mov fs:[0],ecx
0x5c5deb: pop ecx
0x5c5dec: pop esi
0x5c5ded: add esp,10h
0x5c5df0: ret
````

`sub_5c5d60` is called by ?get_mutable_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@SAAAVCComboSymbolTask@@XZ, ?get_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@CAAAVCComboSymbolTask@@XZ. It calls nothing else.

### ?get_mutable_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@SAAAVCComboSymbolTask@@XZ at 0x5c6980 (25 instructions)

````text
0x5c6980: jmp near ptr 005C6BA0h
0x5c6ba0: push 0FFFFFFFFh
0x5c6ba2: push 74B6FEh
0x5c6ba7: mov eax,fs:[0]
0x5c6bad: push eax
0x5c6bae: mov eax,ds:[858220h]
0x5c6bb3: xor eax,esp
0x5c6bb5: push eax
0x5c6bb6: lea eax,[esp+4]
0x5c6bba: mov fs:[0],eax
0x5c6bc0: mov eax,1
0x5c6bc5: test ds:[875D3Ch],al
0x5c6bcb: jne short 005C6BEDh
0x5c6bcd: or ds:[875D3Ch],eax
0x5c6bd3: mov dword ptr [esp+0Ch],0
0x5c6bdb: call 005C5D60h
0x5c6be0: push 77B3E0h
0x5c6be5: call 006527EDh
0x5c6bea: add esp,4
0x5c6bed: mov eax,874968h
0x5c6bf2: mov ecx,[esp+4]
0x5c6bf6: mov fs:[0],ecx
0x5c6bfd: pop ecx
0x5c6bfe: add esp,0Ch
0x5c6c01: ret
````

`?get_mutable_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@SAAAVCComboSymbolTask@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5c5d60, sub_6527ed (2 callees).

### sub_5c6b00 at 0x5c6b00 (49 instructions)

````text
0x5c6b00: mov eax,ds:[874978h]
0x5c6b05: push edi
0x5c6b06: xor edi,edi
0x5c6b08: cmp eax,edi
0x5c6b0a: je short 005C6B4Eh
0x5c6b0c: lea esp,[esp]
0x5c6b10: cmp eax,edi
0x5c6b12: je short 005C6B4Eh
0x5c6b14: mov ecx,ds:[874974h]
0x5c6b1a: lea eax,[ecx+eax-1]
0x5c6b1e: mov ecx,ds:[874970h]
0x5c6b24: cmp ecx,eax
0x5c6b26: ja short 005C6B2Ah
0x5c6b28: sub eax,ecx
0x5c6b2a: mov edx,ds:[87496Ch]
0x5c6b30: mov eax,[edx+eax*4]
0x5c6b33: push eax
0x5c6b34: call 00407C40h
0x5c6b39: mov eax,ds:[874978h]
0x5c6b3e: sub eax,1
0x5c6b41: mov ds:[874978h],eax
0x5c6b46: jne short 005C6B10h
0x5c6b48: mov ds:[874974h],edi
0x5c6b4e: mov eax,ds:[87496Ch]
0x5c6b53: push esi
0x5c6b54: mov esi,ds:[874970h]
0x5c6b5a: cmp esi,edi
0x5c6b5c: jbe short 005C6B7Dh
0x5c6b5e: mov edi,edi
0x5c6b60: sub esi,1
0x5c6b63: cmp [eax+esi*4],edi
0x5c6b66: je short 005C6B79h
0x5c6b68: mov ecx,[eax+esi*4]
0x5c6b6b: push ecx
0x5c6b6c: call 006516BAh
0x5c6b71: mov eax,ds:[87496Ch]
0x5c6b76: add esp,4
0x5c6b79: cmp esi,edi
0x5c6b7b: ja short 005C6B60h
0x5c6b7d: cmp eax,edi
0x5c6b7f: pop esi
0x5c6b80: je short 005C6B8Bh
0x5c6b82: push eax
0x5c6b83: call 006516BAh
0x5c6b88: add esp,4
0x5c6b8b: mov ds:[87496Ch],edi
0x5c6b91: mov ds:[874970h],edi
0x5c6b97: pop edi
0x5c6b98: ret
````

`sub_5c6b00` is called by sub_77b3e0. It delegates to sub_407c40, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@CAAAVCComboSymbolTask@@XZ at 0x5c6ba0 (24 instructions)

````text
0x5c6ba0: push 0FFFFFFFFh
0x5c6ba2: push 74B6FEh
0x5c6ba7: mov eax,fs:[0]
0x5c6bad: push eax
0x5c6bae: mov eax,ds:[858220h]
0x5c6bb3: xor eax,esp
0x5c6bb5: push eax
0x5c6bb6: lea eax,[esp+4]
0x5c6bba: mov fs:[0],eax
0x5c6bc0: mov eax,1
0x5c6bc5: test ds:[875D3Ch],al
0x5c6bcb: jne short 005C6BEDh
0x5c6bcd: or ds:[875D3Ch],eax
0x5c6bd3: mov dword ptr [esp+0Ch],0
0x5c6bdb: call 005C5D60h
0x5c6be0: push 77B3E0h
0x5c6be5: call 006527EDh
0x5c6bea: add esp,4
0x5c6bed: mov eax,874968h
0x5c6bf2: mov ecx,[esp+4]
0x5c6bf6: mov fs:[0],ecx
0x5c6bfd: pop ecx
0x5c6bfe: add esp,0Ch
0x5c6c01: ret
````

`?get_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@CAAAVCComboSymbolTask@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5c5d60, sub_6527ed (2 callees).

### sub_5ce370 at 0x5ce370 (22 instructions)

````text
0x5ce370: or eax,0FFFFFFFFh
0x5ce373: xor edx,edx
0x5ce375: div ecx
0x5ce377: sub esp,10h
0x5ce37a: cmp eax,10h
0x5ce37d: jae short 005CE3ACh
0x5ce37f: lea eax,[esp]
0x5ce382: push eax
0x5ce383: lea ecx,[esp+8]
0x5ce387: mov dword ptr [esp+4],0
0x5ce38f: call dword ptr ds:[77D0DCh]
0x5ce395: push 80A2ACh
0x5ce39a: lea ecx,[esp+8]
0x5ce39e: push ecx
0x5ce39f: mov dword ptr [esp+0Ch],78FFD4h
0x5ce3a7: call 00652AC4h
0x5ce3ac: shl ecx,4
0x5ce3af: push ecx
0x5ce3b0: call 006516C0h
0x5ce3b5: add esp,4
0x5ce3b8: add esp,10h
0x5ce3bb: ret
````

`sub_5ce370` is called by sub_4b4fa0. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_5d11a0 at 0x5d11a0 (38 instructions)

````text
0x5d11a0: push 0FFFFFFFFh
0x5d11a2: push 750170h
0x5d11a7: mov eax,fs:[0]
0x5d11ad: push eax
0x5d11ae: push ecx
0x5d11af: mov eax,ds:[858220h]
0x5d11b4: xor eax,esp
0x5d11b6: push eax
0x5d11b7: lea eax,[esp+8]
0x5d11bb: mov fs:[0],eax
0x5d11c1: mov ecx,875DB4h
0x5d11c6: mov dword ptr [esp+4],875DB4h
0x5d11ce: call dword ptr ds:[77DF80h]
0x5d11d4: mov dword ptr [esp+10h],0
0x5d11dc: call 005D9CE0h
0x5d11e1: mov ds:[875DC0h],eax
0x5d11e6: mov byte ptr [eax+31h],1
0x5d11ea: mov eax,ds:[875DC0h]
0x5d11ef: mov [eax+4],eax
0x5d11f2: mov eax,ds:[875DC0h]
0x5d11f7: mov [eax],eax
0x5d11f9: mov eax,ds:[875DC0h]
0x5d11fe: mov [eax+8],eax
0x5d1201: mov dword ptr ds:[875DC4h],0
0x5d120b: mov ecx,875DCCh
0x5d1210: mov byte ptr [esp+10h],1
0x5d1215: call dword ptr ds:[77CD80h]
0x5d121b: mov byte ptr [esp+10h],2
0x5d1220: push 7F3BDCh
0x5d1225: mov ecx,875DCCh
0x5d122a: mov dword ptr ds:[875DC8h],1
0x5d1234: call dword ptr ds:[77CD50h]
0x5d123a: mov eax,875DB4h
0x5d123f: mov ecx,[esp+8]
0x5d1243: mov fs:[0],ecx
0x5d124a: pop ecx
0x5d124b: add esp,10h
0x5d124e: ret
````

`sub_5d11a0` is called by ?get_mutable_instance@?$singleton@VXDrawManager@@@serialization@boost@@SAAAVXDrawManager@@XZ, ?get_instance@?$singleton@VXDrawManager@@@serialization@boost@@CAAAVXDrawManager@@XZ. It delegates to sub_5d9ce0 (1 callees).

### ?get_mutable_instance@?$singleton@VXDrawManager@@@serialization@boost@@SAAAVXDrawManager@@XZ at 0x5d3850 (25 instructions)

````text
0x5d3850: jmp near ptr 005D3860h
0x5d3860: push 0FFFFFFFFh
0x5d3862: push 75910Eh
0x5d3867: mov eax,fs:[0]
0x5d386d: push eax
0x5d386e: mov eax,ds:[858220h]
0x5d3873: xor eax,esp
0x5d3875: push eax
0x5d3876: lea eax,[esp+4]
0x5d387a: mov fs:[0],eax
0x5d3880: mov eax,1
0x5d3885: test ds:[875F30h],al
0x5d388b: jne short 005D38ADh
0x5d388d: or ds:[875F30h],eax
0x5d3893: mov dword ptr [esp+0Ch],0
0x5d389b: call 005D11A0h
0x5d38a0: push 77B3F0h
0x5d38a5: call 006527EDh
0x5d38aa: add esp,4
0x5d38ad: mov eax,875DB4h
0x5d38b2: mov ecx,[esp+4]
0x5d38b6: mov fs:[0],ecx
0x5d38bd: pop ecx
0x5d38be: add esp,0Ch
0x5d38c1: ret
````

`?get_mutable_instance@?$singleton@VXDrawManager@@@serialization@boost@@SAAAVXDrawManager@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5d11a0, sub_6527ed (2 callees).

### ?get_instance@?$singleton@VXDrawManager@@@serialization@boost@@CAAAVXDrawManager@@XZ at 0x5d3860 (24 instructions)

````text
0x5d3860: push 0FFFFFFFFh
0x5d3862: push 75910Eh
0x5d3867: mov eax,fs:[0]
0x5d386d: push eax
0x5d386e: mov eax,ds:[858220h]
0x5d3873: xor eax,esp
0x5d3875: push eax
0x5d3876: lea eax,[esp+4]
0x5d387a: mov fs:[0],eax
0x5d3880: mov eax,1
0x5d3885: test ds:[875F30h],al
0x5d388b: jne short 005D38ADh
0x5d388d: or ds:[875F30h],eax
0x5d3893: mov dword ptr [esp+0Ch],0
0x5d389b: call 005D11A0h
0x5d38a0: push 77B3F0h
0x5d38a5: call 006527EDh
0x5d38aa: add esp,4
0x5d38ad: mov eax,875DB4h
0x5d38b2: mov ecx,[esp+4]
0x5d38b6: mov fs:[0],ecx
0x5d38bd: pop ecx
0x5d38be: add esp,0Ch
0x5d38c1: ret
````

`?get_instance@?$singleton@VXDrawManager@@@serialization@boost@@CAAAVXDrawManager@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5d11a0, sub_6527ed (2 callees).

### sub_5d7560 at 0x5d7560 (83 instructions)

````text
0x5d7560: push 0FFFFFFFFh
0x5d7562: push 754D98h
0x5d7567: mov eax,fs:[0]
0x5d756d: push eax
0x5d756e: push ebx
0x5d756f: push esi
0x5d7570: push edi
0x5d7571: mov eax,ds:[858220h]
0x5d7576: xor eax,esp
0x5d7578: push eax
0x5d7579: lea eax,[esp+10h]
0x5d757d: mov fs:[0],eax
0x5d7583: mov esi,[esp+20h]
0x5d7587: xor ebx,ebx
0x5d7589: push ebx
0x5d758a: lea eax,[esi+4]
0x5d758d: push eax
0x5d758e: mov dword ptr [esi],7F43ECh
0x5d7594: call 004DDD40h
0x5d7599: mov [esp+18h],ebx
0x5d759d: mov edi,ds:[77DF80h]
0x5d75a3: lea ecx,[esi+40h]
0x5d75a6: call edi
0x5d75a8: mov byte ptr [esp+18h],1
0x5d75ad: call 005D9CE0h
0x5d75b2: mov [esi+4Ch],eax
0x5d75b5: mov byte ptr [eax+31h],1
0x5d75b9: mov eax,[esi+4Ch]
0x5d75bc: mov [eax+4],eax
0x5d75bf: mov eax,[esi+4Ch]
0x5d75c2: mov [eax],eax
0x5d75c4: mov eax,[esi+4Ch]
0x5d75c7: mov [eax+8],eax
0x5d75ca: mov [esi+50h],ebx
0x5d75cd: mov byte ptr [esp+18h],2
0x5d75d2: call 005D9CE0h
0x5d75d7: mov [esi+58h],eax
0x5d75da: mov byte ptr [eax+31h],1
0x5d75de: mov eax,[esi+58h]
0x5d75e1: mov [eax+4],eax
0x5d75e4: mov eax,[esi+58h]
0x5d75e7: mov [eax],eax
0x5d75e9: mov eax,[esi+58h]
0x5d75ec: mov [eax+8],eax
0x5d75ef: mov [esi+5Ch],ebx
0x5d75f2: mov byte ptr [esp+18h],3
0x5d75f7: lea ecx,[esi+64h]
0x5d75fa: mov dword ptr [esi+60h],7F440Ch
0x5d7601: call edi
0x5d7603: mov [esi+70h],ebx
0x5d7606: mov [esi+74h],ebx
0x5d7609: mov [esi+78h],ebx
0x5d760c: mov [esi+7Ch],ebx
0x5d760f: mov dword ptr [esi+80h],0F4240h
0x5d7619: mov byte ptr [esp+18h],4
0x5d761e: push 20h
0x5d7620: mov dword ptr [esi+84h],1
0x5d762a: mov [esi+88h],ebx
0x5d7630: call 006516C0h
0x5d7635: add esp,4
0x5d7638: cmp eax,ebx
0x5d763a: je short 005D7666h
0x5d763c: mov [eax+4],ebx
0x5d763f: mov [eax+8],ebx
0x5d7642: mov dword ptr [eax+0Ch],64h
0x5d7649: mov [eax+10h],ebx
0x5d764c: mov [eax+14h],ebx
0x5d764f: mov [eax+18h],bl
0x5d7652: mov [eax+19h],bl
0x5d7655: mov dword ptr [eax],7F4414h
0x5d765b: mov [eax+1Ch],esi
0x5d765e: mov [esi+88h],eax
0x5d7664: jmp short 005D766Ch
0x5d7666: mov [esi+88h],ebx
0x5d766c: mov eax,esi
0x5d766e: mov ecx,[esp+10h]
0x5d7672: mov fs:[0],ecx
0x5d7679: pop ecx
0x5d767a: pop edi
0x5d767b: pop esi
0x5d767c: pop ebx
0x5d767d: add esp,0Ch
0x5d7680: ret 4
````

`sub_5d7560` is called by ?get_mutable_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@SAAAVTAF_AsynCalcTagging@@XZ, ?get_mutable_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@SAAAVTAF_AsynCalcMatrix@@XZ, ?get_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@CAAAVTAF_AsynCalcTagging@@XZ, ?get_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@CAAAVTAF_AsynCalcMatrix@@XZ. It delegates to sub_4ddd40, sub_5d9ce0, j_ORDINAL 762 (3 callees).

### sub_5d8f50 at 0x5d8f50 (26 instructions)

````text
0x5d8f50: push 0FFFFFFFFh
0x5d8f52: push 74AF5Ch
0x5d8f57: mov eax,fs:[0]
0x5d8f5d: push eax
0x5d8f5e: push ecx
0x5d8f5f: push esi
0x5d8f60: mov eax,ds:[858220h]
0x5d8f65: xor eax,esp
0x5d8f67: push eax
0x5d8f68: lea eax,[esp+0Ch]
0x5d8f6c: mov fs:[0],eax
0x5d8f72: mov esi,ecx
0x5d8f74: mov [esp+8],esi
0x5d8f78: mov dword ptr [esi],7F440Ch
0x5d8f7e: lea eax,[esi+0Ch]
0x5d8f81: mov dword ptr [esp+14h],0
0x5d8f89: call 004664C0h
0x5d8f8e: lea ecx,[esi+4]
0x5d8f91: mov dword ptr [esp+14h],0FFFFFFFFh
0x5d8f99: call dword ptr ds:[77DF7Ch]
0x5d8f9f: mov ecx,[esp+0Ch]
0x5d8fa3: mov fs:[0],ecx
0x5d8faa: pop ecx
0x5d8fab: pop esi
0x5d8fac: add esp,10h
0x5d8faf: ret
````

`sub_5d8f50` is called by sub_77b400, sub_77b420. It delegates to sub_4664c0 (1 callees).

### ?get_mutable_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@SAAAVTAF_AsynCalcTagging@@XZ at 0x5d9130 (29 instructions)

````text
0x5d9130: jmp near ptr 005D94D0h
0x5d94d0: push 0FFFFFFFFh
0x5d94d2: push 76DCEEh
0x5d94d7: mov eax,fs:[0]
0x5d94dd: push eax
0x5d94de: mov eax,ds:[858220h]
0x5d94e3: xor eax,esp
0x5d94e5: push eax
0x5d94e6: lea eax,[esp+4]
0x5d94ea: mov fs:[0],eax
0x5d94f0: mov eax,1
0x5d94f5: test ds:[876550h],al
0x5d94fb: jne short 005D9538h
0x5d94fd: or ds:[876550h],eax
0x5d9503: push 8764B8h
0x5d9508: mov dword ptr [esp+10h],0
0x5d9510: call 005D7560h
0x5d9515: mov eax,ds:[876540h]
0x5d951a: mov dword ptr [eax+0Ch],0C8h
0x5d9521: push 77B420h
0x5d9526: mov dword ptr ds:[8764B8h],7F4468h
0x5d9530: call 006527EDh
0x5d9535: add esp,4
0x5d9538: mov eax,8764B8h
0x5d953d: mov ecx,[esp+4]
0x5d9541: mov fs:[0],ecx
0x5d9548: pop ecx
0x5d9549: add esp,0Ch
0x5d954c: ret
````

`?get_mutable_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@SAAAVTAF_AsynCalcTagging@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5d7560, sub_6527ed (2 callees).

### ?get_mutable_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@SAAAVTAF_AsynCalcMatrix@@XZ at 0x5d9140 (30 instructions)

````text
0x5d9140: jmp near ptr 005D9550h
0x5d9550: push 0FFFFFFFFh
0x5d9552: push 76DCBEh
0x5d9557: mov eax,fs:[0]
0x5d955d: push eax
0x5d955e: mov eax,ds:[858220h]
0x5d9563: xor eax,esp
0x5d9565: push eax
0x5d9566: lea eax,[esp+4]
0x5d956a: mov fs:[0],eax
0x5d9570: mov eax,1
0x5d9575: test ds:[87654Ch],al
0x5d957b: jne short 005D95C2h
0x5d957d: or ds:[87654Ch],eax
0x5d9583: push 876428h
0x5d9588: mov dword ptr [esp+10h],0
0x5d9590: call 005D7560h
0x5d9595: mov eax,ds:[8764B0h]
0x5d959a: mov dword ptr ds:[8764ACh],0Ah
0x5d95a4: mov dword ptr [eax+0Ch],64h
0x5d95ab: push 77B400h
0x5d95b0: mov dword ptr ds:[876428h],7F4488h
0x5d95ba: call 006527EDh
0x5d95bf: add esp,4
0x5d95c2: mov eax,876428h
0x5d95c7: mov ecx,[esp+4]
0x5d95cb: mov fs:[0],ecx
0x5d95d2: pop ecx
0x5d95d3: add esp,0Ch
0x5d95d6: ret
````

`?get_mutable_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@SAAAVTAF_AsynCalcMatrix@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5d7560, sub_6527ed (2 callees).

### sub_5d9390 at 0x5d9390 (9 instructions)

````text
0x5d9390: mov ecx,[eax+8]
0x5d9393: cmp byte ptr [ecx+31h],0
0x5d9397: jne short 005D93ABh
0x5d9399: lea esp,[esp]
0x5d93a0: mov eax,ecx
0x5d93a2: mov ecx,[eax+8]
0x5d93a5: cmp byte ptr [ecx+31h],0
0x5d93a9: je short 005D93A0h
0x5d93ab: ret
````

`sub_5d9390` is called by sub_5e3990. It calls nothing else.

### ?get_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@CAAAVTAF_AsynCalcTagging@@XZ at 0x5d94d0 (28 instructions)

````text
0x5d94d0: push 0FFFFFFFFh
0x5d94d2: push 76DCEEh
0x5d94d7: mov eax,fs:[0]
0x5d94dd: push eax
0x5d94de: mov eax,ds:[858220h]
0x5d94e3: xor eax,esp
0x5d94e5: push eax
0x5d94e6: lea eax,[esp+4]
0x5d94ea: mov fs:[0],eax
0x5d94f0: mov eax,1
0x5d94f5: test ds:[876550h],al
0x5d94fb: jne short 005D9538h
0x5d94fd: or ds:[876550h],eax
0x5d9503: push 8764B8h
0x5d9508: mov dword ptr [esp+10h],0
0x5d9510: call 005D7560h
0x5d9515: mov eax,ds:[876540h]
0x5d951a: mov dword ptr [eax+0Ch],0C8h
0x5d9521: push 77B420h
0x5d9526: mov dword ptr ds:[8764B8h],7F4468h
0x5d9530: call 006527EDh
0x5d9535: add esp,4
0x5d9538: mov eax,8764B8h
0x5d953d: mov ecx,[esp+4]
0x5d9541: mov fs:[0],ecx
0x5d9548: pop ecx
0x5d9549: add esp,0Ch
0x5d954c: ret
````

`?get_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@CAAAVTAF_AsynCalcTagging@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5d7560, sub_6527ed (2 callees).

### ?get_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@CAAAVTAF_AsynCalcMatrix@@XZ at 0x5d9550 (29 instructions)

````text
0x5d9550: push 0FFFFFFFFh
0x5d9552: push 76DCBEh
0x5d9557: mov eax,fs:[0]
0x5d955d: push eax
0x5d955e: mov eax,ds:[858220h]
0x5d9563: xor eax,esp
0x5d9565: push eax
0x5d9566: lea eax,[esp+4]
0x5d956a: mov fs:[0],eax
0x5d9570: mov eax,1
0x5d9575: test ds:[87654Ch],al
0x5d957b: jne short 005D95C2h
0x5d957d: or ds:[87654Ch],eax
0x5d9583: push 876428h
0x5d9588: mov dword ptr [esp+10h],0
0x5d9590: call 005D7560h
0x5d9595: mov eax,ds:[8764B0h]
0x5d959a: mov dword ptr ds:[8764ACh],0Ah
0x5d95a4: mov dword ptr [eax+0Ch],64h
0x5d95ab: push 77B400h
0x5d95b0: mov dword ptr ds:[876428h],7F4488h
0x5d95ba: call 006527EDh
0x5d95bf: add esp,4
0x5d95c2: mov eax,876428h
0x5d95c7: mov ecx,[esp+4]
0x5d95cb: mov fs:[0],ecx
0x5d95d2: pop ecx
0x5d95d3: add esp,0Ch
0x5d95d6: ret
````

`?get_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@CAAAVTAF_AsynCalcMatrix@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5d7560, sub_6527ed (2 callees).

### sub_5d9ce0 at 0x5d9ce0 (16 instructions)

````text
0x5d9ce0: mov ecx,1
0x5d9ce5: call 005D9FC0h
0x5d9cea: test eax,eax
0x5d9cec: je short 005D9CF4h
0x5d9cee: mov dword ptr [eax],0
0x5d9cf4: lea ecx,[eax+4]
0x5d9cf7: test ecx,ecx
0x5d9cf9: je short 005D9D01h
0x5d9cfb: mov dword ptr [ecx],0
0x5d9d01: lea ecx,[eax+8]
0x5d9d04: test ecx,ecx
0x5d9d06: je short 005D9D0Eh
0x5d9d08: mov dword ptr [ecx],0
0x5d9d0e: mov byte ptr [eax+30h],1
0x5d9d12: mov byte ptr [eax+31h],0
0x5d9d16: ret
````

`sub_5d9ce0` is called by sub_5d11a0, sub_5d7560, sub_5dfc30. It delegates to sub_5d9fc0 (1 callees).

### sub_5d9fc0 at 0x5d9fc0 (22 instructions)

````text
0x5d9fc0: or eax,0FFFFFFFFh
0x5d9fc3: xor edx,edx
0x5d9fc5: div ecx
0x5d9fc7: sub esp,10h
0x5d9fca: cmp eax,34h
0x5d9fcd: jae short 005D9FFCh
0x5d9fcf: lea eax,[esp]
0x5d9fd2: push eax
0x5d9fd3: lea ecx,[esp+8]
0x5d9fd7: mov dword ptr [esp+4],0
0x5d9fdf: call dword ptr ds:[77D0DCh]
0x5d9fe5: push 80A2ACh
0x5d9fea: lea ecx,[esp+8]
0x5d9fee: push ecx
0x5d9fef: mov dword ptr [esp+0Ch],78FFD4h
0x5d9ff7: call 00652AC4h
0x5d9ffc: imul ecx,34h
0x5d9fff: push ecx
0x5da000: call 006516C0h
0x5da005: add esp,4
0x5da008: add esp,10h
0x5da00b: ret
````

`sub_5d9fc0` is called by sub_5d9ce0. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_5dcbb0 at 0x5dcbb0 (39 instructions)

````text
0x5dcbb0: push 0FFFFFFFFh
0x5dcbb2: push 73E769h
0x5dcbb7: mov eax,fs:[0]
0x5dcbbd: push eax
0x5dcbbe: push esi
0x5dcbbf: push edi
0x5dcbc0: mov eax,ds:[858220h]
0x5dcbc5: xor eax,esp
0x5dcbc7: push eax
0x5dcbc8: lea eax,[esp+0Ch]
0x5dcbcc: mov fs:[0],eax
0x5dcbd2: mov esi,[esp+1Ch]
0x5dcbd6: xor edi,edi
0x5dcbd8: mov [esp+14h],edi
0x5dcbdc: mov eax,[esi+20h]
0x5dcbdf: cmp eax,edi
0x5dcbe1: je short 005DCBFDh
0x5dcbe3: mov edx,[esp+1Ch]
0x5dcbe7: mov ecx,[esi+24h]
0x5dcbea: push edx
0x5dcbeb: push ecx
0x5dcbec: call 004CF400h
0x5dcbf1: mov eax,[esi+20h]
0x5dcbf4: push eax
0x5dcbf5: call 006516BAh
0x5dcbfa: add esp,0Ch
0x5dcbfd: mov ecx,esi
0x5dcbff: mov [esi+20h],edi
0x5dcc02: mov [esi+24h],edi
0x5dcc05: mov [esi+28h],edi
0x5dcc08: mov dword ptr [esp+14h],0FFFFFFFFh
0x5dcc10: call dword ptr ds:[77CD74h]
0x5dcc16: mov ecx,[esp+0Ch]
0x5dcc1a: mov fs:[0],ecx
0x5dcc21: pop ecx
0x5dcc22: pop edi
0x5dcc23: pop esi
0x5dcc24: add esp,0Ch
0x5dcc27: ret 4
````

`sub_5dcbb0` is called by sub_5e5500, sub_5e6990. It delegates to sub_4cf400, j_ORDINAL 764 (2 callees).

### sub_5df910 at 0x5df910 (30 instructions)

````text
0x5df910: push ebp
0x5df911: mov ebp,[esp+8]
0x5df915: push edi
0x5df916: mov edi,eax
0x5df918: cmp edi,ebp
0x5df91a: je short 005DF94Eh
0x5df91c: push ebx
0x5df91d: push esi
0x5df91e: lea esi,[edi+24h]
0x5df921: xor ebx,ebx
0x5df923: mov eax,[esi]
0x5df925: cmp eax,ebx
0x5df927: je short 005DF932h
0x5df929: push eax
0x5df92a: call 006516BAh
0x5df92f: add esp,4
0x5df932: mov ecx,edi
0x5df934: mov [esi],ebx
0x5df936: mov [esi+4],ebx
0x5df939: mov [esi+8],ebx
0x5df93c: call dword ptr ds:[77CD74h]
0x5df942: add edi,30h
0x5df945: add esi,30h
0x5df948: cmp edi,ebp
0x5df94a: jne short 005DF923h
0x5df94c: pop esi
0x5df94d: pop ebx
0x5df94e: pop edi
0x5df94f: pop ebp
0x5df950: ret
````

`sub_5df910` is called by sub_5e4a20. It delegates to j_ORDINAL 764 (1 callees).

### sub_5dfc30 at 0x5dfc30 (97 instructions)

````text
0x5dfc30: push 0FFFFFFFFh
0x5dfc32: push 754C46h
0x5dfc37: mov eax,fs:[0]
0x5dfc3d: push eax
0x5dfc3e: push ecx
0x5dfc3f: push ebx
0x5dfc40: push esi
0x5dfc41: mov eax,ds:[858220h]
0x5dfc46: xor eax,esp
0x5dfc48: push eax
0x5dfc49: lea eax,[esp+10h]
0x5dfc4d: mov fs:[0],eax
0x5dfc53: mov ecx,875EC0h
0x5dfc58: mov dword ptr [esp+0Ch],875EC0h
0x5dfc60: call dword ptr ds:[77DF80h]
0x5dfc66: xor esi,esi
0x5dfc68: mov [esp+18h],esi
0x5dfc6c: call 005D9CE0h
0x5dfc71: mov ds:[875ECCh],eax
0x5dfc76: mov bl,1
0x5dfc78: mov [eax+31h],bl
0x5dfc7b: mov eax,ds:[875ECCh]
0x5dfc80: mov [eax+4],eax
0x5dfc83: mov eax,ds:[875ECCh]
0x5dfc88: mov [eax],eax
0x5dfc8a: mov eax,ds:[875ECCh]
0x5dfc8f: mov [eax+8],eax
0x5dfc92: mov ds:[875ED0h],esi
0x5dfc98: mov ds:[875ED8h],esi
0x5dfc9e: mov ds:[875EDCh],esi
0x5dfca4: mov ds:[875EE0h],esi
0x5dfcaa: mov ds:[875EE8h],esi
0x5dfcb0: mov ds:[875EECh],esi
0x5dfcb6: mov ds:[875EF0h],esi
0x5dfcbc: mov byte ptr [esp+18h],3
0x5dfcc1: call 005D9CE0h
0x5dfcc6: mov ds:[875EF8h],eax
0x5dfccb: mov [eax+31h],bl
0x5dfcce: mov eax,ds:[875EF8h]
0x5dfcd3: mov [eax+4],eax
0x5dfcd6: mov eax,ds:[875EF8h]
0x5dfcdb: mov [eax],eax
0x5dfcdd: mov eax,ds:[875EF8h]
0x5dfce2: mov [eax+8],eax
0x5dfce5: mov ds:[875EFCh],esi
0x5dfceb: mov byte ptr [esp+18h],4
0x5dfcf0: call 00633900h
0x5dfcf5: mov ds:[875F04h],eax
0x5dfcfa: mov [eax+39h],bl
0x5dfcfd: mov eax,ds:[875F04h]
0x5dfd02: mov [eax+4],eax
0x5dfd05: mov eax,ds:[875F04h]
0x5dfd0a: mov [eax],eax
0x5dfd0c: mov eax,ds:[875F04h]
0x5dfd11: mov [eax+8],eax
0x5dfd14: mov ds:[875F08h],esi
0x5dfd1a: mov byte ptr [esp+18h],5
0x5dfd1f: call 00633900h
0x5dfd24: mov ds:[875F10h],eax
0x5dfd29: mov [eax+39h],bl
0x5dfd2c: mov eax,ds:[875F10h]
0x5dfd31: mov [eax+4],eax
0x5dfd34: mov eax,ds:[875F10h]
0x5dfd39: mov [eax],eax
0x5dfd3b: mov eax,ds:[875F10h]
0x5dfd40: mov [eax+8],eax
0x5dfd43: mov ds:[875F14h],esi
0x5dfd49: mov byte ptr [esp+18h],6
0x5dfd4e: call 00633900h
0x5dfd53: mov ds:[875F1Ch],eax
0x5dfd58: mov [eax+39h],bl
0x5dfd5b: mov eax,ds:[875F1Ch]
0x5dfd60: mov [eax+4],eax
0x5dfd63: mov eax,ds:[875F1Ch]
0x5dfd68: mov [eax],eax
0x5dfd6a: mov eax,ds:[875F1Ch]
0x5dfd6f: mov [eax+8],eax
0x5dfd72: mov ds:[875F20h],esi
0x5dfd78: mov byte ptr [esp+18h],7
0x5dfd7d: call 0063A4A0h
0x5dfd82: mov ds:[875F28h],eax
0x5dfd87: mov [eax+29h],bl
0x5dfd8a: mov eax,ds:[875F28h]
0x5dfd8f: mov [eax+4],eax
0x5dfd92: mov eax,ds:[875F28h]
0x5dfd97: mov [eax],eax
0x5dfd99: mov eax,ds:[875F28h]
0x5dfd9e: mov [eax+8],eax
0x5dfda1: mov ds:[875F2Ch],esi
0x5dfda7: mov eax,875EC0h
0x5dfdac: mov ecx,[esp+10h]
0x5dfdb0: mov fs:[0],ecx
0x5dfdb7: pop ecx
0x5dfdb8: pop esi
0x5dfdb9: pop ebx
0x5dfdba: add esp,10h
0x5dfdbd: ret
````

`sub_5dfc30` is called by ?get_instance@?$singleton@VTAF_Manager@@@serialization@boost@@CAAAVTAF_Manager@@XZ. It delegates to sub_5d9ce0, sub_633900, sub_63a4a0 (3 callees).

### sub_5dfe00 at 0x5dfe00 (74 instructions)

````text
0x5dfe00: push 0FFFFFFFFh
0x5dfe02: push 754C46h
0x5dfe07: mov eax,fs:[0]
0x5dfe0d: push eax
0x5dfe0e: sub esp,8
0x5dfe11: push ebx
0x5dfe12: mov eax,ds:[858220h]
0x5dfe17: xor eax,esp
0x5dfe19: push eax
0x5dfe1a: lea eax,[esp+10h]
0x5dfe1e: mov fs:[0],eax
0x5dfe24: mov dword ptr [esp+0Ch],875EC0h
0x5dfe2c: mov eax,875F24h
0x5dfe31: mov dword ptr [esp+18h],7
0x5dfe39: call 004B4360h
0x5dfe3e: mov eax,875F18h
0x5dfe43: mov byte ptr [esp+18h],6
0x5dfe48: call 005E5540h
0x5dfe4d: mov eax,875F0Ch
0x5dfe52: mov byte ptr [esp+18h],5
0x5dfe57: call 005E5290h
0x5dfe5c: mov eax,875F00h
0x5dfe61: mov byte ptr [esp+18h],4
0x5dfe66: call 005E5020h
0x5dfe6b: mov eax,875EF4h
0x5dfe70: mov byte ptr [esp+18h],3
0x5dfe75: call 005E4B30h
0x5dfe7a: mov byte ptr [esp+18h],2
0x5dfe7f: mov eax,ds:[875EE8h]
0x5dfe84: xor ecx,ecx
0x5dfe86: cmp eax,ecx
0x5dfe88: je short 005DFEAEh
0x5dfe8a: mov ecx,[esp+0Ch]
0x5dfe8e: mov ebx,ds:[875EECh]
0x5dfe94: push ecx
0x5dfe95: call 0044D400h
0x5dfe9a: mov edx,ds:[875EE8h]
0x5dfea0: add esp,4
0x5dfea3: push edx
0x5dfea4: call 006516BAh
0x5dfea9: add esp,4
0x5dfeac: xor ecx,ecx
0x5dfeae: mov byte ptr [esp+18h],1
0x5dfeb3: mov eax,ds:[875ED8h]
0x5dfeb8: cmp eax,ecx
0x5dfeba: mov ds:[875EE8h],ecx
0x5dfec0: mov ds:[875EECh],ecx
0x5dfec6: mov ds:[875EF0h],ecx
0x5dfecc: je short 005DFEF2h
0x5dfece: mov ecx,[esp+0Ch]
0x5dfed2: mov ebx,ds:[875EDCh]
0x5dfed8: push ecx
0x5dfed9: call 0044D400h
0x5dfede: mov edx,ds:[875ED8h]
0x5dfee4: add esp,4
0x5dfee7: push edx
0x5dfee8: call 006516BAh
0x5dfeed: add esp,4
0x5dfef0: xor ecx,ecx
0x5dfef2: mov eax,875EC8h
0x5dfef7: mov ds:[875ED8h],ecx
0x5dfefd: mov ds:[875EDCh],ecx
0x5dff03: mov ds:[875EE0h],ecx
0x5dff09: mov [esp+18h],cl
0x5dff0d: call 005E4B30h
0x5dff12: mov ecx,875EC0h
0x5dff17: mov dword ptr [esp+18h],0FFFFFFFFh
0x5dff1f: call dword ptr ds:[77DF7Ch]
0x5dff25: mov ecx,[esp+10h]
0x5dff29: mov fs:[0],ecx
0x5dff30: pop ecx
0x5dff31: pop ebx
0x5dff32: add esp,14h
0x5dff35: ret
````

`sub_5dfe00` is called by sub_77b440. It delegates to sub_44d400, sub_4b4360, sub_5e4b30 (7 callees).

### sub_5e3990 at 0x5e3990 (247 instructions)

````text
0x5e3990: push 0FFFFFFFFh
0x5e3992: push 7410D9h
0x5e3997: mov eax,fs:[0]
0x5e399d: push eax
0x5e399e: sub esp,44h
0x5e39a1: push ebx
0x5e39a2: push ebp
0x5e39a3: push esi
0x5e39a4: push edi
0x5e39a5: mov eax,ds:[858220h]
0x5e39aa: xor eax,esp
0x5e39ac: push eax
0x5e39ad: lea eax,[esp+58h]
0x5e39b1: mov fs:[0],eax
0x5e39b7: mov eax,[esp+74h]
0x5e39bb: cmp byte ptr [eax+31h],0
0x5e39bf: je short 005E39FDh
0x5e39c1: push 7C5AECh
0x5e39c6: lea ecx,[esp+18h]
0x5e39ca: call dword ptr ds:[77CD7Ch]
0x5e39d0: lea eax,[esp+14h]
0x5e39d4: push eax
0x5e39d5: lea ecx,[esp+34h]
0x5e39d9: mov dword ptr [esp+64h],0
0x5e39e1: call 00401230h
0x5e39e6: push 80A4F8h
0x5e39eb: lea ecx,[esp+34h]
0x5e39ef: push ecx
0x5e39f0: mov dword ptr [esp+38h],790F90h
0x5e39f8: call 00652AC4h
0x5e39fd: lea esi,[esp+70h]
0x5e3a01: mov ebp,eax
0x5e3a03: call 005919D0h
0x5e3a08: mov eax,[ebp]
0x5e3a0b: cmp byte ptr [eax+31h],0
0x5e3a0f: je short 005E3A16h
0x5e3a11: mov edi,[ebp+8]
0x5e3a14: jmp short 005E3A2Eh
0x5e3a16: mov edx,[ebp+8]
0x5e3a19: cmp byte ptr [edx+31h],0
0x5e3a1d: je short 005E3A23h
0x5e3a1f: mov edi,eax
0x5e3a21: jmp short 005E3A2Eh
0x5e3a23: mov ecx,[esp+74h]
0x5e3a27: cmp ecx,ebp
0x5e3a29: mov edi,[ecx+8]
0x5e3a2c: jne short 005E3AA2h
0x5e3a2e: cmp byte ptr [edi+31h],0
0x5e3a32: mov esi,[ebp+4]
0x5e3a35: jne short 005E3A3Ah
0x5e3a37: mov [edi+4],esi
0x5e3a3a: mov ecx,[esp+68h]
0x5e3a3e: mov eax,[ecx+4]
0x5e3a41: cmp [eax+4],ebp
0x5e3a44: jne short 005E3A4Bh
0x5e3a46: mov [eax+4],edi
0x5e3a49: jmp short 005E3A56h
0x5e3a4b: cmp [esi],ebp
0x5e3a4d: jne short 005E3A53h
0x5e3a4f: mov [esi],edi
0x5e3a51: jmp short 005E3A56h
0x5e3a53: mov [esi+8],edi
0x5e3a56: mov edx,[ecx+4]
0x5e3a59: cmp [edx],ebp
0x5e3a5b: jne short 005E3A7Dh
0x5e3a5d: cmp byte ptr [edi+31h],0
0x5e3a61: je short 005E3A67h
0x5e3a63: mov ecx,esi
0x5e3a65: jmp short 005E3A7Bh
0x5e3a67: mov eax,[edi]
0x5e3a69: cmp byte ptr [eax+31h],0
0x5e3a6d: mov ecx,edi
0x5e3a6f: jne short 005E3A7Bh
0x5e3a71: mov ecx,eax
0x5e3a73: mov eax,[ecx]
0x5e3a75: cmp byte ptr [eax+31h],0
0x5e3a79: je short 005E3A71h
0x5e3a7b: mov [edx],ecx
0x5e3a7d: mov eax,[esp+68h]
0x5e3a81: mov ebx,[eax+4]
0x5e3a84: cmp [ebx+8],ebp
0x5e3a87: jne short 005E3AFEh
0x5e3a89: cmp byte ptr [edi+31h],0
0x5e3a8d: je short 005E3A96h
0x5e3a8f: mov eax,esi
0x5e3a91: mov [ebx+8],eax
0x5e3a94: jmp short 005E3AFEh
0x5e3a96: mov eax,edi
0x5e3a98: call 005D9390h
0x5e3a9d: mov [ebx+8],eax
0x5e3aa0: jmp short 005E3AFEh
0x5e3aa2: mov [eax+4],ecx
0x5e3aa5: mov edx,[ebp]
0x5e3aa8: mov [ecx],edx
0x5e3aaa: cmp ecx,[ebp+8]
0x5e3aad: jne short 005E3AB3h
0x5e3aaf: mov esi,ecx
0x5e3ab1: jmp short 005E3ACDh
0x5e3ab3: cmp byte ptr [edi+31h],0
0x5e3ab7: mov esi,[ecx+4]
0x5e3aba: jne short 005E3ABFh
0x5e3abc: mov [edi+4],esi
0x5e3abf: mov [esi],edi
0x5e3ac1: mov eax,[ebp+8]
0x5e3ac4: mov [ecx+8],eax
0x5e3ac7: mov edx,[ebp+8]
0x5e3aca: mov [edx+4],ecx
0x5e3acd: mov eax,[esp+68h]
0x5e3ad1: mov eax,[eax+4]
0x5e3ad4: cmp [eax+4],ebp
0x5e3ad7: jne short 005E3ADEh
0x5e3ad9: mov [eax+4],ecx
0x5e3adc: jmp short 005E3AECh
0x5e3ade: mov eax,[ebp+4]
0x5e3ae1: cmp [eax],ebp
0x5e3ae3: jne short 005E3AE9h
0x5e3ae5: mov [eax],ecx
0x5e3ae7: jmp short 005E3AECh
0x5e3ae9: mov [eax+8],ecx
0x5e3aec: mov edx,[ebp+4]
0x5e3aef: mov [ecx+4],edx
0x5e3af2: mov dl,[ebp+30h]
0x5e3af5: mov al,[ecx+30h]
0x5e3af8: mov [ecx+30h],dl
0x5e3afb: mov [ebp+30h],al
0x5e3afe: mov bl,1
0x5e3b00: cmp [ebp+30h],bl
0x5e3b03: jne near ptr 005E3C2Ah
0x5e3b09: mov eax,[esp+68h]
0x5e3b0d: mov ecx,[eax+4]
0x5e3b10: cmp edi,[ecx+4]
0x5e3b13: je near ptr 005E3C27h
0x5e3b19: lea esp,[esp]
0x5e3b20: cmp [edi+30h],bl
0x5e3b23: jne near ptr 005E3C27h
0x5e3b29: mov ecx,[esi]
0x5e3b2b: cmp edi,ecx
0x5e3b2d: jne short 005E3BA5h
0x5e3b2f: mov ecx,[esi+8]
0x5e3b32: cmp byte ptr [ecx+30h],0
0x5e3b36: jne short 005E3B4Eh
0x5e3b38: mov edx,[esp+68h]
0x5e3b3c: mov [ecx+30h],bl
0x5e3b3f: push edx
0x5e3b40: mov ecx,esi
0x5e3b42: mov byte ptr [esi+30h],0
0x5e3b46: call 005E4DA0h
0x5e3b4b: mov ecx,[esi+8]
0x5e3b4e: cmp byte ptr [ecx+31h],0
0x5e3b52: jne near ptr 005E3BD9h
0x5e3b58: mov eax,[ecx]
0x5e3b5a: cmp [eax+30h],bl
0x5e3b5d: jne short 005E3B67h
0x5e3b5f: mov edx,[ecx+8]
0x5e3b62: cmp [edx+30h],bl
0x5e3b65: je short 005E3BD5h
0x5e3b67: mov eax,[ecx+8]
0x5e3b6a: cmp [eax+30h],bl
0x5e3b6d: jne short 005E3B85h
0x5e3b6f: mov edx,[ecx]
0x5e3b71: mov eax,[esp+68h]
0x5e3b75: mov [edx+30h],bl
0x5e3b78: push eax
0x5e3b79: mov byte ptr [ecx+30h],0
0x5e3b7d: call 005E4AE0h
0x5e3b82: mov ecx,[esi+8]
0x5e3b85: mov dl,[esi+30h]
0x5e3b88: mov [ecx+30h],dl
0x5e3b8b: mov [esi+30h],bl
0x5e3b8e: mov eax,[ecx+8]
0x5e3b91: mov ecx,[esp+68h]
0x5e3b95: push ecx
0x5e3b96: mov ecx,esi
0x5e3b98: mov [eax+30h],bl
0x5e3b9b: call 005E4DA0h
0x5e3ba0: jmp near ptr 005E3C27h
0x5e3ba5: cmp byte ptr [ecx+30h],0
0x5e3ba9: jne short 005E3BC0h
0x5e3bab: mov eax,[esp+68h]
0x5e3baf: mov [ecx+30h],bl
0x5e3bb2: push eax
0x5e3bb3: mov ecx,esi
0x5e3bb5: mov byte ptr [esi+30h],0
0x5e3bb9: call 005E4AE0h
0x5e3bbe: mov ecx,[esi]
0x5e3bc0: cmp byte ptr [ecx+31h],0
0x5e3bc4: jne short 005E3BD9h
0x5e3bc6: mov edx,[ecx+8]
0x5e3bc9: cmp [edx+30h],bl
0x5e3bcc: jne short 005E3BF0h
0x5e3bce: mov eax,[ecx]
0x5e3bd0: cmp [eax+30h],bl
0x5e3bd3: jne short 005E3BF0h
0x5e3bd5: mov byte ptr [ecx+30h],0
0x5e3bd9: mov ecx,[esp+68h]
0x5e3bdd: mov edx,[ecx+4]
0x5e3be0: mov edi,esi
0x5e3be2: cmp edi,[edx+4]
0x5e3be5: mov esi,[esi+4]
0x5e3be8: jne near ptr 005E3B20h
0x5e3bee: jmp short 005E3C27h
0x5e3bf0: mov edx,[ecx]
0x5e3bf2: cmp [edx+30h],bl
0x5e3bf5: jne short 005E3C0Dh
0x5e3bf7: mov eax,[ecx+8]
0x5e3bfa: mov edx,[esp+68h]
0x5e3bfe: mov [eax+30h],bl
0x5e3c01: push edx
0x5e3c02: mov byte ptr [ecx+30h],0
0x5e3c06: call 005E4DA0h
0x5e3c0b: mov ecx,[esi]
0x5e3c0d: mov al,[esi+30h]
0x5e3c10: mov edx,[esp+68h]
0x5e3c14: mov [ecx+30h],al
0x5e3c17: mov [esi+30h],bl
0x5e3c1a: mov ecx,[ecx]
0x5e3c1c: mov [ecx+30h],bl
0x5e3c1f: push edx
0x5e3c20: mov ecx,esi
0x5e3c22: call 005E4AE0h
0x5e3c27: mov [edi+30h],bl
0x5e3c2a: lea eax,[ebp+0Ch]
0x5e3c2d: push eax
0x5e3c2e: call 005E4990h
0x5e3c33: push ebp
0x5e3c34: call 006516BAh
0x5e3c39: mov ecx,[esp+6Ch]
0x5e3c3d: mov eax,[ecx+8]
0x5e3c40: add esp,4
0x5e3c43: test eax,eax
0x5e3c45: jbe short 005E3C4Dh
0x5e3c47: add eax,0FFFFFFFFh
0x5e3c4a: mov [ecx+8],eax
0x5e3c4d: mov eax,[esp+6Ch]
0x5e3c51: mov ecx,[esp+70h]
0x5e3c55: mov edx,[esp+74h]
0x5e3c59: mov [eax],ecx
0x5e3c5b: mov [eax+4],edx
0x5e3c5e: mov ecx,[esp+58h]
0x5e3c62: mov fs:[0],ecx
0x5e3c69: pop ecx
0x5e3c6a: pop edi
0x5e3c6b: pop esi
0x5e3c6c: pop ebp
0x5e3c6d: pop ebx
0x5e3c6e: add esp,50h
0x5e3c71: ret 10h
````

`sub_5e3990` is called by sub_5e5800. It delegates to sub_401230, sub_5919d0, sub_5d9390 (8 callees).

### sub_5e3ee0 at 0x5e3ee0 (247 instructions)

````text
0x5e3ee0: push 0FFFFFFFFh
0x5e3ee2: push 7410D9h
0x5e3ee7: mov eax,fs:[0]
0x5e3eed: push eax
0x5e3eee: sub esp,44h
0x5e3ef1: push ebx
0x5e3ef2: push ebp
0x5e3ef3: push esi
0x5e3ef4: push edi
0x5e3ef5: mov eax,ds:[858220h]
0x5e3efa: xor eax,esp
0x5e3efc: push eax
0x5e3efd: lea eax,[esp+58h]
0x5e3f01: mov fs:[0],eax
0x5e3f07: mov eax,[esp+74h]
0x5e3f0b: cmp byte ptr [eax+39h],0
0x5e3f0f: je short 005E3F4Dh
0x5e3f11: push 7C5AECh
0x5e3f16: lea ecx,[esp+18h]
0x5e3f1a: call dword ptr ds:[77CD7Ch]
0x5e3f20: lea eax,[esp+14h]
0x5e3f24: push eax
0x5e3f25: lea ecx,[esp+34h]
0x5e3f29: mov dword ptr [esp+64h],0
0x5e3f31: call 00401230h
0x5e3f36: push 80A4F8h
0x5e3f3b: lea ecx,[esp+34h]
0x5e3f3f: push ecx
0x5e3f40: mov dword ptr [esp+38h],790F90h
0x5e3f48: call 00652AC4h
0x5e3f4d: lea esi,[esp+70h]
0x5e3f51: mov ebp,eax
0x5e3f53: call 00633EE0h
0x5e3f58: mov eax,[ebp]
0x5e3f5b: cmp byte ptr [eax+39h],0
0x5e3f5f: je short 005E3F66h
0x5e3f61: mov edi,[ebp+8]
0x5e3f64: jmp short 005E3F7Eh
0x5e3f66: mov edx,[ebp+8]
0x5e3f69: cmp byte ptr [edx+39h],0
0x5e3f6d: je short 005E3F73h
0x5e3f6f: mov edi,eax
0x5e3f71: jmp short 005E3F7Eh
0x5e3f73: mov ecx,[esp+74h]
0x5e3f77: cmp ecx,ebp
0x5e3f79: mov edi,[ecx+8]
0x5e3f7c: jne short 005E3FF2h
0x5e3f7e: cmp byte ptr [edi+39h],0
0x5e3f82: mov esi,[ebp+4]
0x5e3f85: jne short 005E3F8Ah
0x5e3f87: mov [edi+4],esi
0x5e3f8a: mov ecx,[esp+68h]
0x5e3f8e: mov eax,[ecx+4]
0x5e3f91: cmp [eax+4],ebp
0x5e3f94: jne short 005E3F9Bh
0x5e3f96: mov [eax+4],edi
0x5e3f99: jmp short 005E3FA6h
0x5e3f9b: cmp [esi],ebp
0x5e3f9d: jne short 005E3FA3h
0x5e3f9f: mov [esi],edi
0x5e3fa1: jmp short 005E3FA6h
0x5e3fa3: mov [esi+8],edi
0x5e3fa6: mov edx,[ecx+4]
0x5e3fa9: cmp [edx],ebp
0x5e3fab: jne short 005E3FCDh
0x5e3fad: cmp byte ptr [edi+39h],0
0x5e3fb1: je short 005E3FB7h
0x5e3fb3: mov ecx,esi
0x5e3fb5: jmp short 005E3FCBh
0x5e3fb7: mov eax,[edi]
0x5e3fb9: cmp byte ptr [eax+39h],0
0x5e3fbd: mov ecx,edi
0x5e3fbf: jne short 005E3FCBh
0x5e3fc1: mov ecx,eax
0x5e3fc3: mov eax,[ecx]
0x5e3fc5: cmp byte ptr [eax+39h],0
0x5e3fc9: je short 005E3FC1h
0x5e3fcb: mov [edx],ecx
0x5e3fcd: mov eax,[esp+68h]
0x5e3fd1: mov ebx,[eax+4]
0x5e3fd4: cmp [ebx+8],ebp
0x5e3fd7: jne short 005E404Eh
0x5e3fd9: cmp byte ptr [edi+39h],0
0x5e3fdd: je short 005E3FE6h
0x5e3fdf: mov eax,esi
0x5e3fe1: mov [ebx+8],eax
0x5e3fe4: jmp short 005E404Eh
0x5e3fe6: mov eax,edi
0x5e3fe8: call 00458540h
0x5e3fed: mov [ebx+8],eax
0x5e3ff0: jmp short 005E404Eh
0x5e3ff2: mov [eax+4],ecx
0x5e3ff5: mov edx,[ebp]
0x5e3ff8: mov [ecx],edx
0x5e3ffa: cmp ecx,[ebp+8]
0x5e3ffd: jne short 005E4003h
0x5e3fff: mov esi,ecx
0x5e4001: jmp short 005E401Dh
0x5e4003: cmp byte ptr [edi+39h],0
0x5e4007: mov esi,[ecx+4]
0x5e400a: jne short 005E400Fh
0x5e400c: mov [edi+4],esi
0x5e400f: mov [esi],edi
0x5e4011: mov eax,[ebp+8]
0x5e4014: mov [ecx+8],eax
0x5e4017: mov edx,[ebp+8]
0x5e401a: mov [edx+4],ecx
0x5e401d: mov eax,[esp+68h]
0x5e4021: mov eax,[eax+4]
0x5e4024: cmp [eax+4],ebp
0x5e4027: jne short 005E402Eh
0x5e4029: mov [eax+4],ecx
0x5e402c: jmp short 005E403Ch
0x5e402e: mov eax,[ebp+4]
0x5e4031: cmp [eax],ebp
0x5e4033: jne short 005E4039h
0x5e4035: mov [eax],ecx
0x5e4037: jmp short 005E403Ch
0x5e4039: mov [eax+8],ecx
0x5e403c: mov edx,[ebp+4]
0x5e403f: mov [ecx+4],edx
0x5e4042: mov dl,[ebp+38h]
0x5e4045: mov al,[ecx+38h]
0x5e4048: mov [ecx+38h],dl
0x5e404b: mov [ebp+38h],al
0x5e404e: mov bl,1
0x5e4050: cmp [ebp+38h],bl
0x5e4053: jne near ptr 005E417Ah
0x5e4059: mov eax,[esp+68h]
0x5e405d: mov ecx,[eax+4]
0x5e4060: cmp edi,[ecx+4]
0x5e4063: je near ptr 005E4177h
0x5e4069: lea esp,[esp]
0x5e4070: cmp [edi+38h],bl
0x5e4073: jne near ptr 005E4177h
0x5e4079: mov ecx,[esi]
0x5e407b: cmp edi,ecx
0x5e407d: jne short 005E40F5h
0x5e407f: mov ecx,[esi+8]
0x5e4082: cmp byte ptr [ecx+38h],0
0x5e4086: jne short 005E409Eh
0x5e4088: mov edx,[esp+68h]
0x5e408c: mov [ecx+38h],bl
0x5e408f: push edx
0x5e4090: mov ecx,esi
0x5e4092: mov byte ptr [esi+38h],0
0x5e4096: call 005F9650h
0x5e409b: mov ecx,[esi+8]
0x5e409e: cmp byte ptr [ecx+39h],0
0x5e40a2: jne near ptr 005E4129h
0x5e40a8: mov eax,[ecx]
0x5e40aa: cmp [eax+38h],bl
0x5e40ad: jne short 005E40B7h
0x5e40af: mov edx,[ecx+8]
0x5e40b2: cmp [edx+38h],bl
0x5e40b5: je short 005E4125h
0x5e40b7: mov eax,[ecx+8]
0x5e40ba: cmp [eax+38h],bl
0x5e40bd: jne short 005E40D5h
0x5e40bf: mov edx,[ecx]
0x5e40c1: mov eax,[esp+68h]
0x5e40c5: mov [edx+38h],bl
0x5e40c8: push eax
0x5e40c9: mov byte ptr [ecx+38h],0
0x5e40cd: call 004DD9C0h
0x5e40d2: mov ecx,[esi+8]
0x5e40d5: mov dl,[esi+38h]
0x5e40d8: mov [ecx+38h],dl
0x5e40db: mov [esi+38h],bl
0x5e40de: mov eax,[ecx+8]
0x5e40e1: mov ecx,[esp+68h]
0x5e40e5: push ecx
0x5e40e6: mov ecx,esi
0x5e40e8: mov [eax+38h],bl
0x5e40eb: call 005F9650h
0x5e40f0: jmp near ptr 005E4177h
0x5e40f5: cmp byte ptr [ecx+38h],0
0x5e40f9: jne short 005E4110h
0x5e40fb: mov eax,[esp+68h]
0x5e40ff: mov [ecx+38h],bl
0x5e4102: push eax
0x5e4103: mov ecx,esi
0x5e4105: mov byte ptr [esi+38h],0
0x5e4109: call 004DD9C0h
0x5e410e: mov ecx,[esi]
0x5e4110: cmp byte ptr [ecx+39h],0
0x5e4114: jne short 005E4129h
0x5e4116: mov edx,[ecx+8]
0x5e4119: cmp [edx+38h],bl
0x5e411c: jne short 005E4140h
0x5e411e: mov eax,[ecx]
0x5e4120: cmp [eax+38h],bl
0x5e4123: jne short 005E4140h
0x5e4125: mov byte ptr [ecx+38h],0
0x5e4129: mov ecx,[esp+68h]
0x5e412d: mov edx,[ecx+4]
0x5e4130: mov edi,esi
0x5e4132: cmp edi,[edx+4]
0x5e4135: mov esi,[esi+4]
0x5e4138: jne near ptr 005E4070h
0x5e413e: jmp short 005E4177h
0x5e4140: mov edx,[ecx]
0x5e4142: cmp [edx+38h],bl
0x5e4145: jne short 005E415Dh
0x5e4147: mov eax,[ecx+8]
0x5e414a: mov edx,[esp+68h]
0x5e414e: mov [eax+38h],bl
0x5e4151: push edx
0x5e4152: mov byte ptr [ecx+38h],0
0x5e4156: call 005F9650h
0x5e415b: mov ecx,[esi]
0x5e415d: mov al,[esi+38h]
0x5e4160: mov edx,[esp+68h]
0x5e4164: mov [ecx+38h],al
0x5e4167: mov [esi+38h],bl
0x5e416a: mov ecx,[ecx]
0x5e416c: mov [ecx+38h],bl
0x5e416f: push edx
0x5e4170: mov ecx,esi
0x5e4172: call 004DD9C0h
0x5e4177: mov [edi+38h],bl
0x5e417a: lea eax,[ebp+0Ch]
0x5e417d: push eax
0x5e417e: call 005E4A20h
0x5e4183: push ebp
0x5e4184: call 006516BAh
0x5e4189: mov ecx,[esp+6Ch]
0x5e418d: mov eax,[ecx+8]
0x5e4190: add esp,4
0x5e4193: test eax,eax
0x5e4195: jbe short 005E419Dh
0x5e4197: add eax,0FFFFFFFFh
0x5e419a: mov [ecx+8],eax
0x5e419d: mov eax,[esp+6Ch]
0x5e41a1: mov ecx,[esp+70h]
0x5e41a5: mov edx,[esp+74h]
0x5e41a9: mov [eax],ecx
0x5e41ab: mov [eax+4],edx
0x5e41ae: mov ecx,[esp+58h]
0x5e41b2: mov fs:[0],ecx
0x5e41b9: pop ecx
0x5e41ba: pop edi
0x5e41bb: pop esi
0x5e41bc: pop ebp
0x5e41bd: pop ebx
0x5e41be: add esp,50h
0x5e41c1: ret 10h
````

`sub_5e3ee0` is called by sub_5e5cd0. It delegates to sub_401230, sub_458540, sub_4dd9c0 (8 callees).

### sub_5e42e0 at 0x5e42e0 (257 instructions)

````text
0x5e42e0: push 0FFFFFFFFh
0x5e42e2: push 7410D9h
0x5e42e7: mov eax,fs:[0]
0x5e42ed: push eax
0x5e42ee: sub esp,44h
0x5e42f1: push ebx
0x5e42f2: push ebp
0x5e42f3: push esi
0x5e42f4: push edi
0x5e42f5: mov eax,ds:[858220h]
0x5e42fa: xor eax,esp
0x5e42fc: push eax
0x5e42fd: lea eax,[esp+58h]
0x5e4301: mov fs:[0],eax
0x5e4307: mov eax,[esp+74h]
0x5e430b: cmp byte ptr [eax+39h],0
0x5e430f: je short 005E434Dh
0x5e4311: push 7C5AECh
0x5e4316: lea ecx,[esp+18h]
0x5e431a: call dword ptr ds:[77CD7Ch]
0x5e4320: lea eax,[esp+14h]
0x5e4324: push eax
0x5e4325: lea ecx,[esp+34h]
0x5e4329: mov dword ptr [esp+64h],0
0x5e4331: call 00401230h
0x5e4336: push 80A4F8h
0x5e433b: lea ecx,[esp+34h]
0x5e433f: push ecx
0x5e4340: mov dword ptr [esp+38h],790F90h
0x5e4348: call 00652AC4h
0x5e434d: lea esi,[esp+70h]
0x5e4351: mov ebp,eax
0x5e4353: call 00633EE0h
0x5e4358: mov eax,[ebp]
0x5e435b: cmp byte ptr [eax+39h],0
0x5e435f: je short 005E4366h
0x5e4361: mov edi,[ebp+8]
0x5e4364: jmp short 005E437Eh
0x5e4366: mov edx,[ebp+8]
0x5e4369: cmp byte ptr [edx+39h],0
0x5e436d: je short 005E4373h
0x5e436f: mov edi,eax
0x5e4371: jmp short 005E437Eh
0x5e4373: mov ecx,[esp+74h]
0x5e4377: cmp ecx,ebp
0x5e4379: mov edi,[ecx+8]
0x5e437c: jne short 005E43F2h
0x5e437e: cmp byte ptr [edi+39h],0
0x5e4382: mov esi,[ebp+4]
0x5e4385: jne short 005E438Ah
0x5e4387: mov [edi+4],esi
0x5e438a: mov ecx,[esp+68h]
0x5e438e: mov eax,[ecx+4]
0x5e4391: cmp [eax+4],ebp
0x5e4394: jne short 005E439Bh
0x5e4396: mov [eax+4],edi
0x5e4399: jmp short 005E43A6h
0x5e439b: cmp [esi],ebp
0x5e439d: jne short 005E43A3h
0x5e439f: mov [esi],edi
0x5e43a1: jmp short 005E43A6h
0x5e43a3: mov [esi+8],edi
0x5e43a6: mov edx,[ecx+4]
0x5e43a9: cmp [edx],ebp
0x5e43ab: jne short 005E43CDh
0x5e43ad: cmp byte ptr [edi+39h],0
0x5e43b1: je short 005E43B7h
0x5e43b3: mov ecx,esi
0x5e43b5: jmp short 005E43CBh
0x5e43b7: mov eax,[edi]
0x5e43b9: cmp byte ptr [eax+39h],0
0x5e43bd: mov ecx,edi
0x5e43bf: jne short 005E43CBh
0x5e43c1: mov ecx,eax
0x5e43c3: mov eax,[ecx]
0x5e43c5: cmp byte ptr [eax+39h],0
0x5e43c9: je short 005E43C1h
0x5e43cb: mov [edx],ecx
0x5e43cd: mov eax,[esp+68h]
0x5e43d1: mov ebx,[eax+4]
0x5e43d4: cmp [ebx+8],ebp
0x5e43d7: jne short 005E444Eh
0x5e43d9: cmp byte ptr [edi+39h],0
0x5e43dd: je short 005E43E6h
0x5e43df: mov eax,esi
0x5e43e1: mov [ebx+8],eax
0x5e43e4: jmp short 005E444Eh
0x5e43e6: mov eax,edi
0x5e43e8: call 00458540h
0x5e43ed: mov [ebx+8],eax
0x5e43f0: jmp short 005E444Eh
0x5e43f2: mov [eax+4],ecx
0x5e43f5: mov edx,[ebp]
0x5e43f8: mov [ecx],edx
0x5e43fa: cmp ecx,[ebp+8]
0x5e43fd: jne short 005E4403h
0x5e43ff: mov esi,ecx
0x5e4401: jmp short 005E441Dh
0x5e4403: cmp byte ptr [edi+39h],0
0x5e4407: mov esi,[ecx+4]
0x5e440a: jne short 005E440Fh
0x5e440c: mov [edi+4],esi
0x5e440f: mov [esi],edi
0x5e4411: mov eax,[ebp+8]
0x5e4414: mov [ecx+8],eax
0x5e4417: mov edx,[ebp+8]
0x5e441a: mov [edx+4],ecx
0x5e441d: mov eax,[esp+68h]
0x5e4421: mov eax,[eax+4]
0x5e4424: cmp [eax+4],ebp
0x5e4427: jne short 005E442Eh
0x5e4429: mov [eax+4],ecx
0x5e442c: jmp short 005E443Ch
0x5e442e: mov eax,[ebp+4]
0x5e4431: cmp [eax],ebp
0x5e4433: jne short 005E4439h
0x5e4435: mov [eax],ecx
0x5e4437: jmp short 005E443Ch
0x5e4439: mov [eax+8],ecx
0x5e443c: mov edx,[ebp+4]
0x5e443f: mov [ecx+4],edx
0x5e4442: mov dl,[ebp+38h]
0x5e4445: mov al,[ecx+38h]
0x5e4448: mov [ecx+38h],dl
0x5e444b: mov [ebp+38h],al
0x5e444e: mov bl,1
0x5e4450: cmp [ebp+38h],bl
0x5e4453: jne near ptr 005E457Ah
0x5e4459: mov eax,[esp+68h]
0x5e445d: mov ecx,[eax+4]
0x5e4460: cmp edi,[ecx+4]
0x5e4463: je near ptr 005E4577h
0x5e4469: lea esp,[esp]
0x5e4470: cmp [edi+38h],bl
0x5e4473: jne near ptr 005E4577h
0x5e4479: mov ecx,[esi]
0x5e447b: cmp edi,ecx
0x5e447d: jne short 005E44F5h
0x5e447f: mov ecx,[esi+8]
0x5e4482: cmp byte ptr [ecx+38h],0
0x5e4486: jne short 005E449Eh
0x5e4488: mov edx,[esp+68h]
0x5e448c: mov [ecx+38h],bl
0x5e448f: push edx
0x5e4490: mov ecx,esi
0x5e4492: mov byte ptr [esi+38h],0
0x5e4496: call 005F9650h
0x5e449b: mov ecx,[esi+8]
0x5e449e: cmp byte ptr [ecx+39h],0
0x5e44a2: jne near ptr 005E4529h
0x5e44a8: mov eax,[ecx]
0x5e44aa: cmp [eax+38h],bl
0x5e44ad: jne short 005E44B7h
0x5e44af: mov edx,[ecx+8]
0x5e44b2: cmp [edx+38h],bl
0x5e44b5: je short 005E4525h
0x5e44b7: mov eax,[ecx+8]
0x5e44ba: cmp [eax+38h],bl
0x5e44bd: jne short 005E44D5h
0x5e44bf: mov edx,[ecx]
0x5e44c1: mov eax,[esp+68h]
0x5e44c5: mov [edx+38h],bl
0x5e44c8: push eax
0x5e44c9: mov byte ptr [ecx+38h],0
0x5e44cd: call 004DD9C0h
0x5e44d2: mov ecx,[esi+8]
0x5e44d5: mov dl,[esi+38h]
0x5e44d8: mov [ecx+38h],dl
0x5e44db: mov [esi+38h],bl
0x5e44de: mov eax,[ecx+8]
0x5e44e1: mov ecx,[esp+68h]
0x5e44e5: push ecx
0x5e44e6: mov ecx,esi
0x5e44e8: mov [eax+38h],bl
0x5e44eb: call 005F9650h
0x5e44f0: jmp near ptr 005E4577h
0x5e44f5: cmp byte ptr [ecx+38h],0
0x5e44f9: jne short 005E4510h
0x5e44fb: mov eax,[esp+68h]
0x5e44ff: mov [ecx+38h],bl
0x5e4502: push eax
0x5e4503: mov ecx,esi
0x5e4505: mov byte ptr [esi+38h],0
0x5e4509: call 004DD9C0h
0x5e450e: mov ecx,[esi]
0x5e4510: cmp byte ptr [ecx+39h],0
0x5e4514: jne short 005E4529h
0x5e4516: mov edx,[ecx+8]
0x5e4519: cmp [edx+38h],bl
0x5e451c: jne short 005E4540h
0x5e451e: mov eax,[ecx]
0x5e4520: cmp [eax+38h],bl
0x5e4523: jne short 005E4540h
0x5e4525: mov byte ptr [ecx+38h],0
0x5e4529: mov ecx,[esp+68h]
0x5e452d: mov edx,[ecx+4]
0x5e4530: mov edi,esi
0x5e4532: cmp edi,[edx+4]
0x5e4535: mov esi,[esi+4]
0x5e4538: jne near ptr 005E4470h
0x5e453e: jmp short 005E4577h
0x5e4540: mov edx,[ecx]
0x5e4542: cmp [edx+38h],bl
0x5e4545: jne short 005E455Dh
0x5e4547: mov eax,[ecx+8]
0x5e454a: mov edx,[esp+68h]
0x5e454e: mov [eax+38h],bl
0x5e4551: push edx
0x5e4552: mov byte ptr [ecx+38h],0
0x5e4556: call 005F9650h
0x5e455b: mov ecx,[esi]
0x5e455d: mov al,[esi+38h]
0x5e4560: mov edx,[esp+68h]
0x5e4564: mov [ecx+38h],al
0x5e4567: mov [esi+38h],bl
0x5e456a: mov ecx,[ecx]
0x5e456c: mov [ecx+38h],bl
0x5e456f: push edx
0x5e4570: mov ecx,esi
0x5e4572: call 004DD9C0h
0x5e4577: mov [edi+38h],bl
0x5e457a: mov eax,[ebp+2Ch]
0x5e457d: lea esi,[ebp+0Ch]
0x5e4580: xor edi,edi
0x5e4582: cmp eax,edi
0x5e4584: je short 005E458Fh
0x5e4586: push eax
0x5e4587: call 006516BAh
0x5e458c: add esp,4
0x5e458f: mov ecx,esi
0x5e4591: mov [esi+20h],edi
0x5e4594: mov [esi+24h],edi
0x5e4597: mov [esi+28h],edi
0x5e459a: call dword ptr ds:[77CD74h]
0x5e45a0: push ebp
0x5e45a1: call 006516BAh
0x5e45a6: mov ecx,[esp+6Ch]
0x5e45aa: mov eax,[ecx+8]
0x5e45ad: add esp,4
0x5e45b0: cmp eax,edi
0x5e45b2: jbe short 005E45BAh
0x5e45b4: add eax,0FFFFFFFFh
0x5e45b7: mov [ecx+8],eax
0x5e45ba: mov eax,[esp+6Ch]
0x5e45be: mov ecx,[esp+70h]
0x5e45c2: mov edx,[esp+74h]
0x5e45c6: mov [eax],ecx
0x5e45c8: mov [eax+4],edx
0x5e45cb: mov ecx,[esp+58h]
0x5e45cf: mov fs:[0],ecx
0x5e45d6: pop ecx
0x5e45d7: pop edi
0x5e45d8: pop esi
0x5e45d9: pop ebp
0x5e45da: pop ebx
0x5e45db: add esp,50h
0x5e45de: ret 10h
````

`sub_5e42e0` is called by sub_5e6050. It delegates to sub_401230, sub_458540, sub_4dd9c0 (7 callees).

### ?get_mutable_instance@?$singleton@VTAF_Manager@@@serialization@boost@@SAAAVTAF_Manager@@XZ at 0x5e47e0 (4 instructions)

````text
0x5e47e0: push ecx
0x5e47e1: call 005E5580h
0x5e47e6: pop ecx
0x5e47e7: ret
````

`?get_mutable_instance@?$singleton@VTAF_Manager@@@serialization@boost@@SAAAVTAF_Manager@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VTAF_Manager@@@serialization@boost@@CAAAVTAF_Manager@@XZ (1 callees).

### sub_5e4990 at 0x5e4990 (42 instructions)

````text
0x5e4990: push 0FFFFFFFFh
0x5e4992: push 73E769h
0x5e4997: mov eax,fs:[0]
0x5e499d: push eax
0x5e499e: push esi
0x5e499f: push edi
0x5e49a0: mov eax,ds:[858220h]
0x5e49a5: xor eax,esp
0x5e49a7: push eax
0x5e49a8: lea eax,[esp+0Ch]
0x5e49ac: mov fs:[0],eax
0x5e49b2: mov edi,[esp+1Ch]
0x5e49b6: mov dword ptr [esp+14h],0
0x5e49be: mov esi,[edi+20h]
0x5e49c1: test esi,esi
0x5e49c3: je short 005E49EFh
0x5e49c5: lea eax,[esi+4]
0x5e49c8: or ecx,0FFFFFFFFh
0x5e49cb: lock xadd [eax],ecx
0x5e49cf: jne short 005E49EFh
0x5e49d1: mov edx,[esi]
0x5e49d3: mov eax,[edx+4]
0x5e49d6: mov ecx,esi
0x5e49d8: call eax
0x5e49da: lea ecx,[esi+8]
0x5e49dd: or edx,0FFFFFFFFh
0x5e49e0: lock xadd [ecx],edx
0x5e49e4: jne short 005E49EFh
0x5e49e6: mov eax,[esi]
0x5e49e8: mov edx,[eax+8]
0x5e49eb: mov ecx,esi
0x5e49ed: call edx
0x5e49ef: mov ecx,edi
0x5e49f1: mov dword ptr [esp+14h],0FFFFFFFFh
0x5e49f9: call dword ptr ds:[77CD74h]
0x5e49ff: mov ecx,[esp+0Ch]
0x5e4a03: mov fs:[0],ecx
0x5e4a0a: pop ecx
0x5e4a0b: pop edi
0x5e4a0c: pop esi
0x5e4a0d: add esp,0Ch
0x5e4a10: ret 4
````

`sub_5e4990` is called by sub_5e3990, sub_5e4aa0. It calls nothing else.

### sub_5e4a20 at 0x5e4a20 (39 instructions)

````text
0x5e4a20: push 0FFFFFFFFh
0x5e4a22: push 73E769h
0x5e4a27: mov eax,fs:[0]
0x5e4a2d: push eax
0x5e4a2e: push esi
0x5e4a2f: push edi
0x5e4a30: mov eax,ds:[858220h]
0x5e4a35: xor eax,esp
0x5e4a37: push eax
0x5e4a38: lea eax,[esp+0Ch]
0x5e4a3c: mov fs:[0],eax
0x5e4a42: mov esi,[esp+1Ch]
0x5e4a46: xor edi,edi
0x5e4a48: mov [esp+14h],edi
0x5e4a4c: mov eax,[esi+20h]
0x5e4a4f: cmp eax,edi
0x5e4a51: je short 005E4A6Dh
0x5e4a53: mov edx,[esp+1Ch]
0x5e4a57: mov ecx,[esi+24h]
0x5e4a5a: push edx
0x5e4a5b: push ecx
0x5e4a5c: call 005DF910h
0x5e4a61: mov eax,[esi+20h]
0x5e4a64: push eax
0x5e4a65: call 006516BAh
0x5e4a6a: add esp,0Ch
0x5e4a6d: mov ecx,esi
0x5e4a6f: mov [esi+20h],edi
0x5e4a72: mov [esi+24h],edi
0x5e4a75: mov [esi+28h],edi
0x5e4a78: mov dword ptr [esp+14h],0FFFFFFFFh
0x5e4a80: call dword ptr ds:[77CD74h]
0x5e4a86: mov ecx,[esp+0Ch]
0x5e4a8a: mov fs:[0],ecx
0x5e4a91: pop ecx
0x5e4a92: pop edi
0x5e4a93: pop esi
0x5e4a94: add esp,0Ch
0x5e4a97: ret 4
````

`sub_5e4a20` is called by sub_5e3ee0, sub_5e6d20. It delegates to sub_5df910, j_ORDINAL 764 (2 callees).

### sub_5e4aa0 at 0x5e4aa0 (26 instructions)

````text
0x5e4aa0: push ebx
0x5e4aa1: push esi
0x5e4aa2: push edi
0x5e4aa3: mov edi,[esp+10h]
0x5e4aa7: cmp byte ptr [edi+31h],0
0x5e4aab: mov ebx,ecx
0x5e4aad: mov esi,edi
0x5e4aaf: jne short 005E4AD8h
0x5e4ab1: mov eax,[esi+8]
0x5e4ab4: push eax
0x5e4ab5: mov ecx,ebx
0x5e4ab7: call 005E4AA0h
0x5e4abc: mov esi,[esi]
0x5e4abe: lea ecx,[edi+0Ch]
0x5e4ac1: push ecx
0x5e4ac2: call 005E4990h
0x5e4ac7: push edi
0x5e4ac8: call 006516BAh
0x5e4acd: add esp,4
0x5e4ad0: cmp byte ptr [esi+31h],0
0x5e4ad4: mov edi,esi
0x5e4ad6: je short 005E4AB1h
0x5e4ad8: pop edi
0x5e4ad9: pop esi
0x5e4ada: pop ebx
0x5e4adb: ret 4
````

`sub_5e4aa0` is called by sub_5e4aa0, sub_5e5800. It delegates to sub_5e4990, sub_5e4aa0, j_ORDINAL 764 (3 callees).

### sub_5e4ae0 at 0x5e4ae0 (28 instructions)

````text
0x5e4ae0: mov eax,[ecx]
0x5e4ae2: mov edx,[eax+8]
0x5e4ae5: mov [ecx],edx
0x5e4ae7: mov edx,[eax+8]
0x5e4aea: cmp byte ptr [edx+31h],0
0x5e4aee: jne short 005E4AF3h
0x5e4af0: mov [edx+4],ecx
0x5e4af3: mov edx,[ecx+4]
0x5e4af6: mov [eax+4],edx
0x5e4af9: mov edx,[esp+4]
0x5e4afd: mov edx,[edx+4]
0x5e4b00: cmp ecx,[edx+4]
0x5e4b03: jne short 005E4B11h
0x5e4b05: mov [edx+4],eax
0x5e4b08: mov [eax+8],ecx
0x5e4b0b: mov [ecx+4],eax
0x5e4b0e: ret 4
0x5e4b11: mov edx,[ecx+4]
0x5e4b14: cmp ecx,[edx+8]
0x5e4b17: jne short 005E4B25h
0x5e4b19: mov [edx+8],eax
0x5e4b1c: mov [eax+8],ecx
0x5e4b1f: mov [ecx+4],eax
0x5e4b22: ret 4
0x5e4b25: mov [edx],eax
0x5e4b27: mov [eax+8],ecx
0x5e4b2a: mov [ecx+4],eax
0x5e4b2d: ret 4
````

`sub_5e4ae0` is called by sub_5e3990. It calls nothing else.

### sub_5e4b30 at 0x5e4b30 (26 instructions)

````text
0x5e4b30: push ebp
0x5e4b31: mov ebp,esp
0x5e4b33: and esp,0FFFFFFF8h
0x5e4b36: sub esp,0Ch
0x5e4b39: push edi
0x5e4b3a: mov edi,eax
0x5e4b3c: mov eax,[edi+4]
0x5e4b3f: mov ecx,[eax]
0x5e4b41: push eax
0x5e4b42: push edi
0x5e4b43: push ecx
0x5e4b44: push edi
0x5e4b45: lea eax,[esp+18h]
0x5e4b49: push eax
0x5e4b4a: call 005E5800h
0x5e4b4f: mov ecx,[edi+4]
0x5e4b52: push ecx
0x5e4b53: call 006516BAh
0x5e4b58: add esp,4
0x5e4b5b: xor eax,eax
0x5e4b5d: mov [edi+4],eax
0x5e4b60: mov [edi+8],eax
0x5e4b63: pop edi
0x5e4b64: mov esp,ebp
0x5e4b66: pop ebp
0x5e4b67: ret
````

`sub_5e4b30` is called by sub_5dfe00, sub_77b3f0, sub_77b400, sub_77b420. It delegates to sub_5e5800, j_ORDINAL 764 (2 callees).

### sub_5e4da0 at 0x5e4da0 (28 instructions)

````text
0x5e4da0: mov eax,[ecx+8]
0x5e4da3: mov edx,[eax]
0x5e4da5: mov [ecx+8],edx
0x5e4da8: mov edx,[eax]
0x5e4daa: cmp byte ptr [edx+31h],0
0x5e4dae: jne short 005E4DB3h
0x5e4db0: mov [edx+4],ecx
0x5e4db3: mov edx,[ecx+4]
0x5e4db6: mov [eax+4],edx
0x5e4db9: mov edx,[esp+4]
0x5e4dbd: mov edx,[edx+4]
0x5e4dc0: cmp ecx,[edx+4]
0x5e4dc3: jne short 005E4DD0h
0x5e4dc5: mov [edx+4],eax
0x5e4dc8: mov [eax],ecx
0x5e4dca: mov [ecx+4],eax
0x5e4dcd: ret 4
0x5e4dd0: mov edx,[ecx+4]
0x5e4dd3: cmp ecx,[edx]
0x5e4dd5: jne short 005E4DE1h
0x5e4dd7: mov [edx],eax
0x5e4dd9: mov [eax],ecx
0x5e4ddb: mov [ecx+4],eax
0x5e4dde: ret 4
0x5e4de1: mov [edx+8],eax
0x5e4de4: mov [eax],ecx
0x5e4de6: mov [ecx+4],eax
0x5e4de9: ret 4
````

`sub_5e4da0` is called by sub_5e3990. It calls nothing else.

### sub_5e5020 at 0x5e5020 (26 instructions)

````text
0x5e5020: push ebp
0x5e5021: mov ebp,esp
0x5e5023: and esp,0FFFFFFF8h
0x5e5026: sub esp,0Ch
0x5e5029: push edi
0x5e502a: mov edi,eax
0x5e502c: mov eax,[edi+4]
0x5e502f: mov ecx,[eax]
0x5e5031: push eax
0x5e5032: push edi
0x5e5033: push ecx
0x5e5034: push edi
0x5e5035: lea eax,[esp+18h]
0x5e5039: push eax
0x5e503a: call 005E5CD0h
0x5e503f: mov ecx,[edi+4]
0x5e5042: push ecx
0x5e5043: call 006516BAh
0x5e5048: add esp,4
0x5e504b: xor eax,eax
0x5e504d: mov [edi+4],eax
0x5e5050: mov [edi+8],eax
0x5e5053: pop edi
0x5e5054: mov esp,ebp
0x5e5056: pop ebp
0x5e5057: ret
````

`sub_5e5020` is called by sub_5dfe00. It delegates to sub_5e5cd0, j_ORDINAL 764 (2 callees).

### sub_5e5290 at 0x5e5290 (26 instructions)

````text
0x5e5290: push ebp
0x5e5291: mov ebp,esp
0x5e5293: and esp,0FFFFFFF8h
0x5e5296: sub esp,0Ch
0x5e5299: push edi
0x5e529a: mov edi,eax
0x5e529c: mov eax,[edi+4]
0x5e529f: mov ecx,[eax]
0x5e52a1: push eax
0x5e52a2: push edi
0x5e52a3: push ecx
0x5e52a4: push edi
0x5e52a5: lea eax,[esp+18h]
0x5e52a9: push eax
0x5e52aa: call 005E6050h
0x5e52af: mov ecx,[edi+4]
0x5e52b2: push ecx
0x5e52b3: call 006516BAh
0x5e52b8: add esp,4
0x5e52bb: xor eax,eax
0x5e52bd: mov [edi+4],eax
0x5e52c0: mov [edi+8],eax
0x5e52c3: pop edi
0x5e52c4: mov esp,ebp
0x5e52c6: pop ebp
0x5e52c7: ret
````

`sub_5e5290` is called by sub_5dfe00. It delegates to sub_5e6050, j_ORDINAL 764 (2 callees).

### sub_5e5500 at 0x5e5500 (26 instructions)

````text
0x5e5500: push ebx
0x5e5501: push esi
0x5e5502: push edi
0x5e5503: mov edi,[esp+10h]
0x5e5507: cmp byte ptr [edi+39h],0
0x5e550b: mov ebx,ecx
0x5e550d: mov esi,edi
0x5e550f: jne short 005E5538h
0x5e5511: mov eax,[esi+8]
0x5e5514: push eax
0x5e5515: mov ecx,ebx
0x5e5517: call 005E5500h
0x5e551c: mov esi,[esi]
0x5e551e: lea ecx,[edi+0Ch]
0x5e5521: push ecx
0x5e5522: call 005DCBB0h
0x5e5527: push edi
0x5e5528: call 006516BAh
0x5e552d: add esp,4
0x5e5530: cmp byte ptr [esi+39h],0
0x5e5534: mov edi,esi
0x5e5536: je short 005E5511h
0x5e5538: pop edi
0x5e5539: pop esi
0x5e553a: pop ebx
0x5e553b: ret 4
````

`sub_5e5500` is called by sub_5e5500, sub_5e63d0. It delegates to sub_5dcbb0, sub_5e5500, j_ORDINAL 764 (3 callees).

### sub_5e5540 at 0x5e5540 (26 instructions)

````text
0x5e5540: push ebp
0x5e5541: mov ebp,esp
0x5e5543: and esp,0FFFFFFF8h
0x5e5546: sub esp,0Ch
0x5e5549: push edi
0x5e554a: mov edi,eax
0x5e554c: mov eax,[edi+4]
0x5e554f: mov ecx,[eax]
0x5e5551: push eax
0x5e5552: push edi
0x5e5553: push ecx
0x5e5554: push edi
0x5e5555: lea eax,[esp+18h]
0x5e5559: push eax
0x5e555a: call 005E63D0h
0x5e555f: mov ecx,[edi+4]
0x5e5562: push ecx
0x5e5563: call 006516BAh
0x5e5568: add esp,4
0x5e556b: xor eax,eax
0x5e556d: mov [edi+4],eax
0x5e5570: mov [edi+8],eax
0x5e5573: pop edi
0x5e5574: mov esp,ebp
0x5e5576: pop ebp
0x5e5577: ret
````

`sub_5e5540` is called by sub_5dfe00. It delegates to sub_5e63d0, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@VTAF_Manager@@@serialization@boost@@CAAAVTAF_Manager@@XZ at 0x5e5580 (25 instructions)

````text
0x5e5580: push 0FFFFFFFFh
0x5e5582: push 76123Eh
0x5e5587: mov eax,fs:[0]
0x5e558d: push eax
0x5e558e: mov eax,ds:[858220h]
0x5e5593: push ecx
0x5e5594: xor eax,esp
0x5e5596: push eax
0x5e5597: lea eax,[esp+8]
0x5e559b: mov fs:[0],eax
0x5e55a1: mov eax,1
0x5e55a6: test ds:[876370h],al
0x5e55ac: jne short 005E55CEh
0x5e55ae: or ds:[876370h],eax
0x5e55b4: mov dword ptr [esp+10h],0
0x5e55bc: call 005DFC30h
0x5e55c1: push 77B440h
0x5e55c6: call 006527EDh
0x5e55cb: add esp,4
0x5e55ce: mov eax,875EC0h
0x5e55d3: mov ecx,[esp+8]
0x5e55d7: mov fs:[0],ecx
0x5e55de: pop ecx
0x5e55df: add esp,10h
0x5e55e2: ret
````

`?get_instance@?$singleton@VTAF_Manager@@@serialization@boost@@CAAAVTAF_Manager@@XZ` is called by ?get_mutable_instance@?$singleton@VTAF_Manager@@@serialization@boost@@SAAAVTAF_Manager@@XZ. It delegates to sub_5dfc30, sub_6527ed (2 callees).

### sub_5e56d0 at 0x5e56d0 (12 instructions)

````text
0x5e56d0: mov eax,[edi]
0x5e56d2: test eax,eax
0x5e56d4: je short 005E56DAh
0x5e56d6: cmp eax,[esi]
0x5e56d8: je short 005E56E0h
0x5e56da: call dword ptr ds:[77D0E4h]
0x5e56e0: mov eax,[edi+4]
0x5e56e3: xor ecx,ecx
0x5e56e5: cmp eax,[esi+4]
0x5e56e8: sete cl
0x5e56eb: mov al,cl
0x5e56ed: ret
````

`sub_5e56d0` is called by sub_465ff0, sub_639c30. It calls nothing else.

### sub_5e5800 at 0x5e5800 (72 instructions)

````text
0x5e5800: mov eax,[edi+4]
0x5e5803: sub esp,0Ch
0x5e5806: push ebx
0x5e5807: mov ebx,[esp+18h]
0x5e580b: test ebx,ebx
0x5e580d: push ebp
0x5e580e: push esi
0x5e580f: mov esi,[eax]
0x5e5811: je short 005E5817h
0x5e5813: cmp ebx,edi
0x5e5815: je short 005E581Dh
0x5e5817: call dword ptr ds:[77D0E4h]
0x5e581d: mov ebp,[esp+24h]
0x5e5821: cmp ebp,esi
0x5e5823: jne short 005E5880h
0x5e5825: mov eax,[esp+28h]
0x5e5829: test eax,eax
0x5e582b: mov esi,[edi+4]
0x5e582e: je short 005E5834h
0x5e5830: cmp eax,edi
0x5e5832: je short 005E583Ah
0x5e5834: call dword ptr ds:[77D0E4h]
0x5e583a: cmp [esp+2Ch],esi
0x5e583e: jne short 005E5880h
0x5e5840: mov ecx,[edi+4]
0x5e5843: mov edx,[ecx+4]
0x5e5846: push edx
0x5e5847: mov ecx,edi
0x5e5849: call 005E4AA0h
0x5e584e: mov eax,[edi+4]
0x5e5851: mov [eax+4],eax
0x5e5854: mov eax,[edi+4]
0x5e5857: mov dword ptr [edi+8],0
0x5e585e: mov [eax],eax
0x5e5860: mov eax,[edi+4]
0x5e5863: mov [eax+8],eax
0x5e5866: mov eax,[edi+4]
0x5e5869: mov ecx,[eax]
0x5e586b: mov eax,[esp+1Ch]
0x5e586f: mov [eax+4],ecx
0x5e5872: mov [eax],edi
0x5e5874: pop esi
0x5e5875: pop ebp
0x5e5876: pop ebx
0x5e5877: add esp,0Ch
0x5e587a: ret 14h
0x5e5880: test ebx,ebx
0x5e5882: je short 005E588Ah
0x5e5884: cmp ebx,[esp+28h]
0x5e5888: je short 005E5890h
0x5e588a: call dword ptr ds:[77D0E4h]
0x5e5890: cmp ebp,[esp+2Ch]
0x5e5894: je short 005E58B6h
0x5e5896: lea esi,[esp+20h]
0x5e589a: call 005919D0h
0x5e589f: push ebp
0x5e58a0: push ebx
0x5e58a1: lea edx,[esp+18h]
0x5e58a5: push edx
0x5e58a6: push edi
0x5e58a7: call 005E3990h
0x5e58ac: mov ebp,[esp+24h]
0x5e58b0: mov ebx,[esp+20h]
0x5e58b4: jmp short 005E5880h
0x5e58b6: mov eax,[esp+1Ch]
0x5e58ba: pop esi
0x5e58bb: mov [eax+4],ebp
0x5e58be: pop ebp
0x5e58bf: mov [eax],ebx
0x5e58c1: pop ebx
0x5e58c2: add esp,0Ch
0x5e58c5: ret 14h
````

`sub_5e5800` is called by sub_5e4b30. It delegates to sub_5919d0, sub_5e3990, sub_5e4aa0 (3 callees).

### sub_5e5cd0 at 0x5e5cd0 (72 instructions)

````text
0x5e5cd0: mov eax,[edi+4]
0x5e5cd3: sub esp,0Ch
0x5e5cd6: push ebx
0x5e5cd7: mov ebx,[esp+18h]
0x5e5cdb: test ebx,ebx
0x5e5cdd: push ebp
0x5e5cde: push esi
0x5e5cdf: mov esi,[eax]
0x5e5ce1: je short 005E5CE7h
0x5e5ce3: cmp ebx,edi
0x5e5ce5: je short 005E5CEDh
0x5e5ce7: call dword ptr ds:[77D0E4h]
0x5e5ced: mov ebp,[esp+24h]
0x5e5cf1: cmp ebp,esi
0x5e5cf3: jne short 005E5D50h
0x5e5cf5: mov eax,[esp+28h]
0x5e5cf9: test eax,eax
0x5e5cfb: mov esi,[edi+4]
0x5e5cfe: je short 005E5D04h
0x5e5d00: cmp eax,edi
0x5e5d02: je short 005E5D0Ah
0x5e5d04: call dword ptr ds:[77D0E4h]
0x5e5d0a: cmp [esp+2Ch],esi
0x5e5d0e: jne short 005E5D50h
0x5e5d10: mov ecx,[edi+4]
0x5e5d13: mov edx,[ecx+4]
0x5e5d16: push edx
0x5e5d17: mov ecx,edi
0x5e5d19: call 005E6D20h
0x5e5d1e: mov eax,[edi+4]
0x5e5d21: mov [eax+4],eax
0x5e5d24: mov eax,[edi+4]
0x5e5d27: mov dword ptr [edi+8],0
0x5e5d2e: mov [eax],eax
0x5e5d30: mov eax,[edi+4]
0x5e5d33: mov [eax+8],eax
0x5e5d36: mov eax,[edi+4]
0x5e5d39: mov ecx,[eax]
0x5e5d3b: mov eax,[esp+1Ch]
0x5e5d3f: mov [eax+4],ecx
0x5e5d42: mov [eax],edi
0x5e5d44: pop esi
0x5e5d45: pop ebp
0x5e5d46: pop ebx
0x5e5d47: add esp,0Ch
0x5e5d4a: ret 14h
0x5e5d50: test ebx,ebx
0x5e5d52: je short 005E5D5Ah
0x5e5d54: cmp ebx,[esp+28h]
0x5e5d58: je short 005E5D60h
0x5e5d5a: call dword ptr ds:[77D0E4h]
0x5e5d60: cmp ebp,[esp+2Ch]
0x5e5d64: je short 005E5D86h
0x5e5d66: lea esi,[esp+20h]
0x5e5d6a: call 00633EE0h
0x5e5d6f: push ebp
0x5e5d70: push ebx
0x5e5d71: lea edx,[esp+18h]
0x5e5d75: push edx
0x5e5d76: push edi
0x5e5d77: call 005E3EE0h
0x5e5d7c: mov ebp,[esp+24h]
0x5e5d80: mov ebx,[esp+20h]
0x5e5d84: jmp short 005E5D50h
0x5e5d86: mov eax,[esp+1Ch]
0x5e5d8a: pop esi
0x5e5d8b: mov [eax+4],ebp
0x5e5d8e: pop ebp
0x5e5d8f: mov [eax],ebx
0x5e5d91: pop ebx
0x5e5d92: add esp,0Ch
0x5e5d95: ret 14h
````

`sub_5e5cd0` is called by sub_5e5020. It delegates to sub_5e3ee0, sub_5e6d20, sub_633ee0 (3 callees).

### sub_5e6050 at 0x5e6050 (72 instructions)

````text
0x5e6050: mov eax,[edi+4]
0x5e6053: sub esp,0Ch
0x5e6056: push ebx
0x5e6057: mov ebx,[esp+18h]
0x5e605b: test ebx,ebx
0x5e605d: push ebp
0x5e605e: push esi
0x5e605f: mov esi,[eax]
0x5e6061: je short 005E6067h
0x5e6063: cmp ebx,edi
0x5e6065: je short 005E606Dh
0x5e6067: call dword ptr ds:[77D0E4h]
0x5e606d: mov ebp,[esp+24h]
0x5e6071: cmp ebp,esi
0x5e6073: jne short 005E60D0h
0x5e6075: mov eax,[esp+28h]
0x5e6079: test eax,eax
0x5e607b: mov esi,[edi+4]
0x5e607e: je short 005E6084h
0x5e6080: cmp eax,edi
0x5e6082: je short 005E608Ah
0x5e6084: call dword ptr ds:[77D0E4h]
0x5e608a: cmp [esp+2Ch],esi
0x5e608e: jne short 005E60D0h
0x5e6090: mov ecx,[edi+4]
0x5e6093: mov edx,[ecx+4]
0x5e6096: push edx
0x5e6097: mov ecx,edi
0x5e6099: call 005E6D60h
0x5e609e: mov eax,[edi+4]
0x5e60a1: mov [eax+4],eax
0x5e60a4: mov eax,[edi+4]
0x5e60a7: mov dword ptr [edi+8],0
0x5e60ae: mov [eax],eax
0x5e60b0: mov eax,[edi+4]
0x5e60b3: mov [eax+8],eax
0x5e60b6: mov eax,[edi+4]
0x5e60b9: mov ecx,[eax]
0x5e60bb: mov eax,[esp+1Ch]
0x5e60bf: mov [eax+4],ecx
0x5e60c2: mov [eax],edi
0x5e60c4: pop esi
0x5e60c5: pop ebp
0x5e60c6: pop ebx
0x5e60c7: add esp,0Ch
0x5e60ca: ret 14h
0x5e60d0: test ebx,ebx
0x5e60d2: je short 005E60DAh
0x5e60d4: cmp ebx,[esp+28h]
0x5e60d8: je short 005E60E0h
0x5e60da: call dword ptr ds:[77D0E4h]
0x5e60e0: cmp ebp,[esp+2Ch]
0x5e60e4: je short 005E6106h
0x5e60e6: lea esi,[esp+20h]
0x5e60ea: call 00633EE0h
0x5e60ef: push ebp
0x5e60f0: push ebx
0x5e60f1: lea edx,[esp+18h]
0x5e60f5: push edx
0x5e60f6: push edi
0x5e60f7: call 005E42E0h
0x5e60fc: mov ebp,[esp+24h]
0x5e6100: mov ebx,[esp+20h]
0x5e6104: jmp short 005E60D0h
0x5e6106: mov eax,[esp+1Ch]
0x5e610a: pop esi
0x5e610b: mov [eax+4],ebp
0x5e610e: pop ebp
0x5e610f: mov [eax],ebx
0x5e6111: pop ebx
0x5e6112: add esp,0Ch
0x5e6115: ret 14h
````

`sub_5e6050` is called by sub_5e5290. It delegates to sub_5e42e0, sub_5e6d60, sub_633ee0 (3 callees).

### sub_5e63d0 at 0x5e63d0 (72 instructions)

````text
0x5e63d0: mov eax,[edi+4]
0x5e63d3: sub esp,0Ch
0x5e63d6: push ebx
0x5e63d7: mov ebx,[esp+18h]
0x5e63db: test ebx,ebx
0x5e63dd: push ebp
0x5e63de: push esi
0x5e63df: mov esi,[eax]
0x5e63e1: je short 005E63E7h
0x5e63e3: cmp ebx,edi
0x5e63e5: je short 005E63EDh
0x5e63e7: call dword ptr ds:[77D0E4h]
0x5e63ed: mov ebp,[esp+24h]
0x5e63f1: cmp ebp,esi
0x5e63f3: jne short 005E6450h
0x5e63f5: mov eax,[esp+28h]
0x5e63f9: test eax,eax
0x5e63fb: mov esi,[edi+4]
0x5e63fe: je short 005E6404h
0x5e6400: cmp eax,edi
0x5e6402: je short 005E640Ah
0x5e6404: call dword ptr ds:[77D0E4h]
0x5e640a: cmp [esp+2Ch],esi
0x5e640e: jne short 005E6450h
0x5e6410: mov ecx,[edi+4]
0x5e6413: mov edx,[ecx+4]
0x5e6416: push edx
0x5e6417: mov ecx,edi
0x5e6419: call 005E5500h
0x5e641e: mov eax,[edi+4]
0x5e6421: mov [eax+4],eax
0x5e6424: mov eax,[edi+4]
0x5e6427: mov dword ptr [edi+8],0
0x5e642e: mov [eax],eax
0x5e6430: mov eax,[edi+4]
0x5e6433: mov [eax+8],eax
0x5e6436: mov eax,[edi+4]
0x5e6439: mov ecx,[eax]
0x5e643b: mov eax,[esp+1Ch]
0x5e643f: mov [eax+4],ecx
0x5e6442: mov [eax],edi
0x5e6444: pop esi
0x5e6445: pop ebp
0x5e6446: pop ebx
0x5e6447: add esp,0Ch
0x5e644a: ret 14h
0x5e6450: test ebx,ebx
0x5e6452: je short 005E645Ah
0x5e6454: cmp ebx,[esp+28h]
0x5e6458: je short 005E6460h
0x5e645a: call dword ptr ds:[77D0E4h]
0x5e6460: cmp ebp,[esp+2Ch]
0x5e6464: je short 005E6486h
0x5e6466: lea esi,[esp+20h]
0x5e646a: call 00633EE0h
0x5e646f: push ebp
0x5e6470: push ebx
0x5e6471: lea edx,[esp+18h]
0x5e6475: push edx
0x5e6476: push edi
0x5e6477: call 005E6990h
0x5e647c: mov ebp,[esp+24h]
0x5e6480: mov ebx,[esp+20h]
0x5e6484: jmp short 005E6450h
0x5e6486: mov eax,[esp+1Ch]
0x5e648a: pop esi
0x5e648b: mov [eax+4],ebp
0x5e648e: pop ebp
0x5e648f: mov [eax],ebx
0x5e6491: pop ebx
0x5e6492: add esp,0Ch
0x5e6495: ret 14h
````

`sub_5e63d0` is called by sub_5e5540. It delegates to sub_5e5500, sub_5e6990, sub_633ee0 (3 callees).

### sub_5e6990 at 0x5e6990 (247 instructions)

````text
0x5e6990: push 0FFFFFFFFh
0x5e6992: push 7410D9h
0x5e6997: mov eax,fs:[0]
0x5e699d: push eax
0x5e699e: sub esp,44h
0x5e69a1: push ebx
0x5e69a2: push ebp
0x5e69a3: push esi
0x5e69a4: push edi
0x5e69a5: mov eax,ds:[858220h]
0x5e69aa: xor eax,esp
0x5e69ac: push eax
0x5e69ad: lea eax,[esp+58h]
0x5e69b1: mov fs:[0],eax
0x5e69b7: mov eax,[esp+74h]
0x5e69bb: cmp byte ptr [eax+39h],0
0x5e69bf: je short 005E69FDh
0x5e69c1: push 7C5AECh
0x5e69c6: lea ecx,[esp+18h]
0x5e69ca: call dword ptr ds:[77CD7Ch]
0x5e69d0: lea eax,[esp+14h]
0x5e69d4: push eax
0x5e69d5: lea ecx,[esp+34h]
0x5e69d9: mov dword ptr [esp+64h],0
0x5e69e1: call 00401230h
0x5e69e6: push 80A4F8h
0x5e69eb: lea ecx,[esp+34h]
0x5e69ef: push ecx
0x5e69f0: mov dword ptr [esp+38h],790F90h
0x5e69f8: call 00652AC4h
0x5e69fd: lea esi,[esp+70h]
0x5e6a01: mov ebp,eax
0x5e6a03: call 00633EE0h
0x5e6a08: mov eax,[ebp]
0x5e6a0b: cmp byte ptr [eax+39h],0
0x5e6a0f: je short 005E6A16h
0x5e6a11: mov edi,[ebp+8]
0x5e6a14: jmp short 005E6A2Eh
0x5e6a16: mov edx,[ebp+8]
0x5e6a19: cmp byte ptr [edx+39h],0
0x5e6a1d: je short 005E6A23h
0x5e6a1f: mov edi,eax
0x5e6a21: jmp short 005E6A2Eh
0x5e6a23: mov ecx,[esp+74h]
0x5e6a27: cmp ecx,ebp
0x5e6a29: mov edi,[ecx+8]
0x5e6a2c: jne short 005E6AA2h
0x5e6a2e: cmp byte ptr [edi+39h],0
0x5e6a32: mov esi,[ebp+4]
0x5e6a35: jne short 005E6A3Ah
0x5e6a37: mov [edi+4],esi
0x5e6a3a: mov ecx,[esp+68h]
0x5e6a3e: mov eax,[ecx+4]
0x5e6a41: cmp [eax+4],ebp
0x5e6a44: jne short 005E6A4Bh
0x5e6a46: mov [eax+4],edi
0x5e6a49: jmp short 005E6A56h
0x5e6a4b: cmp [esi],ebp
0x5e6a4d: jne short 005E6A53h
0x5e6a4f: mov [esi],edi
0x5e6a51: jmp short 005E6A56h
0x5e6a53: mov [esi+8],edi
0x5e6a56: mov edx,[ecx+4]
0x5e6a59: cmp [edx],ebp
0x5e6a5b: jne short 005E6A7Dh
0x5e6a5d: cmp byte ptr [edi+39h],0
0x5e6a61: je short 005E6A67h
0x5e6a63: mov ecx,esi
0x5e6a65: jmp short 005E6A7Bh
0x5e6a67: mov eax,[edi]
0x5e6a69: cmp byte ptr [eax+39h],0
0x5e6a6d: mov ecx,edi
0x5e6a6f: jne short 005E6A7Bh
0x5e6a71: mov ecx,eax
0x5e6a73: mov eax,[ecx]
0x5e6a75: cmp byte ptr [eax+39h],0
0x5e6a79: je short 005E6A71h
0x5e6a7b: mov [edx],ecx
0x5e6a7d: mov eax,[esp+68h]
0x5e6a81: mov ebx,[eax+4]
0x5e6a84: cmp [ebx+8],ebp
0x5e6a87: jne short 005E6AFEh
0x5e6a89: cmp byte ptr [edi+39h],0
0x5e6a8d: je short 005E6A96h
0x5e6a8f: mov eax,esi
0x5e6a91: mov [ebx+8],eax
0x5e6a94: jmp short 005E6AFEh
0x5e6a96: mov eax,edi
0x5e6a98: call 00458540h
0x5e6a9d: mov [ebx+8],eax
0x5e6aa0: jmp short 005E6AFEh
0x5e6aa2: mov [eax+4],ecx
0x5e6aa5: mov edx,[ebp]
0x5e6aa8: mov [ecx],edx
0x5e6aaa: cmp ecx,[ebp+8]
0x5e6aad: jne short 005E6AB3h
0x5e6aaf: mov esi,ecx
0x5e6ab1: jmp short 005E6ACDh
0x5e6ab3: cmp byte ptr [edi+39h],0
0x5e6ab7: mov esi,[ecx+4]
0x5e6aba: jne short 005E6ABFh
0x5e6abc: mov [edi+4],esi
0x5e6abf: mov [esi],edi
0x5e6ac1: mov eax,[ebp+8]
0x5e6ac4: mov [ecx+8],eax
0x5e6ac7: mov edx,[ebp+8]
0x5e6aca: mov [edx+4],ecx
0x5e6acd: mov eax,[esp+68h]
0x5e6ad1: mov eax,[eax+4]
0x5e6ad4: cmp [eax+4],ebp
0x5e6ad7: jne short 005E6ADEh
0x5e6ad9: mov [eax+4],ecx
0x5e6adc: jmp short 005E6AECh
0x5e6ade: mov eax,[ebp+4]
0x5e6ae1: cmp [eax],ebp
0x5e6ae3: jne short 005E6AE9h
0x5e6ae5: mov [eax],ecx
0x5e6ae7: jmp short 005E6AECh
0x5e6ae9: mov [eax+8],ecx
0x5e6aec: mov edx,[ebp+4]
0x5e6aef: mov [ecx+4],edx
0x5e6af2: mov dl,[ebp+38h]
0x5e6af5: mov al,[ecx+38h]
0x5e6af8: mov [ecx+38h],dl
0x5e6afb: mov [ebp+38h],al
0x5e6afe: mov bl,1
0x5e6b00: cmp [ebp+38h],bl
0x5e6b03: jne near ptr 005E6C2Ah
0x5e6b09: mov eax,[esp+68h]
0x5e6b0d: mov ecx,[eax+4]
0x5e6b10: cmp edi,[ecx+4]
0x5e6b13: je near ptr 005E6C27h
0x5e6b19: lea esp,[esp]
0x5e6b20: cmp [edi+38h],bl
0x5e6b23: jne near ptr 005E6C27h
0x5e6b29: mov ecx,[esi]
0x5e6b2b: cmp edi,ecx
0x5e6b2d: jne short 005E6BA5h
0x5e6b2f: mov ecx,[esi+8]
0x5e6b32: cmp byte ptr [ecx+38h],0
0x5e6b36: jne short 005E6B4Eh
0x5e6b38: mov edx,[esp+68h]
0x5e6b3c: mov [ecx+38h],bl
0x5e6b3f: push edx
0x5e6b40: mov ecx,esi
0x5e6b42: mov byte ptr [esi+38h],0
0x5e6b46: call 005F9650h
0x5e6b4b: mov ecx,[esi+8]
0x5e6b4e: cmp byte ptr [ecx+39h],0
0x5e6b52: jne near ptr 005E6BD9h
0x5e6b58: mov eax,[ecx]
0x5e6b5a: cmp [eax+38h],bl
0x5e6b5d: jne short 005E6B67h
0x5e6b5f: mov edx,[ecx+8]
0x5e6b62: cmp [edx+38h],bl
0x5e6b65: je short 005E6BD5h
0x5e6b67: mov eax,[ecx+8]
0x5e6b6a: cmp [eax+38h],bl
0x5e6b6d: jne short 005E6B85h
0x5e6b6f: mov edx,[ecx]
0x5e6b71: mov eax,[esp+68h]
0x5e6b75: mov [edx+38h],bl
0x5e6b78: push eax
0x5e6b79: mov byte ptr [ecx+38h],0
0x5e6b7d: call 004DD9C0h
0x5e6b82: mov ecx,[esi+8]
0x5e6b85: mov dl,[esi+38h]
0x5e6b88: mov [ecx+38h],dl
0x5e6b8b: mov [esi+38h],bl
0x5e6b8e: mov eax,[ecx+8]
0x5e6b91: mov ecx,[esp+68h]
0x5e6b95: push ecx
0x5e6b96: mov ecx,esi
0x5e6b98: mov [eax+38h],bl
0x5e6b9b: call 005F9650h
0x5e6ba0: jmp near ptr 005E6C27h
0x5e6ba5: cmp byte ptr [ecx+38h],0
0x5e6ba9: jne short 005E6BC0h
0x5e6bab: mov eax,[esp+68h]
0x5e6baf: mov [ecx+38h],bl
0x5e6bb2: push eax
0x5e6bb3: mov ecx,esi
0x5e6bb5: mov byte ptr [esi+38h],0
0x5e6bb9: call 004DD9C0h
0x5e6bbe: mov ecx,[esi]
0x5e6bc0: cmp byte ptr [ecx+39h],0
0x5e6bc4: jne short 005E6BD9h
0x5e6bc6: mov edx,[ecx+8]
0x5e6bc9: cmp [edx+38h],bl
0x5e6bcc: jne short 005E6BF0h
0x5e6bce: mov eax,[ecx]
0x5e6bd0: cmp [eax+38h],bl
0x5e6bd3: jne short 005E6BF0h
0x5e6bd5: mov byte ptr [ecx+38h],0
0x5e6bd9: mov ecx,[esp+68h]
0x5e6bdd: mov edx,[ecx+4]
0x5e6be0: mov edi,esi
0x5e6be2: cmp edi,[edx+4]
0x5e6be5: mov esi,[esi+4]
0x5e6be8: jne near ptr 005E6B20h
0x5e6bee: jmp short 005E6C27h
0x5e6bf0: mov edx,[ecx]
0x5e6bf2: cmp [edx+38h],bl
0x5e6bf5: jne short 005E6C0Dh
0x5e6bf7: mov eax,[ecx+8]
0x5e6bfa: mov edx,[esp+68h]
0x5e6bfe: mov [eax+38h],bl
0x5e6c01: push edx
0x5e6c02: mov byte ptr [ecx+38h],0
0x5e6c06: call 005F9650h
0x5e6c0b: mov ecx,[esi]
0x5e6c0d: mov al,[esi+38h]
0x5e6c10: mov edx,[esp+68h]
0x5e6c14: mov [ecx+38h],al
0x5e6c17: mov [esi+38h],bl
0x5e6c1a: mov ecx,[ecx]
0x5e6c1c: mov [ecx+38h],bl
0x5e6c1f: push edx
0x5e6c20: mov ecx,esi
0x5e6c22: call 004DD9C0h
0x5e6c27: mov [edi+38h],bl
0x5e6c2a: lea eax,[ebp+0Ch]
0x5e6c2d: push eax
0x5e6c2e: call 005DCBB0h
0x5e6c33: push ebp
0x5e6c34: call 006516BAh
0x5e6c39: mov ecx,[esp+6Ch]
0x5e6c3d: mov eax,[ecx+8]
0x5e6c40: add esp,4
0x5e6c43: test eax,eax
0x5e6c45: jbe short 005E6C4Dh
0x5e6c47: add eax,0FFFFFFFFh
0x5e6c4a: mov [ecx+8],eax
0x5e6c4d: mov eax,[esp+6Ch]
0x5e6c51: mov ecx,[esp+70h]
0x5e6c55: mov edx,[esp+74h]
0x5e6c59: mov [eax],ecx
0x5e6c5b: mov [eax+4],edx
0x5e6c5e: mov ecx,[esp+58h]
0x5e6c62: mov fs:[0],ecx
0x5e6c69: pop ecx
0x5e6c6a: pop edi
0x5e6c6b: pop esi
0x5e6c6c: pop ebp
0x5e6c6d: pop ebx
0x5e6c6e: add esp,50h
0x5e6c71: ret 10h
````

`sub_5e6990` is called by sub_5e63d0. It delegates to sub_401230, sub_458540, sub_4dd9c0 (8 callees).

### sub_5e6d20 at 0x5e6d20 (26 instructions)

````text
0x5e6d20: push ebx
0x5e6d21: push esi
0x5e6d22: push edi
0x5e6d23: mov edi,[esp+10h]
0x5e6d27: cmp byte ptr [edi+39h],0
0x5e6d2b: mov ebx,ecx
0x5e6d2d: mov esi,edi
0x5e6d2f: jne short 005E6D58h
0x5e6d31: mov eax,[esi+8]
0x5e6d34: push eax
0x5e6d35: mov ecx,ebx
0x5e6d37: call 005E6D20h
0x5e6d3c: mov esi,[esi]
0x5e6d3e: lea ecx,[edi+0Ch]
0x5e6d41: push ecx
0x5e6d42: call 005E4A20h
0x5e6d47: push edi
0x5e6d48: call 006516BAh
0x5e6d4d: add esp,4
0x5e6d50: cmp byte ptr [esi+39h],0
0x5e6d54: mov edi,esi
0x5e6d56: je short 005E6D31h
0x5e6d58: pop edi
0x5e6d59: pop esi
0x5e6d5a: pop ebx
0x5e6d5b: ret 4
````

`sub_5e6d20` is called by sub_5e5cd0, sub_5e6d20. It delegates to sub_5e4a20, sub_5e6d20, j_ORDINAL 764 (3 callees).

### sub_5e6d60 at 0x5e6d60 (39 instructions)

````text
0x5e6d60: push ebx
0x5e6d61: push ebp
0x5e6d62: mov ebp,[esp+0Ch]
0x5e6d66: cmp byte ptr [ebp+39h],0
0x5e6d6a: push esi
0x5e6d6b: mov ebx,ecx
0x5e6d6d: mov esi,ebp
0x5e6d6f: jne short 005E6DB9h
0x5e6d71: push edi
0x5e6d72: mov eax,[esi+8]
0x5e6d75: push eax
0x5e6d76: mov ecx,ebx
0x5e6d78: call 005E6D60h
0x5e6d7d: mov eax,[ebp+2Ch]
0x5e6d80: mov esi,[esi]
0x5e6d82: lea edi,[ebp+0Ch]
0x5e6d85: xor ecx,ecx
0x5e6d87: cmp eax,ecx
0x5e6d89: je short 005E6D96h
0x5e6d8b: push eax
0x5e6d8c: call 006516BAh
0x5e6d91: add esp,4
0x5e6d94: xor ecx,ecx
0x5e6d96: mov [edi+20h],ecx
0x5e6d99: mov [edi+24h],ecx
0x5e6d9c: mov [edi+28h],ecx
0x5e6d9f: mov ecx,edi
0x5e6da1: call dword ptr ds:[77CD74h]
0x5e6da7: push ebp
0x5e6da8: call 006516BAh
0x5e6dad: add esp,4
0x5e6db0: cmp byte ptr [esi+39h],0
0x5e6db4: mov ebp,esi
0x5e6db6: je short 005E6D72h
0x5e6db8: pop edi
0x5e6db9: pop esi
0x5e6dba: pop ebp
0x5e6dbb: pop ebx
0x5e6dbc: ret 4
````

`sub_5e6d60` is called by sub_5e6050, sub_5e6d60. It delegates to sub_5e6d60, j_ORDINAL 764 (2 callees).

### sub_5e87e0 at 0x5e87e0 (22 instructions)

````text
0x5e87e0: push 0FFFFFFFFh
0x5e87e2: push 739029h
0x5e87e7: mov eax,fs:[0]
0x5e87ed: push eax
0x5e87ee: push ecx
0x5e87ef: mov eax,ds:[858220h]
0x5e87f4: xor eax,esp
0x5e87f6: push eax
0x5e87f7: lea eax,[esp+8]
0x5e87fb: mov fs:[0],eax
0x5e8801: mov ecx,875D24h
0x5e8806: call dword ptr ds:[77DF80h]
0x5e880c: xor eax,eax
0x5e880e: mov ds:[875D30h],eax
0x5e8813: mov ds:[875D34h],eax
0x5e8818: mov ds:[875D38h],eax
0x5e881d: mov eax,875D24h
0x5e8822: mov ecx,[esp+8]
0x5e8826: mov fs:[0],ecx
0x5e882d: pop ecx
0x5e882e: add esp,10h
0x5e8831: ret
````

`sub_5e87e0` is called by ?get_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@CAAAVTAF_TemplateManager@@XZ. It calls nothing else.

### ?get_mutable_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@SAAAVTAF_TemplateManager@@XZ at 0x5e9fe0 (4 instructions)

````text
0x5e9fe0: push ecx
0x5e9fe1: call 005EA080h
0x5e9fe6: pop ecx
0x5e9fe7: ret
````

`?get_mutable_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@SAAAVTAF_TemplateManager@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@CAAAVTAF_TemplateManager@@XZ (1 callees).

### ?get_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@CAAAVTAF_TemplateManager@@XZ at 0x5ea080 (25 instructions)

````text
0x5ea080: push 0FFFFFFFFh
0x5ea082: push 74FAEEh
0x5ea087: mov eax,fs:[0]
0x5ea08d: push eax
0x5ea08e: mov eax,ds:[858220h]
0x5ea093: push ecx
0x5ea094: xor eax,esp
0x5ea096: push eax
0x5ea097: lea eax,[esp+8]
0x5ea09b: mov fs:[0],eax
0x5ea0a1: mov eax,1
0x5ea0a6: test ds:[875DB0h],al
0x5ea0ac: jne short 005EA0CEh
0x5ea0ae: or ds:[875DB0h],eax
0x5ea0b4: mov dword ptr [esp+10h],0
0x5ea0bc: call 005E87E0h
0x5ea0c1: push 77B450h
0x5ea0c6: call 006527EDh
0x5ea0cb: add esp,4
0x5ea0ce: mov eax,875D24h
0x5ea0d3: mov ecx,[esp+8]
0x5ea0d7: mov fs:[0],ecx
0x5ea0de: pop ecx
0x5ea0df: add esp,10h
0x5ea0e2: ret
````

`?get_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@CAAAVTAF_TemplateManager@@XZ` is called by ?get_mutable_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@SAAAVTAF_TemplateManager@@XZ. It delegates to sub_5e87e0, sub_6527ed (2 callees).

### sub_5ea5d0 at 0x5ea5d0 (225 instructions)

````text
0x5ea5d0: push 0FFFFFFFFh
0x5ea5d2: push 7548F3h
0x5ea5d7: mov eax,fs:[0]
0x5ea5dd: push eax
0x5ea5de: sub esp,2Ch
0x5ea5e1: push ebx
0x5ea5e2: push esi
0x5ea5e3: mov eax,ds:[858220h]
0x5ea5e8: xor eax,esp
0x5ea5ea: push eax
0x5ea5eb: lea eax,[esp+38h]
0x5ea5ef: mov fs:[0],eax
0x5ea5f5: xor ebx,ebx
0x5ea5f7: mov [esp+10h],ebx
0x5ea5fb: mov esi,874D80h
0x5ea600: mov [esp+14h],esi
0x5ea604: mov dword ptr ds:[874D80h],7F4C44h
0x5ea60e: mov dword ptr ds:[874D84h],186A0h
0x5ea618: mov ds:[874D8Ch],ebx
0x5ea61e: mov ds:[874D90h],ebx
0x5ea624: mov ds:[874D94h],ebx
0x5ea62a: mov [esp+40h],ebx
0x5ea62e: mov ds:[874D98h],ebx
0x5ea634: mov ds:[874D9Ch],ebx
0x5ea63a: mov ds:[874DA0h],ebx
0x5ea640: mov ds:[874DA4h],ebx
0x5ea646: mov ds:[874DA8h],ebx
0x5ea64c: mov ds:[874DACh],ebx
0x5ea652: mov ds:[874DB4h],ebx
0x5ea658: mov ds:[874DB8h],ebx
0x5ea65e: mov ds:[874DBCh],ebx
0x5ea664: mov ds:[874DC4h],ebx
0x5ea66a: mov ds:[874DC8h],ebx
0x5ea670: mov ds:[874DCCh],ebx
0x5ea676: mov byte ptr [esp+40h],5
0x5ea67b: call 00633900h
0x5ea680: mov ds:[874DD4h],eax
0x5ea685: mov byte ptr [eax+39h],1
0x5ea689: mov eax,ds:[874DD4h]
0x5ea68e: mov [eax+4],eax
0x5ea691: mov eax,ds:[874DD4h]
0x5ea696: mov [eax],eax
0x5ea698: mov eax,ds:[874DD4h]
0x5ea69d: mov [eax+8],eax
0x5ea6a0: mov ds:[874DD8h],ebx
0x5ea6a6: mov ds:[874DDCh],ebx
0x5ea6ac: mov ds:[874DE0h],ebx
0x5ea6b2: push ebx
0x5ea6b3: push 874DE4h
0x5ea6b8: mov byte ptr [esp+48h],7
0x5ea6bd: call 004DDD40h
0x5ea6c2: mov ecx,874E20h
0x5ea6c7: mov byte ptr [esp+40h],8
0x5ea6cc: call dword ptr ds:[77DF80h]
0x5ea6d2: mov ds:[874E2Ch],ebx
0x5ea6d8: mov ds:[874E30h],ebx
0x5ea6de: mov ds:[874E34h],ebx
0x5ea6e4: mov ds:[874E38h],ebx
0x5ea6ea: mov byte ptr [esp+40h],0Ah
0x5ea6ef: call 005F0BC0h
0x5ea6f4: mov ds:[874E40h],eax
0x5ea6f9: mov byte ptr [eax+19h],1
0x5ea6fd: mov eax,ds:[874E40h]
0x5ea702: mov [eax+4],eax
0x5ea705: mov eax,ds:[874E40h]
0x5ea70a: mov [eax],eax
0x5ea70c: mov eax,ds:[874E40h]
0x5ea711: mov [eax+8],eax
0x5ea714: mov ds:[874E44h],ebx
0x5ea71a: mov ds:[874E48h],ebx
0x5ea720: mov ds:[874E4Ch],ebx
0x5ea726: push 20h
0x5ea728: mov byte ptr [esp+44h],0Ch
0x5ea72d: call 006516C0h
0x5ea732: add esp,4
0x5ea735: cmp eax,ebx
0x5ea737: je short 005EA75Dh
0x5ea739: mov [eax+4],ebx
0x5ea73c: mov [eax+8],ebx
0x5ea73f: mov dword ptr [eax+0Ch],0C8h
0x5ea746: mov [eax+10h],ebx
0x5ea749: mov [eax+14h],ebx
0x5ea74c: mov [eax+18h],bl
0x5ea74f: mov [eax+19h],bl
0x5ea752: mov dword ptr [eax],7F4C4Ch
0x5ea758: mov [eax+1Ch],esi
0x5ea75b: jmp short 005EA75Fh
0x5ea75d: xor eax,eax
0x5ea75f: push 38h
0x5ea761: mov ds:[874E50h],eax
0x5ea766: call 006516C0h
0x5ea76b: mov esi,eax
0x5ea76d: add esp,4
0x5ea770: mov [esp+18h],esi
0x5ea774: cmp esi,ebx
0x5ea776: mov byte ptr [esp+40h],0Dh
0x5ea77b: je short 005EA7C8h
0x5ea77d: push 7C72A0h
0x5ea782: lea ecx,[esp+20h]
0x5ea786: call dword ptr ds:[77CD7Ch]
0x5ea78c: lea eax,[esp+1Ch]
0x5ea790: mov byte ptr [esp+40h],0Eh
0x5ea795: push eax
0x5ea796: lea ecx,[esi+4]
0x5ea799: mov dword ptr [esp+14h],1
0x5ea7a1: mov dword ptr [esi],7F4DF4h
0x5ea7a7: call dword ptr ds:[77CD78h]
0x5ea7ad: fldz
0x5ea7af: fstp qword ptr [esi+30h]
0x5ea7b2: mov dword ptr [esi+20h],2
0x5ea7b9: mov byte ptr [esi+24h],1
0x5ea7bd: mov dword ptr [esi],7F4E2Ch
0x5ea7c3: mov [esi+2Ah],bl
0x5ea7c6: jmp short 005EA7CAh
0x5ea7c8: xor esi,esi
0x5ea7ca: mov dword ptr [esp+40h],0Ch
0x5ea7d2: test byte ptr [esp+10h],1
0x5ea7d7: je short 005EA7E8h
0x5ea7d9: and dword ptr [esp+10h],0FFFFFFFEh
0x5ea7de: lea ecx,[esp+1Ch]
0x5ea7e2: call dword ptr ds:[77CD74h]
0x5ea7e8: mov ecx,esi
0x5ea7ea: mov eax,874D98h
0x5ea7ef: mov word ptr [esi+28h],67h
0x5ea7f5: call 0044BE60h
0x5ea7fa: push 38h
0x5ea7fc: call 006516C0h
0x5ea801: mov esi,eax
0x5ea803: add esp,4
0x5ea806: mov [esp+18h],esi
0x5ea80a: cmp esi,ebx
0x5ea80c: mov byte ptr [esp+40h],10h
0x5ea811: je short 005EA85Bh
0x5ea813: push 7C7254h
0x5ea818: lea ecx,[esp+20h]
0x5ea81c: call dword ptr ds:[77CD7Ch]
0x5ea822: lea ecx,[esp+1Ch]
0x5ea826: mov byte ptr [esp+40h],11h
0x5ea82b: or dword ptr [esp+10h],2
0x5ea830: push ecx
0x5ea831: lea ecx,[esi+4]
0x5ea834: mov dword ptr [esi],7F4DF4h
0x5ea83a: call dword ptr ds:[77CD78h]
0x5ea840: fldz
0x5ea842: fstp qword ptr [esi+30h]
0x5ea845: mov dword ptr [esi+20h],2
0x5ea84c: mov byte ptr [esi+24h],1
0x5ea850: mov dword ptr [esi],7F4E2Ch
0x5ea856: mov [esi+2Ah],bl
0x5ea859: jmp short 005EA85Dh
0x5ea85b: xor esi,esi
0x5ea85d: mov dword ptr [esp+40h],0Ch
0x5ea865: test byte ptr [esp+10h],2
0x5ea86a: je short 005EA87Bh
0x5ea86c: and dword ptr [esp+10h],0FFFFFFFDh
0x5ea871: lea ecx,[esp+1Ch]
0x5ea875: call dword ptr ds:[77CD74h]
0x5ea87b: mov ecx,esi
0x5ea87d: mov eax,874DA0h
0x5ea882: mov word ptr [esi+28h],0CAh
0x5ea888: call 0044BE60h
0x5ea88d: push 38h
0x5ea88f: call 006516C0h
0x5ea894: mov esi,eax
0x5ea896: add esp,4
0x5ea899: mov [esp+18h],esi
0x5ea89d: cmp esi,ebx
0x5ea89f: mov byte ptr [esp+40h],13h
0x5ea8a4: je short 005EA8EEh
0x5ea8a6: push 7C7248h
0x5ea8ab: lea ecx,[esp+20h]
0x5ea8af: call dword ptr ds:[77CD7Ch]
0x5ea8b5: lea edx,[esp+1Ch]
0x5ea8b9: mov byte ptr [esp+40h],14h
0x5ea8be: or dword ptr [esp+10h],4
0x5ea8c3: push edx
0x5ea8c4: lea ecx,[esi+4]
0x5ea8c7: mov dword ptr [esi],7F4DF4h
0x5ea8cd: call dword ptr ds:[77CD78h]
0x5ea8d3: fldz
0x5ea8d5: fstp qword ptr [esi+30h]
0x5ea8d8: mov dword ptr [esi+20h],2
0x5ea8df: mov byte ptr [esi+24h],1
0x5ea8e3: mov dword ptr [esi],7F4E2Ch
0x5ea8e9: mov [esi+2Ah],bl
0x5ea8ec: jmp short 005EA8F0h
0x5ea8ee: xor esi,esi
0x5ea8f0: mov dword ptr [esp+40h],0Ch
0x5ea8f8: test byte ptr [esp+10h],4
0x5ea8fd: je short 005EA909h
0x5ea8ff: lea ecx,[esp+1Ch]
0x5ea903: call dword ptr ds:[77CD74h]
0x5ea909: mov ecx,esi
0x5ea90b: mov eax,874DA8h
0x5ea910: mov word ptr [esi+28h],0CBh
0x5ea916: call 0044BE60h
0x5ea91b: push 24h
0x5ea91d: call 006516C0h
0x5ea922: mov esi,eax
0x5ea924: add esp,4
0x5ea927: mov [esp+18h],esi
0x5ea92b: cmp esi,ebx
0x5ea92d: mov byte ptr [esp+40h],16h
0x5ea932: je short 005EA93Fh
0x5ea934: lea ecx,[esi+4]
0x5ea937: call dword ptr ds:[77CD80h]
0x5ea93d: jmp short 005EA941h
0x5ea93f: xor esi,esi
0x5ea941: push 7C31C7h
0x5ea946: lea ecx,[esi+4]
0x5ea949: mov byte ptr [esp+44h],0Ch
0x5ea94e: call dword ptr ds:[77CD50h]
0x5ea954: mov ecx,esi
0x5ea956: mov eax,874DDCh
0x5ea95b: mov [esi],ebx
0x5ea95d: mov [esi+20h],ebx
0x5ea960: call 005F0C60h
0x5ea965: mov eax,874D80h
0x5ea96a: mov ecx,[esp+38h]
0x5ea96e: mov fs:[0],ecx
0x5ea975: pop ecx
0x5ea976: pop esi
0x5ea977: pop ebx
0x5ea978: add esp,38h
0x5ea97b: ret
````

`sub_5ea5d0` is called by ?get_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@CAAAVTAS_Alerter@@XZ. It delegates to sub_44be60, sub_4ddd40, sub_5f0bc0 (6 callees).

### sub_5ea9c0 at 0x5ea9c0 (196 instructions)

````text
0x5ea9c0: push 0FFFFFFFFh
0x5ea9c2: push 761099h
0x5ea9c7: mov eax,fs:[0]
0x5ea9cd: push eax
0x5ea9ce: sub esp,8
0x5ea9d1: push ebx
0x5ea9d2: push esi
0x5ea9d3: push edi
0x5ea9d4: mov eax,ds:[858220h]
0x5ea9d9: xor eax,esp
0x5ea9db: push eax
0x5ea9dc: lea eax,[esp+18h]
0x5ea9e0: mov fs:[0],eax
0x5ea9e6: mov edi,ecx
0x5ea9e8: mov [esp+14h],edi
0x5ea9ec: mov dword ptr [edi],7F4C44h
0x5ea9f2: lea ebx,[edi+64h]
0x5ea9f5: push ebx
0x5ea9f6: push ecx
0x5ea9f7: mov dword ptr [esp+28h],0Ch
0x5ea9ff: call 004DD270h
0x5eaa04: add esp,4
0x5eaa07: mov ecx,eax
0x5eaa09: call 004DC780h
0x5eaa0e: mov esi,[edi+0D0h]
0x5eaa14: test esi,esi
0x5eaa16: je short 005EAA1Dh
0x5eaa18: call 00401080h
0x5eaa1d: mov ecx,[edi+0D0h]
0x5eaa23: test ecx,ecx
0x5eaa25: je short 005EAA2Fh
0x5eaa27: mov eax,[ecx]
0x5eaa29: mov edx,[eax]
0x5eaa2b: push 1
0x5eaa2d: call edx
0x5eaa2f: mov byte ptr [esp+20h],0Bh
0x5eaa34: mov esi,[edi+0CCh]
0x5eaa3a: test esi,esi
0x5eaa3c: je short 005EAA68h
0x5eaa3e: lea eax,[esi+4]
0x5eaa41: or ecx,0FFFFFFFFh
0x5eaa44: lock xadd [eax],ecx
0x5eaa48: jne short 005EAA68h
0x5eaa4a: mov edx,[esi]
0x5eaa4c: mov eax,[edx+4]
0x5eaa4f: mov ecx,esi
0x5eaa51: call eax
0x5eaa53: lea ecx,[esi+8]
0x5eaa56: or edx,0FFFFFFFFh
0x5eaa59: lock xadd [ecx],edx
0x5eaa5d: jne short 005EAA68h
0x5eaa5f: mov eax,[esi]
0x5eaa61: mov edx,[eax+8]
0x5eaa64: mov ecx,esi
0x5eaa66: call edx
0x5eaa68: lea eax,[edi+0BCh]
0x5eaa6e: mov byte ptr [esp+20h],0Ah
0x5eaa73: call 005F00F0h
0x5eaa78: lea eax,[edi+0A8h]
0x5eaa7e: mov byte ptr [esp+20h],9
0x5eaa83: call 004664C0h
0x5eaa88: lea ecx,[edi+0A0h]
0x5eaa8e: mov byte ptr [esp+20h],8
0x5eaa93: call dword ptr ds:[77DF7Ch]
0x5eaa99: mov ecx,ebx
0x5eaa9b: mov byte ptr [esp+20h],7
0x5eaaa0: call 004DDE10h
0x5eaaa5: mov byte ptr [esp+20h],6
0x5eaaaa: mov esi,[edi+60h]
0x5eaaad: test esi,esi
0x5eaaaf: je short 005EAADBh
0x5eaab1: lea eax,[esi+4]
0x5eaab4: or ecx,0FFFFFFFFh
0x5eaab7: lock xadd [eax],ecx
0x5eaabb: jne short 005EAADBh
0x5eaabd: mov edx,[esi]
0x5eaabf: mov eax,[edx+4]
0x5eaac2: mov ecx,esi
0x5eaac4: call eax
0x5eaac6: lea ecx,[esi+8]
0x5eaac9: or edx,0FFFFFFFFh
0x5eaacc: lock xadd [ecx],edx
0x5eaad0: jne short 005EAADBh
0x5eaad2: mov eax,[esi]
0x5eaad4: mov edx,[eax+8]
0x5eaad7: mov ecx,esi
0x5eaad9: call edx
0x5eaadb: lea eax,[edi+50h]
0x5eaade: mov byte ptr [esp+20h],5
0x5eaae3: call 005EFD50h
0x5eaae8: lea ebx,[edi+40h]
0x5eaaeb: mov byte ptr [esp+20h],4
0x5eaaf0: call 00433080h
0x5eaaf5: mov byte ptr [esp+20h],3
0x5eaafa: mov eax,[edi+34h]
0x5eaafd: xor ebx,ebx
0x5eaaff: cmp eax,ebx
0x5eab01: je short 005EAB21h
0x5eab03: mov ecx,[esp+14h]
0x5eab07: mov ebx,[edi+38h]
0x5eab0a: push ecx
0x5eab0b: call 0044D400h
0x5eab10: mov eax,[edi+34h]
0x5eab13: add esp,4
0x5eab16: push eax
0x5eab17: call 006516BAh
0x5eab1c: add esp,4
0x5eab1f: xor ebx,ebx
0x5eab21: mov [edi+34h],ebx
0x5eab24: mov [edi+38h],ebx
0x5eab27: mov [edi+3Ch],ebx
0x5eab2a: mov byte ptr [esp+20h],2
0x5eab2f: mov esi,[edi+2Ch]
0x5eab32: cmp esi,ebx
0x5eab34: je short 005EAB60h
0x5eab36: lea edx,[esi+4]
0x5eab39: or eax,0FFFFFFFFh
0x5eab3c: lock xadd [edx],eax
0x5eab40: jne short 005EAB60h
0x5eab42: mov edx,[esi]
0x5eab44: mov eax,[edx+4]
0x5eab47: mov ecx,esi
0x5eab49: call eax
0x5eab4b: lea ecx,[esi+8]
0x5eab4e: or edx,0FFFFFFFFh
0x5eab51: lock xadd [ecx],edx
0x5eab55: jne short 005EAB60h
0x5eab57: mov eax,[esi]
0x5eab59: mov edx,[eax+8]
0x5eab5c: mov ecx,esi
0x5eab5e: call edx
0x5eab60: mov byte ptr [esp+20h],1
0x5eab65: mov esi,[edi+24h]
0x5eab68: cmp esi,ebx
0x5eab6a: je short 005EAB96h
0x5eab6c: lea eax,[esi+4]
0x5eab6f: or ecx,0FFFFFFFFh
0x5eab72: lock xadd [eax],ecx
0x5eab76: jne short 005EAB96h
0x5eab78: mov edx,[esi]
0x5eab7a: mov eax,[edx+4]
0x5eab7d: mov ecx,esi
0x5eab7f: call eax
0x5eab81: lea ecx,[esi+8]
0x5eab84: or edx,0FFFFFFFFh
0x5eab87: lock xadd [ecx],edx
0x5eab8b: jne short 005EAB96h
0x5eab8d: mov eax,[esi]
0x5eab8f: mov edx,[eax+8]
0x5eab92: mov ecx,esi
0x5eab94: call edx
0x5eab96: mov [esp+20h],bl
0x5eab9a: mov esi,[edi+1Ch]
0x5eab9d: cmp esi,ebx
0x5eab9f: je short 005EABCBh
0x5eaba1: lea eax,[esi+4]
0x5eaba4: or ecx,0FFFFFFFFh
0x5eaba7: lock xadd [eax],ecx
0x5eabab: jne short 005EABCBh
0x5eabad: mov edx,[esi]
0x5eabaf: mov eax,[edx+4]
0x5eabb2: mov ecx,esi
0x5eabb4: call eax
0x5eabb6: lea ecx,[esi+8]
0x5eabb9: or edx,0FFFFFFFFh
0x5eabbc: lock xadd [ecx],edx
0x5eabc0: jne short 005EABCBh
0x5eabc2: mov eax,[esi]
0x5eabc4: mov edx,[eax+8]
0x5eabc7: mov ecx,esi
0x5eabc9: call edx
0x5eabcb: mov dword ptr [esp+20h],0FFFFFFFFh
0x5eabd3: mov eax,[edi+0Ch]
0x5eabd6: cmp eax,ebx
0x5eabd8: je short 005EABF8h
0x5eabda: mov ecx,[esp+14h]
0x5eabde: mov ebx,[edi+10h]
0x5eabe1: push ecx
0x5eabe2: call 0044D400h
0x5eabe7: mov edx,[edi+0Ch]
0x5eabea: add esp,4
0x5eabed: push edx
0x5eabee: call 006516BAh
0x5eabf3: add esp,4
0x5eabf6: xor ebx,ebx
0x5eabf8: mov [edi+0Ch],ebx
0x5eabfb: mov [edi+10h],ebx
0x5eabfe: mov [edi+14h],ebx
0x5eac01: mov ecx,[esp+18h]
0x5eac05: mov fs:[0],ecx
0x5eac0c: pop ecx
0x5eac0d: pop edi
0x5eac0e: pop esi
0x5eac0f: pop ebx
0x5eac10: add esp,14h
0x5eac13: ret
````

`sub_5ea9c0` is called by sub_77b460. It delegates to sub_401080, sub_433080, sub_44d400 (10 callees).

### sub_5ef4e0 at 0x5ef4e0 (247 instructions)

````text
0x5ef4e0: push 0FFFFFFFFh
0x5ef4e2: push 7410D9h
0x5ef4e7: mov eax,fs:[0]
0x5ef4ed: push eax
0x5ef4ee: sub esp,44h
0x5ef4f1: push ebx
0x5ef4f2: push ebp
0x5ef4f3: push esi
0x5ef4f4: push edi
0x5ef4f5: mov eax,ds:[858220h]
0x5ef4fa: xor eax,esp
0x5ef4fc: push eax
0x5ef4fd: lea eax,[esp+58h]
0x5ef501: mov fs:[0],eax
0x5ef507: mov eax,[esp+74h]
0x5ef50b: cmp byte ptr [eax+39h],0
0x5ef50f: je short 005EF54Dh
0x5ef511: push 7C5AECh
0x5ef516: lea ecx,[esp+18h]
0x5ef51a: call dword ptr ds:[77CD7Ch]
0x5ef520: lea eax,[esp+14h]
0x5ef524: push eax
0x5ef525: lea ecx,[esp+34h]
0x5ef529: mov dword ptr [esp+64h],0
0x5ef531: call 00401230h
0x5ef536: push 80A4F8h
0x5ef53b: lea ecx,[esp+34h]
0x5ef53f: push ecx
0x5ef540: mov dword ptr [esp+38h],790F90h
0x5ef548: call 00652AC4h
0x5ef54d: lea esi,[esp+70h]
0x5ef551: mov ebp,eax
0x5ef553: call 00633EE0h
0x5ef558: mov eax,[ebp]
0x5ef55b: cmp byte ptr [eax+39h],0
0x5ef55f: je short 005EF566h
0x5ef561: mov edi,[ebp+8]
0x5ef564: jmp short 005EF57Eh
0x5ef566: mov edx,[ebp+8]
0x5ef569: cmp byte ptr [edx+39h],0
0x5ef56d: je short 005EF573h
0x5ef56f: mov edi,eax
0x5ef571: jmp short 005EF57Eh
0x5ef573: mov ecx,[esp+74h]
0x5ef577: cmp ecx,ebp
0x5ef579: mov edi,[ecx+8]
0x5ef57c: jne short 005EF5F2h
0x5ef57e: cmp byte ptr [edi+39h],0
0x5ef582: mov esi,[ebp+4]
0x5ef585: jne short 005EF58Ah
0x5ef587: mov [edi+4],esi
0x5ef58a: mov ecx,[esp+68h]
0x5ef58e: mov eax,[ecx+4]
0x5ef591: cmp [eax+4],ebp
0x5ef594: jne short 005EF59Bh
0x5ef596: mov [eax+4],edi
0x5ef599: jmp short 005EF5A6h
0x5ef59b: cmp [esi],ebp
0x5ef59d: jne short 005EF5A3h
0x5ef59f: mov [esi],edi
0x5ef5a1: jmp short 005EF5A6h
0x5ef5a3: mov [esi+8],edi
0x5ef5a6: mov edx,[ecx+4]
0x5ef5a9: cmp [edx],ebp
0x5ef5ab: jne short 005EF5CDh
0x5ef5ad: cmp byte ptr [edi+39h],0
0x5ef5b1: je short 005EF5B7h
0x5ef5b3: mov ecx,esi
0x5ef5b5: jmp short 005EF5CBh
0x5ef5b7: mov eax,[edi]
0x5ef5b9: cmp byte ptr [eax+39h],0
0x5ef5bd: mov ecx,edi
0x5ef5bf: jne short 005EF5CBh
0x5ef5c1: mov ecx,eax
0x5ef5c3: mov eax,[ecx]
0x5ef5c5: cmp byte ptr [eax+39h],0
0x5ef5c9: je short 005EF5C1h
0x5ef5cb: mov [edx],ecx
0x5ef5cd: mov eax,[esp+68h]
0x5ef5d1: mov ebx,[eax+4]
0x5ef5d4: cmp [ebx+8],ebp
0x5ef5d7: jne short 005EF64Eh
0x5ef5d9: cmp byte ptr [edi+39h],0
0x5ef5dd: je short 005EF5E6h
0x5ef5df: mov eax,esi
0x5ef5e1: mov [ebx+8],eax
0x5ef5e4: jmp short 005EF64Eh
0x5ef5e6: mov eax,edi
0x5ef5e8: call 00458540h
0x5ef5ed: mov [ebx+8],eax
0x5ef5f0: jmp short 005EF64Eh
0x5ef5f2: mov [eax+4],ecx
0x5ef5f5: mov edx,[ebp]
0x5ef5f8: mov [ecx],edx
0x5ef5fa: cmp ecx,[ebp+8]
0x5ef5fd: jne short 005EF603h
0x5ef5ff: mov esi,ecx
0x5ef601: jmp short 005EF61Dh
0x5ef603: cmp byte ptr [edi+39h],0
0x5ef607: mov esi,[ecx+4]
0x5ef60a: jne short 005EF60Fh
0x5ef60c: mov [edi+4],esi
0x5ef60f: mov [esi],edi
0x5ef611: mov eax,[ebp+8]
0x5ef614: mov [ecx+8],eax
0x5ef617: mov edx,[ebp+8]
0x5ef61a: mov [edx+4],ecx
0x5ef61d: mov eax,[esp+68h]
0x5ef621: mov eax,[eax+4]
0x5ef624: cmp [eax+4],ebp
0x5ef627: jne short 005EF62Eh
0x5ef629: mov [eax+4],ecx
0x5ef62c: jmp short 005EF63Ch
0x5ef62e: mov eax,[ebp+4]
0x5ef631: cmp [eax],ebp
0x5ef633: jne short 005EF639h
0x5ef635: mov [eax],ecx
0x5ef637: jmp short 005EF63Ch
0x5ef639: mov [eax+8],ecx
0x5ef63c: mov edx,[ebp+4]
0x5ef63f: mov [ecx+4],edx
0x5ef642: mov dl,[ebp+38h]
0x5ef645: mov al,[ecx+38h]
0x5ef648: mov [ecx+38h],dl
0x5ef64b: mov [ebp+38h],al
0x5ef64e: mov bl,1
0x5ef650: cmp [ebp+38h],bl
0x5ef653: jne near ptr 005EF77Ah
0x5ef659: mov eax,[esp+68h]
0x5ef65d: mov ecx,[eax+4]
0x5ef660: cmp edi,[ecx+4]
0x5ef663: je near ptr 005EF777h
0x5ef669: lea esp,[esp]
0x5ef670: cmp [edi+38h],bl
0x5ef673: jne near ptr 005EF777h
0x5ef679: mov ecx,[esi]
0x5ef67b: cmp edi,ecx
0x5ef67d: jne short 005EF6F5h
0x5ef67f: mov ecx,[esi+8]
0x5ef682: cmp byte ptr [ecx+38h],0
0x5ef686: jne short 005EF69Eh
0x5ef688: mov edx,[esp+68h]
0x5ef68c: mov [ecx+38h],bl
0x5ef68f: push edx
0x5ef690: mov ecx,esi
0x5ef692: mov byte ptr [esi+38h],0
0x5ef696: call 005F9650h
0x5ef69b: mov ecx,[esi+8]
0x5ef69e: cmp byte ptr [ecx+39h],0
0x5ef6a2: jne near ptr 005EF729h
0x5ef6a8: mov eax,[ecx]
0x5ef6aa: cmp [eax+38h],bl
0x5ef6ad: jne short 005EF6B7h
0x5ef6af: mov edx,[ecx+8]
0x5ef6b2: cmp [edx+38h],bl
0x5ef6b5: je short 005EF725h
0x5ef6b7: mov eax,[ecx+8]
0x5ef6ba: cmp [eax+38h],bl
0x5ef6bd: jne short 005EF6D5h
0x5ef6bf: mov edx,[ecx]
0x5ef6c1: mov eax,[esp+68h]
0x5ef6c5: mov [edx+38h],bl
0x5ef6c8: push eax
0x5ef6c9: mov byte ptr [ecx+38h],0
0x5ef6cd: call 004DD9C0h
0x5ef6d2: mov ecx,[esi+8]
0x5ef6d5: mov dl,[esi+38h]
0x5ef6d8: mov [ecx+38h],dl
0x5ef6db: mov [esi+38h],bl
0x5ef6de: mov eax,[ecx+8]
0x5ef6e1: mov ecx,[esp+68h]
0x5ef6e5: push ecx
0x5ef6e6: mov ecx,esi
0x5ef6e8: mov [eax+38h],bl
0x5ef6eb: call 005F9650h
0x5ef6f0: jmp near ptr 005EF777h
0x5ef6f5: cmp byte ptr [ecx+38h],0
0x5ef6f9: jne short 005EF710h
0x5ef6fb: mov eax,[esp+68h]
0x5ef6ff: mov [ecx+38h],bl
0x5ef702: push eax
0x5ef703: mov ecx,esi
0x5ef705: mov byte ptr [esi+38h],0
0x5ef709: call 004DD9C0h
0x5ef70e: mov ecx,[esi]
0x5ef710: cmp byte ptr [ecx+39h],0
0x5ef714: jne short 005EF729h
0x5ef716: mov edx,[ecx+8]
0x5ef719: cmp [edx+38h],bl
0x5ef71c: jne short 005EF740h
0x5ef71e: mov eax,[ecx]
0x5ef720: cmp [eax+38h],bl
0x5ef723: jne short 005EF740h
0x5ef725: mov byte ptr [ecx+38h],0
0x5ef729: mov ecx,[esp+68h]
0x5ef72d: mov edx,[ecx+4]
0x5ef730: mov edi,esi
0x5ef732: cmp edi,[edx+4]
0x5ef735: mov esi,[esi+4]
0x5ef738: jne near ptr 005EF670h
0x5ef73e: jmp short 005EF777h
0x5ef740: mov edx,[ecx]
0x5ef742: cmp [edx+38h],bl
0x5ef745: jne short 005EF75Dh
0x5ef747: mov eax,[ecx+8]
0x5ef74a: mov edx,[esp+68h]
0x5ef74e: mov [eax+38h],bl
0x5ef751: push edx
0x5ef752: mov byte ptr [ecx+38h],0
0x5ef756: call 005F9650h
0x5ef75b: mov ecx,[esi]
0x5ef75d: mov al,[esi+38h]
0x5ef760: mov edx,[esp+68h]
0x5ef764: mov [ecx+38h],al
0x5ef767: mov [esi+38h],bl
0x5ef76a: mov ecx,[ecx]
0x5ef76c: mov [ecx+38h],bl
0x5ef76f: push edx
0x5ef770: mov ecx,esi
0x5ef772: call 004DD9C0h
0x5ef777: mov [edi+38h],bl
0x5ef77a: lea eax,[ebp+0Ch]
0x5ef77d: push eax
0x5ef77e: call 005EFA60h
0x5ef783: push ebp
0x5ef784: call 006516BAh
0x5ef789: mov ecx,[esp+6Ch]
0x5ef78d: mov eax,[ecx+8]
0x5ef790: add esp,4
0x5ef793: test eax,eax
0x5ef795: jbe short 005EF79Dh
0x5ef797: add eax,0FFFFFFFFh
0x5ef79a: mov [ecx+8],eax
0x5ef79d: mov eax,[esp+6Ch]
0x5ef7a1: mov ecx,[esp+70h]
0x5ef7a5: mov edx,[esp+74h]
0x5ef7a9: mov [eax],ecx
0x5ef7ab: mov [eax+4],edx
0x5ef7ae: mov ecx,[esp+58h]
0x5ef7b2: mov fs:[0],ecx
0x5ef7b9: pop ecx
0x5ef7ba: pop edi
0x5ef7bb: pop esi
0x5ef7bc: pop ebp
0x5ef7bd: pop ebx
0x5ef7be: add esp,50h
0x5ef7c1: ret 10h
````

`sub_5ef4e0` is called by sub_5f0420. It delegates to sub_401230, sub_458540, sub_4dd9c0 (8 callees).

### ?get_mutable_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@SAAAVTAS_Alerter@@XZ at 0x5efa50 (4 instructions)

````text
0x5efa50: push ecx
0x5efa51: call 005F0130h
0x5efa56: pop ecx
0x5efa57: ret
````

`?get_mutable_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@SAAAVTAS_Alerter@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@CAAAVTAS_Alerter@@XZ (1 callees).

### sub_5efa60 at 0x5efa60 (40 instructions)

````text
0x5efa60: push 0FFFFFFFFh
0x5efa62: push 73BEE9h
0x5efa67: mov eax,fs:[0]
0x5efa6d: push eax
0x5efa6e: push ebx
0x5efa6f: push esi
0x5efa70: push edi
0x5efa71: mov eax,ds:[858220h]
0x5efa76: xor eax,esp
0x5efa78: push eax
0x5efa79: lea eax,[esp+10h]
0x5efa7d: mov fs:[0],eax
0x5efa83: mov esi,[esp+20h]
0x5efa87: xor edi,edi
0x5efa89: mov [esp+18h],edi
0x5efa8d: mov eax,[esi+20h]
0x5efa90: cmp eax,edi
0x5efa92: je short 005EFAADh
0x5efa94: mov ecx,[esp+20h]
0x5efa98: mov ebx,[esi+24h]
0x5efa9b: push ecx
0x5efa9c: call 0044D400h
0x5efaa1: mov eax,[esi+20h]
0x5efaa4: push eax
0x5efaa5: call 006516BAh
0x5efaaa: add esp,8
0x5efaad: mov ecx,esi
0x5efaaf: mov [esi+20h],edi
0x5efab2: mov [esi+24h],edi
0x5efab5: mov [esi+28h],edi
0x5efab8: mov dword ptr [esp+18h],0FFFFFFFFh
0x5efac0: call dword ptr ds:[77CD74h]
0x5efac6: mov ecx,[esp+10h]
0x5efaca: mov fs:[0],ecx
0x5efad1: pop ecx
0x5efad2: pop edi
0x5efad3: pop esi
0x5efad4: pop ebx
0x5efad5: add esp,0Ch
0x5efad8: ret 4
````

`sub_5efa60` is called by sub_5ef4e0, sub_5efd10. It delegates to sub_44d400, j_ORDINAL 764 (2 callees).

### sub_5efd10 at 0x5efd10 (26 instructions)

````text
0x5efd10: push ebx
0x5efd11: push esi
0x5efd12: push edi
0x5efd13: mov edi,[esp+10h]
0x5efd17: cmp byte ptr [edi+39h],0
0x5efd1b: mov ebx,ecx
0x5efd1d: mov esi,edi
0x5efd1f: jne short 005EFD48h
0x5efd21: mov eax,[esi+8]
0x5efd24: push eax
0x5efd25: mov ecx,ebx
0x5efd27: call 005EFD10h
0x5efd2c: mov esi,[esi]
0x5efd2e: lea ecx,[edi+0Ch]
0x5efd31: push ecx
0x5efd32: call 005EFA60h
0x5efd37: push edi
0x5efd38: call 006516BAh
0x5efd3d: add esp,4
0x5efd40: cmp byte ptr [esi+39h],0
0x5efd44: mov edi,esi
0x5efd46: je short 005EFD21h
0x5efd48: pop edi
0x5efd49: pop esi
0x5efd4a: pop ebx
0x5efd4b: ret 4
````

`sub_5efd10` is called by sub_5efd10, sub_5f0420. It delegates to sub_5efa60, sub_5efd10, j_ORDINAL 764 (3 callees).

### sub_5efd50 at 0x5efd50 (26 instructions)

````text
0x5efd50: push ebp
0x5efd51: mov ebp,esp
0x5efd53: and esp,0FFFFFFF8h
0x5efd56: sub esp,0Ch
0x5efd59: push edi
0x5efd5a: mov edi,eax
0x5efd5c: mov eax,[edi+4]
0x5efd5f: mov ecx,[eax]
0x5efd61: push eax
0x5efd62: push edi
0x5efd63: push ecx
0x5efd64: push edi
0x5efd65: lea eax,[esp+18h]
0x5efd69: push eax
0x5efd6a: call 005F0420h
0x5efd6f: mov ecx,[edi+4]
0x5efd72: push ecx
0x5efd73: call 006516BAh
0x5efd78: add esp,4
0x5efd7b: xor eax,eax
0x5efd7d: mov [edi+4],eax
0x5efd80: mov [edi+8],eax
0x5efd83: pop edi
0x5efd84: mov esp,ebp
0x5efd86: pop ebp
0x5efd87: ret
````

`sub_5efd50` is called by sub_5ea9c0. It delegates to sub_5f0420, j_ORDINAL 764 (2 callees).

### sub_5eff00 at 0x5eff00 (23 instructions)

````text
0x5eff00: push ebx
0x5eff01: push esi
0x5eff02: push edi
0x5eff03: mov edi,[esp+10h]
0x5eff07: cmp byte ptr [edi+19h],0
0x5eff0b: mov ebx,ecx
0x5eff0d: mov esi,edi
0x5eff0f: jne short 005EFF2Fh
0x5eff11: mov eax,[esi+8]
0x5eff14: push eax
0x5eff15: mov ecx,ebx
0x5eff17: call 005EFF00h
0x5eff1c: mov esi,[esi]
0x5eff1e: push edi
0x5eff1f: call 006516BAh
0x5eff24: add esp,4
0x5eff27: cmp byte ptr [esi+19h],0
0x5eff2b: mov edi,esi
0x5eff2d: je short 005EFF11h
0x5eff2f: pop edi
0x5eff30: pop esi
0x5eff31: pop ebx
0x5eff32: ret 4
````

`sub_5eff00` is called by sub_5eff00, sub_5f06a0. It delegates to sub_5eff00, j_ORDINAL 764 (2 callees).

### sub_5f00f0 at 0x5f00f0 (26 instructions)

````text
0x5f00f0: push ebp
0x5f00f1: mov ebp,esp
0x5f00f3: and esp,0FFFFFFF8h
0x5f00f6: sub esp,0Ch
0x5f00f9: push edi
0x5f00fa: mov edi,eax
0x5f00fc: mov eax,[edi+4]
0x5f00ff: mov ecx,[eax]
0x5f0101: push eax
0x5f0102: push edi
0x5f0103: push ecx
0x5f0104: push edi
0x5f0105: lea eax,[esp+18h]
0x5f0109: push eax
0x5f010a: call 005F06A0h
0x5f010f: mov ecx,[edi+4]
0x5f0112: push ecx
0x5f0113: call 006516BAh
0x5f0118: add esp,4
0x5f011b: xor eax,eax
0x5f011d: mov [edi+4],eax
0x5f0120: mov [edi+8],eax
0x5f0123: pop edi
0x5f0124: mov esp,ebp
0x5f0126: pop ebp
0x5f0127: ret
````

`sub_5f00f0` is called by sub_5ea9c0. It delegates to sub_5f06a0, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@CAAAVTAS_Alerter@@XZ at 0x5f0130 (26 instructions)

````text
0x5f0130: push 0FFFFFFFFh
0x5f0132: push 768AEEh
0x5f0137: mov eax,fs:[0]
0x5f013d: push eax
0x5f013e: mov eax,ds:[858220h]
0x5f0143: push ecx
0x5f0144: xor eax,esp
0x5f0146: push eax
0x5f0147: lea eax,[esp+8]
0x5f014b: mov fs:[0],eax
0x5f0151: mov eax,1
0x5f0156: test ds:[876420h],al
0x5f015c: jne short 005F0188h
0x5f015e: or ds:[876420h],eax
0x5f0164: mov dword ptr [esp+10h],0
0x5f016c: call 005EA5D0h
0x5f0171: push 77B460h
0x5f0176: mov dword ptr ds:[874D80h],7F4C60h
0x5f0180: call 006527EDh
0x5f0185: add esp,4
0x5f0188: mov eax,874D80h
0x5f018d: mov ecx,[esp+8]
0x5f0191: mov fs:[0],ecx
0x5f0198: pop ecx
0x5f0199: add esp,10h
0x5f019c: ret
````

`?get_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@CAAAVTAS_Alerter@@XZ` is called by ?get_mutable_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@SAAAVTAS_Alerter@@XZ. It delegates to sub_5ea5d0, sub_6527ed (2 callees).

### sub_5f0420 at 0x5f0420 (72 instructions)

````text
0x5f0420: mov eax,[edi+4]
0x5f0423: sub esp,0Ch
0x5f0426: push ebx
0x5f0427: mov ebx,[esp+18h]
0x5f042b: test ebx,ebx
0x5f042d: push ebp
0x5f042e: push esi
0x5f042f: mov esi,[eax]
0x5f0431: je short 005F0437h
0x5f0433: cmp ebx,edi
0x5f0435: je short 005F043Dh
0x5f0437: call dword ptr ds:[77D0E4h]
0x5f043d: mov ebp,[esp+24h]
0x5f0441: cmp ebp,esi
0x5f0443: jne short 005F04A0h
0x5f0445: mov eax,[esp+28h]
0x5f0449: test eax,eax
0x5f044b: mov esi,[edi+4]
0x5f044e: je short 005F0454h
0x5f0450: cmp eax,edi
0x5f0452: je short 005F045Ah
0x5f0454: call dword ptr ds:[77D0E4h]
0x5f045a: cmp [esp+2Ch],esi
0x5f045e: jne short 005F04A0h
0x5f0460: mov ecx,[edi+4]
0x5f0463: mov edx,[ecx+4]
0x5f0466: push edx
0x5f0467: mov ecx,edi
0x5f0469: call 005EFD10h
0x5f046e: mov eax,[edi+4]
0x5f0471: mov [eax+4],eax
0x5f0474: mov eax,[edi+4]
0x5f0477: mov dword ptr [edi+8],0
0x5f047e: mov [eax],eax
0x5f0480: mov eax,[edi+4]
0x5f0483: mov [eax+8],eax
0x5f0486: mov eax,[edi+4]
0x5f0489: mov ecx,[eax]
0x5f048b: mov eax,[esp+1Ch]
0x5f048f: mov [eax+4],ecx
0x5f0492: mov [eax],edi
0x5f0494: pop esi
0x5f0495: pop ebp
0x5f0496: pop ebx
0x5f0497: add esp,0Ch
0x5f049a: ret 14h
0x5f04a0: test ebx,ebx
0x5f04a2: je short 005F04AAh
0x5f04a4: cmp ebx,[esp+28h]
0x5f04a8: je short 005F04B0h
0x5f04aa: call dword ptr ds:[77D0E4h]
0x5f04b0: cmp ebp,[esp+2Ch]
0x5f04b4: je short 005F04D6h
0x5f04b6: lea esi,[esp+20h]
0x5f04ba: call 00633EE0h
0x5f04bf: push ebp
0x5f04c0: push ebx
0x5f04c1: lea edx,[esp+18h]
0x5f04c5: push edx
0x5f04c6: push edi
0x5f04c7: call 005EF4E0h
0x5f04cc: mov ebp,[esp+24h]
0x5f04d0: mov ebx,[esp+20h]
0x5f04d4: jmp short 005F04A0h
0x5f04d6: mov eax,[esp+1Ch]
0x5f04da: pop esi
0x5f04db: mov [eax+4],ebp
0x5f04de: pop ebp
0x5f04df: mov [eax],ebx
0x5f04e1: pop ebx
0x5f04e2: add esp,0Ch
0x5f04e5: ret 14h
````

`sub_5f0420` is called by sub_5efd50. It delegates to sub_5ef4e0, sub_5efd10, sub_633ee0 (3 callees).

### sub_5f06a0 at 0x5f06a0 (72 instructions)

````text
0x5f06a0: mov eax,[edi+4]
0x5f06a3: sub esp,0Ch
0x5f06a6: push ebx
0x5f06a7: mov ebx,[esp+18h]
0x5f06ab: test ebx,ebx
0x5f06ad: push ebp
0x5f06ae: push esi
0x5f06af: mov esi,[eax]
0x5f06b1: je short 005F06B7h
0x5f06b3: cmp ebx,edi
0x5f06b5: je short 005F06BDh
0x5f06b7: call dword ptr ds:[77D0E4h]
0x5f06bd: mov ebp,[esp+24h]
0x5f06c1: cmp ebp,esi
0x5f06c3: jne short 005F0720h
0x5f06c5: mov eax,[esp+28h]
0x5f06c9: test eax,eax
0x5f06cb: mov esi,[edi+4]
0x5f06ce: je short 005F06D4h
0x5f06d0: cmp eax,edi
0x5f06d2: je short 005F06DAh
0x5f06d4: call dword ptr ds:[77D0E4h]
0x5f06da: cmp [esp+2Ch],esi
0x5f06de: jne short 005F0720h
0x5f06e0: mov ecx,[edi+4]
0x5f06e3: mov edx,[ecx+4]
0x5f06e6: push edx
0x5f06e7: mov ecx,edi
0x5f06e9: call 005EFF00h
0x5f06ee: mov eax,[edi+4]
0x5f06f1: mov [eax+4],eax
0x5f06f4: mov eax,[edi+4]
0x5f06f7: mov dword ptr [edi+8],0
0x5f06fe: mov [eax],eax
0x5f0700: mov eax,[edi+4]
0x5f0703: mov [eax+8],eax
0x5f0706: mov eax,[edi+4]
0x5f0709: mov ecx,[eax]
0x5f070b: mov eax,[esp+1Ch]
0x5f070f: mov [eax+4],ecx
0x5f0712: mov [eax],edi
0x5f0714: pop esi
0x5f0715: pop ebp
0x5f0716: pop ebx
0x5f0717: add esp,0Ch
0x5f071a: ret 14h
0x5f0720: test ebx,ebx
0x5f0722: je short 005F072Ah
0x5f0724: cmp ebx,[esp+28h]
0x5f0728: je short 005F0730h
0x5f072a: call dword ptr ds:[77D0E4h]
0x5f0730: cmp ebp,[esp+2Ch]
0x5f0734: je short 005F0756h
0x5f0736: lea esi,[esp+20h]
0x5f073a: call 005853F0h
0x5f073f: push ebp
0x5f0740: push ebx
0x5f0741: lea edx,[esp+18h]
0x5f0745: push edx
0x5f0746: push edi
0x5f0747: call 005F08A0h
0x5f074c: mov ebp,[esp+24h]
0x5f0750: mov ebx,[esp+20h]
0x5f0754: jmp short 005F0720h
0x5f0756: mov eax,[esp+1Ch]
0x5f075a: pop esi
0x5f075b: mov [eax+4],ebp
0x5f075e: pop ebp
0x5f075f: mov [eax],ebx
0x5f0761: pop ebx
0x5f0762: add esp,0Ch
0x5f0765: ret 14h
````

`sub_5f06a0` is called by sub_5f00f0. It delegates to sub_5853f0, sub_5eff00, sub_5f08a0 (3 callees).

### sub_5f0770 at 0x5f0770 (28 instructions)

````text
0x5f0770: mov eax,[ecx]
0x5f0772: mov edx,[eax+8]
0x5f0775: mov [ecx],edx
0x5f0777: mov edx,[eax+8]
0x5f077a: cmp byte ptr [edx+19h],0
0x5f077e: jne short 005F0783h
0x5f0780: mov [edx+4],ecx
0x5f0783: mov edx,[ecx+4]
0x5f0786: mov [eax+4],edx
0x5f0789: mov edx,[esp+4]
0x5f078d: mov edx,[edx+4]
0x5f0790: cmp ecx,[edx+4]
0x5f0793: jne short 005F07A1h
0x5f0795: mov [edx+4],eax
0x5f0798: mov [eax+8],ecx
0x5f079b: mov [ecx+4],eax
0x5f079e: ret 4
0x5f07a1: mov edx,[ecx+4]
0x5f07a4: cmp ecx,[edx+8]
0x5f07a7: jne short 005F07B5h
0x5f07a9: mov [edx+8],eax
0x5f07ac: mov [eax+8],ecx
0x5f07af: mov [ecx+4],eax
0x5f07b2: ret 4
0x5f07b5: mov [edx],eax
0x5f07b7: mov [eax+8],ecx
0x5f07ba: mov [ecx+4],eax
0x5f07bd: ret 4
````

`sub_5f0770` is called by sub_5069d0, sub_584970, sub_5f08a0. It calls nothing else.

### sub_5f08a0 at 0x5f08a0 (236 instructions)

````text
0x5f08a0: push 0FFFFFFFFh
0x5f08a2: push 7410D9h
0x5f08a7: mov eax,fs:[0]
0x5f08ad: push eax
0x5f08ae: sub esp,44h
0x5f08b1: push ebx
0x5f08b2: push ebp
0x5f08b3: push esi
0x5f08b4: push edi
0x5f08b5: mov eax,ds:[858220h]
0x5f08ba: xor eax,esp
0x5f08bc: push eax
0x5f08bd: lea eax,[esp+58h]
0x5f08c1: mov fs:[0],eax
0x5f08c7: mov ebp,[esp+68h]
0x5f08cb: mov eax,[esp+74h]
0x5f08cf: cmp byte ptr [eax+19h],0
0x5f08d3: je short 005F0911h
0x5f08d5: push 7C5AECh
0x5f08da: lea ecx,[esp+18h]
0x5f08de: call dword ptr ds:[77CD7Ch]
0x5f08e4: lea eax,[esp+14h]
0x5f08e8: push eax
0x5f08e9: lea ecx,[esp+34h]
0x5f08ed: mov dword ptr [esp+64h],0
0x5f08f5: call 00401230h
0x5f08fa: push 80A4F8h
0x5f08ff: lea ecx,[esp+34h]
0x5f0903: push ecx
0x5f0904: mov dword ptr [esp+38h],790F90h
0x5f090c: call 00652AC4h
0x5f0911: mov ebx,eax
0x5f0913: lea esi,[esp+70h]
0x5f0917: mov [esp+68h],ebx
0x5f091b: call 005853F0h
0x5f0920: mov eax,[ebx]
0x5f0922: cmp byte ptr [eax+19h],0
0x5f0926: je short 005F092Dh
0x5f0928: mov edi,[ebx+8]
0x5f092b: jmp short 005F0945h
0x5f092d: mov edx,[ebx+8]
0x5f0930: cmp byte ptr [edx+19h],0
0x5f0934: je short 005F093Ah
0x5f0936: mov edi,eax
0x5f0938: jmp short 005F0945h
0x5f093a: mov ecx,[esp+74h]
0x5f093e: cmp ecx,ebx
0x5f0940: mov edi,[ecx+8]
0x5f0943: jne short 005F09B5h
0x5f0945: cmp byte ptr [edi+19h],0
0x5f0949: mov esi,[ebx+4]
0x5f094c: jne short 005F0951h
0x5f094e: mov [edi+4],esi
0x5f0951: mov eax,[ebp+4]
0x5f0954: cmp [eax+4],ebx
0x5f0957: jne short 005F095Eh
0x5f0959: mov [eax+4],edi
0x5f095c: jmp short 005F0969h
0x5f095e: cmp [esi],ebx
0x5f0960: jne short 005F0966h
0x5f0962: mov [esi],edi
0x5f0964: jmp short 005F0969h
0x5f0966: mov [esi+8],edi
0x5f0969: mov edx,[ebp+4]
0x5f096c: cmp [edx],ebx
0x5f096e: jne short 005F0990h
0x5f0970: cmp byte ptr [edi+19h],0
0x5f0974: je short 005F097Ah
0x5f0976: mov ecx,esi
0x5f0978: jmp short 005F098Eh
0x5f097a: mov eax,[edi]
0x5f097c: cmp byte ptr [eax+19h],0
0x5f0980: mov ecx,edi
0x5f0982: jne short 005F098Eh
0x5f0984: mov ecx,eax
0x5f0986: mov eax,[ecx]
0x5f0988: cmp byte ptr [eax+19h],0
0x5f098c: je short 005F0984h
0x5f098e: mov [edx],ecx
0x5f0990: mov ebx,[ebp+4]
0x5f0993: mov eax,[esp+68h]
0x5f0997: cmp [ebx+8],eax
0x5f099a: jne short 005F0A0Ch
0x5f099c: cmp byte ptr [edi+19h],0
0x5f09a0: je short 005F09A9h
0x5f09a2: mov eax,esi
0x5f09a4: mov [ebx+8],eax
0x5f09a7: jmp short 005F0A0Ch
0x5f09a9: mov eax,edi
0x5f09ab: call 00585460h
0x5f09b0: mov [ebx+8],eax
0x5f09b3: jmp short 005F0A0Ch
0x5f09b5: mov [eax+4],ecx
0x5f09b8: mov edx,[ebx]
0x5f09ba: mov [ecx],edx
0x5f09bc: cmp ecx,[ebx+8]
0x5f09bf: jne short 005F09C5h
0x5f09c1: mov esi,ecx
0x5f09c3: jmp short 005F09DFh
0x5f09c5: cmp byte ptr [edi+19h],0
0x5f09c9: mov esi,[ecx+4]
0x5f09cc: jne short 005F09D1h
0x5f09ce: mov [edi+4],esi
0x5f09d1: mov [esi],edi
0x5f09d3: mov eax,[ebx+8]
0x5f09d6: mov [ecx+8],eax
0x5f09d9: mov edx,[ebx+8]
0x5f09dc: mov [edx+4],ecx
0x5f09df: mov eax,[ebp+4]
0x5f09e2: cmp [eax+4],ebx
0x5f09e5: jne short 005F09ECh
0x5f09e7: mov [eax+4],ecx
0x5f09ea: jmp short 005F09FAh
0x5f09ec: mov eax,[ebx+4]
0x5f09ef: cmp [eax],ebx
0x5f09f1: jne short 005F09F7h
0x5f09f3: mov [eax],ecx
0x5f09f5: jmp short 005F09FAh
0x5f09f7: mov [eax+8],ecx
0x5f09fa: mov eax,[ebx+4]
0x5f09fd: mov [ecx+4],eax
0x5f0a00: mov dl,[ebx+18h]
0x5f0a03: mov al,[ecx+18h]
0x5f0a06: mov [ecx+18h],dl
0x5f0a09: mov [ebx+18h],al
0x5f0a0c: mov eax,[esp+68h]
0x5f0a10: mov bl,1
0x5f0a12: cmp [eax+18h],bl
0x5f0a15: jne near ptr 005F0B0Eh
0x5f0a1b: mov ecx,[ebp+4]
0x5f0a1e: cmp edi,[ecx+4]
0x5f0a21: je near ptr 005F0B0Bh
0x5f0a27: cmp [edi+18h],bl
0x5f0a2a: jne near ptr 005F0B0Bh
0x5f0a30: mov ecx,[esi]
0x5f0a32: cmp edi,ecx
0x5f0a34: jne short 005F0A99h
0x5f0a36: mov ecx,[esi+8]
0x5f0a39: cmp byte ptr [ecx+18h],0
0x5f0a3d: jne short 005F0A51h
0x5f0a3f: mov [ecx+18h],bl
0x5f0a42: push ebp
0x5f0a43: mov ecx,esi
0x5f0a45: mov byte ptr [esi+18h],0
0x5f0a49: call 005070E0h
0x5f0a4e: mov ecx,[esi+8]
0x5f0a51: cmp byte ptr [ecx+19h],0
0x5f0a55: jne short 005F0AC9h
0x5f0a57: mov edx,[ecx]
0x5f0a59: cmp [edx+18h],bl
0x5f0a5c: jne short 005F0A66h
0x5f0a5e: mov eax,[ecx+8]
0x5f0a61: cmp [eax+18h],bl
0x5f0a64: je short 005F0AC5h
0x5f0a66: mov edx,[ecx+8]
0x5f0a69: cmp [edx+18h],bl
0x5f0a6c: jne short 005F0A80h
0x5f0a6e: mov eax,[ecx]
0x5f0a70: mov [eax+18h],bl
0x5f0a73: push ebp
0x5f0a74: mov byte ptr [ecx+18h],0
0x5f0a78: call 005F0770h
0x5f0a7d: mov ecx,[esi+8]
0x5f0a80: mov dl,[esi+18h]
0x5f0a83: mov [ecx+18h],dl
0x5f0a86: mov [esi+18h],bl
0x5f0a89: mov eax,[ecx+8]
0x5f0a8c: push ebp
0x5f0a8d: mov ecx,esi
0x5f0a8f: mov [eax+18h],bl
0x5f0a92: call 005070E0h
0x5f0a97: jmp short 005F0B0Bh
0x5f0a99: cmp byte ptr [ecx+18h],0
0x5f0a9d: jne short 005F0AB0h
0x5f0a9f: mov [ecx+18h],bl
0x5f0aa2: push ebp
0x5f0aa3: mov ecx,esi
0x5f0aa5: mov byte ptr [esi+18h],0
0x5f0aa9: call 005F0770h
0x5f0aae: mov ecx,[esi]
0x5f0ab0: cmp byte ptr [ecx+19h],0
0x5f0ab4: jne short 005F0AC9h
0x5f0ab6: mov edx,[ecx+8]
0x5f0ab9: cmp [edx+18h],bl
0x5f0abc: jne short 005F0ADCh
0x5f0abe: mov eax,[ecx]
0x5f0ac0: cmp [eax+18h],bl
0x5f0ac3: jne short 005F0ADCh
0x5f0ac5: mov byte ptr [ecx+18h],0
0x5f0ac9: mov ecx,[ebp+4]
0x5f0acc: mov edi,esi
0x5f0ace: cmp edi,[ecx+4]
0x5f0ad1: mov esi,[esi+4]
0x5f0ad4: jne near ptr 005F0A27h
0x5f0ada: jmp short 005F0B0Bh
0x5f0adc: mov edx,[ecx]
0x5f0ade: cmp [edx+18h],bl
0x5f0ae1: jne short 005F0AF5h
0x5f0ae3: mov eax,[ecx+8]
0x5f0ae6: mov [eax+18h],bl
0x5f0ae9: push ebp
0x5f0aea: mov byte ptr [ecx+18h],0
0x5f0aee: call 005070E0h
0x5f0af3: mov ecx,[esi]
0x5f0af5: mov dl,[esi+18h]
0x5f0af8: mov [ecx+18h],dl
0x5f0afb: mov [esi+18h],bl
0x5f0afe: mov eax,[ecx]
0x5f0b00: push ebp
0x5f0b01: mov ecx,esi
0x5f0b03: mov [eax+18h],bl
0x5f0b06: call 005F0770h
0x5f0b0b: mov [edi+18h],bl
0x5f0b0e: mov ecx,[esp+68h]
0x5f0b12: push ecx
0x5f0b13: call 006516BAh
0x5f0b18: mov eax,[ebp+8]
0x5f0b1b: add esp,4
0x5f0b1e: test eax,eax
0x5f0b20: jbe short 005F0B28h
0x5f0b22: add eax,0FFFFFFFFh
0x5f0b25: mov [ebp+8],eax
0x5f0b28: mov eax,[esp+6Ch]
0x5f0b2c: mov edx,[esp+70h]
0x5f0b30: mov ecx,[esp+74h]
0x5f0b34: mov [eax],edx
0x5f0b36: mov [eax+4],ecx
0x5f0b39: mov ecx,[esp+58h]
0x5f0b3d: mov fs:[0],ecx
0x5f0b44: pop ecx
0x5f0b45: pop edi
0x5f0b46: pop esi
0x5f0b47: pop ebp
0x5f0b48: pop ebx
0x5f0b49: add esp,50h
0x5f0b4c: ret 10h
````

`sub_5f08a0` is called by sub_5f06a0. It delegates to sub_401230, sub_5070e0, sub_5853f0 (7 callees).

### sub_5f0bc0 at 0x5f0bc0 (16 instructions)

````text
0x5f0bc0: mov ecx,1
0x5f0bc5: call 0049A870h
0x5f0bca: test eax,eax
0x5f0bcc: je short 005F0BD4h
0x5f0bce: mov dword ptr [eax],0
0x5f0bd4: lea ecx,[eax+4]
0x5f0bd7: test ecx,ecx
0x5f0bd9: je short 005F0BE1h
0x5f0bdb: mov dword ptr [ecx],0
0x5f0be1: lea ecx,[eax+8]
0x5f0be4: test ecx,ecx
0x5f0be6: je short 005F0BEEh
0x5f0be8: mov dword ptr [ecx],0
0x5f0bee: mov byte ptr [eax+18h],1
0x5f0bf2: mov byte ptr [eax+19h],0
0x5f0bf6: ret
````

`sub_5f0bc0` is called by sub_5ea5d0. It delegates to sub_49a870 (1 callees).

### sub_5f0c60 at 0x5f0c60 (37 instructions)

````text
0x5f0c60: sub esp,10h
0x5f0c63: push esi
0x5f0c64: mov esi,eax
0x5f0c66: lea eax,[esp+8]
0x5f0c6a: push eax
0x5f0c6b: call 005F0D20h
0x5f0c70: mov ecx,[eax]
0x5f0c72: mov edx,[esi]
0x5f0c74: mov [eax],edx
0x5f0c76: mov [esi],ecx
0x5f0c78: mov edx,[eax+4]
0x5f0c7b: mov ecx,[esi+4]
0x5f0c7e: mov [esi+4],edx
0x5f0c81: mov [eax+4],ecx
0x5f0c84: mov eax,[esp+0Ch]
0x5f0c88: test eax,eax
0x5f0c8a: je short 005F0CB8h
0x5f0c8c: mov esi,eax
0x5f0c8e: add eax,4
0x5f0c91: or ecx,0FFFFFFFFh
0x5f0c94: lock xadd [eax],ecx
0x5f0c98: jne short 005F0CB8h
0x5f0c9a: mov edx,[esi]
0x5f0c9c: mov eax,[edx+4]
0x5f0c9f: mov ecx,esi
0x5f0ca1: call eax
0x5f0ca3: lea ecx,[esi+8]
0x5f0ca6: or edx,0FFFFFFFFh
0x5f0ca9: lock xadd [ecx],edx
0x5f0cad: jne short 005F0CB8h
0x5f0caf: mov eax,[esi]
0x5f0cb1: mov edx,[eax+8]
0x5f0cb4: mov ecx,esi
0x5f0cb6: call edx
0x5f0cb8: pop esi
0x5f0cb9: add esp,10h
0x5f0cbc: ret
````

`sub_5f0c60` is called by sub_5ea5d0. It delegates to sub_5f0d20 (1 callees).

### sub_5f0d20 at 0x5f0d20 (28 instructions)

````text
0x5f0d20: push 0FFFFFFFFh
0x5f0d22: push 73F2EBh
0x5f0d27: mov eax,fs:[0]
0x5f0d2d: push eax
0x5f0d2e: push esi
0x5f0d2f: push edi
0x5f0d30: mov eax,ds:[858220h]
0x5f0d35: xor eax,esp
0x5f0d37: push eax
0x5f0d38: lea eax,[esp+0Ch]
0x5f0d3c: mov fs:[0],eax
0x5f0d42: mov edi,ecx
0x5f0d44: mov esi,[esp+1Ch]
0x5f0d48: lea eax,[esi+4]
0x5f0d4b: mov [esi],edi
0x5f0d4d: mov dword ptr [eax],0
0x5f0d53: push esi
0x5f0d54: mov dword ptr [esp+18h],0
0x5f0d5c: call 005F0E20h
0x5f0d61: add esp,4
0x5f0d64: mov eax,esi
0x5f0d66: mov ecx,[esp+0Ch]
0x5f0d6a: mov fs:[0],ecx
0x5f0d71: pop ecx
0x5f0d72: pop edi
0x5f0d73: pop esi
0x5f0d74: add esp,0Ch
0x5f0d77: ret 4
````

`sub_5f0d20` is called by sub_5f0c60. It delegates to sub_5f0e20 (1 callees).

### sub_5f0e20 at 0x5f0e20 (39 instructions)

````text
0x5f0e20: push ecx
0x5f0e21: push esi
0x5f0e22: push edi
0x5f0e23: lea ecx,[esp+8]
0x5f0e27: mov esi,eax
0x5f0e29: call 005F0F40h
0x5f0e2e: mov edx,[eax]
0x5f0e30: mov ecx,[esi]
0x5f0e32: mov [esi],edx
0x5f0e34: mov [eax],ecx
0x5f0e36: mov eax,[esp+4]
0x5f0e3a: test eax,eax
0x5f0e3c: je short 005F0E6Ah
0x5f0e3e: mov esi,eax
0x5f0e40: add eax,4
0x5f0e43: or ecx,0FFFFFFFFh
0x5f0e46: lock xadd [eax],ecx
0x5f0e4a: jne short 005F0E6Ah
0x5f0e4c: mov edx,[esi]
0x5f0e4e: mov eax,[edx+4]
0x5f0e51: mov ecx,esi
0x5f0e53: call eax
0x5f0e55: lea ecx,[esi+8]
0x5f0e58: or edx,0FFFFFFFFh
0x5f0e5b: lock xadd [ecx],edx
0x5f0e5f: jne short 005F0E6Ah
0x5f0e61: mov eax,[esi]
0x5f0e63: mov edx,[eax+8]
0x5f0e66: mov ecx,esi
0x5f0e68: call edx
0x5f0e6a: mov eax,[esp+0Ch]
0x5f0e6e: push edi
0x5f0e6f: push edi
0x5f0e70: push eax
0x5f0e71: call 004A5750h
0x5f0e76: add esp,0Ch
0x5f0e79: pop esi
0x5f0e7a: pop ecx
0x5f0e7b: ret
````

`sub_5f0e20` is called by sub_5f0d20. It delegates to sub_4a5750, sub_5f0f40 (2 callees).

### sub_5f0f40 at 0x5f0f40 (43 instructions)

````text
0x5f0f40: push ebp
0x5f0f41: mov ebp,esp
0x5f0f43: push 0FFFFFFFFh
0x5f0f45: push 73B050h
0x5f0f4a: mov eax,fs:[0]
0x5f0f50: push eax
0x5f0f51: push ecx
0x5f0f52: push ebx
0x5f0f53: push esi
0x5f0f54: push edi
0x5f0f55: mov eax,ds:[858220h]
0x5f0f5a: xor eax,ebp
0x5f0f5c: push eax
0x5f0f5d: lea eax,[ebp-0Ch]
0x5f0f60: mov fs:[0],eax
0x5f0f66: mov [ebp-10h],esp
0x5f0f69: mov esi,ecx
0x5f0f6b: push 10h
0x5f0f6d: mov dword ptr [esi],0
0x5f0f73: mov dword ptr [ebp-4],0
0x5f0f7a: call 006516C0h
0x5f0f7f: add esp,4
0x5f0f82: test eax,eax
0x5f0f84: je short 005F0F9Fh
0x5f0f86: mov ecx,1
0x5f0f8b: mov [eax+4],ecx
0x5f0f8e: mov [eax+8],ecx
0x5f0f91: mov ecx,[ebp+8]
0x5f0f94: mov dword ptr [eax],7F4C2Ch
0x5f0f9a: mov [eax+0Ch],ecx
0x5f0f9d: jmp short 005F0FA1h
0x5f0f9f: xor eax,eax
0x5f0fa1: mov [esi],eax
0x5f0fa3: mov eax,esi
0x5f0fa5: mov ecx,[ebp-0Ch]
0x5f0fa8: mov fs:[0],ecx
0x5f0faf: pop ecx
0x5f0fb0: pop edi
0x5f0fb1: pop esi
0x5f0fb2: pop ebx
0x5f0fb3: mov esp,ebp
0x5f0fb5: pop ebp
0x5f0fb6: ret 4
````

`sub_5f0f40` is called by sub_5f0e20. It delegates to j_ORDINAL 762 (1 callees).

### sub_5f1870 at 0x5f1870 (23 instructions)

````text
0x5f1870: push 0FFFFFFFFh
0x5f1872: push 74F84Ch
0x5f1877: mov eax,fs:[0]
0x5f187d: push eax
0x5f187e: push ecx
0x5f187f: mov eax,ds:[858220h]
0x5f1884: xor eax,esp
0x5f1886: push eax
0x5f1887: lea eax,[esp+8]
0x5f188b: mov fs:[0],eax
0x5f1891: mov ecx,875D98h
0x5f1896: mov dword ptr ds:[875D94h],7F4DACh
0x5f18a0: call dword ptr ds:[77DF80h]
0x5f18a6: xor eax,eax
0x5f18a8: mov ds:[875DA4h],eax
0x5f18ad: mov ds:[875DA8h],eax
0x5f18b2: mov ds:[875DACh],eax
0x5f18b7: mov eax,875D94h
0x5f18bc: mov ecx,[esp+8]
0x5f18c0: mov fs:[0],ecx
0x5f18c7: pop ecx
0x5f18c8: add esp,10h
0x5f18cb: ret
````

`sub_5f1870` is called by ?get_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@CAAAVTAS_SelectorPlan@@XZ. It calls nothing else.

### ?get_mutable_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@SAAAVTAS_SelectorPlan@@XZ at 0x5f3800 (4 instructions)

````text
0x5f3800: push ecx
0x5f3801: call 005F3980h
0x5f3806: pop ecx
0x5f3807: ret
````

`?get_mutable_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@SAAAVTAS_SelectorPlan@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@CAAAVTAS_SelectorPlan@@XZ (1 callees).

### ?get_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@CAAAVTAS_SelectorPlan@@XZ at 0x5f3980 (26 instructions)

````text
0x5f3980: push 0FFFFFFFFh
0x5f3982: push 75478Eh
0x5f3987: mov eax,fs:[0]
0x5f398d: push eax
0x5f398e: mov eax,ds:[858220h]
0x5f3993: push ecx
0x5f3994: xor eax,esp
0x5f3996: push eax
0x5f3997: lea eax,[esp+8]
0x5f399b: mov fs:[0],eax
0x5f39a1: mov eax,1
0x5f39a6: test ds:[875EBCh],al
0x5f39ac: jne short 005F39D8h
0x5f39ae: or ds:[875EBCh],eax
0x5f39b4: mov dword ptr [esp+10h],0
0x5f39bc: call 005F1870h
0x5f39c1: push 77B480h
0x5f39c6: mov dword ptr ds:[875D94h],7F4DB4h
0x5f39d0: call 006527EDh
0x5f39d5: add esp,4
0x5f39d8: mov eax,875D94h
0x5f39dd: mov ecx,[esp+8]
0x5f39e1: mov fs:[0],ecx
0x5f39e8: pop ecx
0x5f39e9: add esp,10h
0x5f39ec: ret
````

`?get_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@CAAAVTAS_SelectorPlan@@XZ` is called by ?get_mutable_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@SAAAVTAS_SelectorPlan@@XZ. It delegates to sub_5f1870, sub_6527ed (2 callees).

### sub_5f5590 at 0x5f5590 (66 instructions)

````text
0x5f5590: push 0FFFFFFFFh
0x5f5592: push 760F7Eh
0x5f5597: mov eax,fs:[0]
0x5f559d: push eax
0x5f559e: push ecx
0x5f559f: push ebx
0x5f55a0: push esi
0x5f55a1: mov eax,ds:[858220h]
0x5f55a6: xor eax,esp
0x5f55a8: push eax
0x5f55a9: lea eax,[esp+10h]
0x5f55ad: mov fs:[0],eax
0x5f55b3: mov dword ptr [esp+0Ch],875F40h
0x5f55bb: call 00633900h
0x5f55c0: mov ds:[875F44h],eax
0x5f55c5: mov bl,1
0x5f55c7: mov [eax+39h],bl
0x5f55ca: mov eax,ds:[875F44h]
0x5f55cf: mov [eax+4],eax
0x5f55d2: mov eax,ds:[875F44h]
0x5f55d7: mov [eax],eax
0x5f55d9: mov eax,ds:[875F44h]
0x5f55de: xor esi,esi
0x5f55e0: mov [eax+8],eax
0x5f55e3: mov ds:[875F48h],esi
0x5f55e9: mov [esp+18h],esi
0x5f55ed: call 00633900h
0x5f55f2: mov ds:[875F50h],eax
0x5f55f7: mov [eax+39h],bl
0x5f55fa: mov eax,ds:[875F50h]
0x5f55ff: mov [eax+4],eax
0x5f5602: mov eax,ds:[875F50h]
0x5f5607: mov [eax],eax
0x5f5609: mov eax,ds:[875F50h]
0x5f560e: mov [eax+8],eax
0x5f5611: mov ds:[875F54h],esi
0x5f5617: mov [esp+18h],bl
0x5f561b: call 00633900h
0x5f5620: mov ds:[875F5Ch],eax
0x5f5625: mov [eax+39h],bl
0x5f5628: mov eax,ds:[875F5Ch]
0x5f562d: mov [eax+4],eax
0x5f5630: mov eax,ds:[875F5Ch]
0x5f5635: mov [eax],eax
0x5f5637: mov eax,ds:[875F5Ch]
0x5f563c: mov [eax+8],eax
0x5f563f: mov ds:[875F60h],esi
0x5f5645: mov byte ptr [esp+18h],2
0x5f564a: call 00633900h
0x5f564f: mov ds:[875F68h],eax
0x5f5654: mov [eax+39h],bl
0x5f5657: mov eax,ds:[875F68h]
0x5f565c: mov [eax+4],eax
0x5f565f: mov eax,ds:[875F68h]
0x5f5664: mov [eax],eax
0x5f5666: mov eax,ds:[875F68h]
0x5f566b: mov [eax+8],eax
0x5f566e: mov ds:[875F6Ch],esi
0x5f5674: mov eax,875F40h
0x5f5679: mov ecx,[esp+10h]
0x5f567d: mov fs:[0],ecx
0x5f5684: pop ecx
0x5f5685: pop esi
0x5f5686: pop ebx
0x5f5687: add esp,10h
0x5f568a: ret
````

`sub_5f5590` is called by ?get_mutable_instance@?$singleton@VCHotKey@@@serialization@boost@@SAAAVCHotKey@@XZ, ?get_instance@?$singleton@VCHotKey@@@serialization@boost@@CAAAVCHotKey@@XZ. It delegates to sub_633900 (1 callees).

### ?get_mutable_instance@?$singleton@VCHotKey@@@serialization@boost@@SAAAVCHotKey@@XZ at 0x5f83a0 (25 instructions)

````text
0x5f83a0: jmp near ptr 005F8970h
0x5f8970: push 0FFFFFFFFh
0x5f8972: push 76D64Eh
0x5f8977: mov eax,fs:[0]
0x5f897d: push eax
0x5f897e: mov eax,ds:[858220h]
0x5f8983: xor eax,esp
0x5f8985: push eax
0x5f8986: lea eax,[esp+4]
0x5f898a: mov fs:[0],eax
0x5f8990: mov eax,1
0x5f8995: test ds:[876548h],al
0x5f899b: jne short 005F89BDh
0x5f899d: or ds:[876548h],eax
0x5f89a3: mov dword ptr [esp+0Ch],0
0x5f89ab: call 005F5590h
0x5f89b0: push 77B4A0h
0x5f89b5: call 006527EDh
0x5f89ba: add esp,4
0x5f89bd: mov eax,875F40h
0x5f89c2: mov ecx,[esp+4]
0x5f89c6: mov fs:[0],ecx
0x5f89cd: pop ecx
0x5f89ce: add esp,0Ch
0x5f89d1: ret
````

`?get_mutable_instance@?$singleton@VCHotKey@@@serialization@boost@@SAAAVCHotKey@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5f5590, sub_6527ed (2 callees).

### sub_5f8640 at 0x5f8640 (40 instructions)

````text
0x5f8640: push 0FFFFFFFFh
0x5f8642: push 73BEE9h
0x5f8647: mov eax,fs:[0]
0x5f864d: push eax
0x5f864e: push ebx
0x5f864f: push esi
0x5f8650: push edi
0x5f8651: mov eax,ds:[858220h]
0x5f8656: xor eax,esp
0x5f8658: push eax
0x5f8659: lea eax,[esp+10h]
0x5f865d: mov fs:[0],eax
0x5f8663: mov esi,[esp+20h]
0x5f8667: xor edi,edi
0x5f8669: mov [esp+18h],edi
0x5f866d: mov eax,[esi+20h]
0x5f8670: cmp eax,edi
0x5f8672: je short 005F868Dh
0x5f8674: mov ecx,[esp+20h]
0x5f8678: mov ebx,[esi+24h]
0x5f867b: push ecx
0x5f867c: call 005F9E20h
0x5f8681: mov eax,[esi+20h]
0x5f8684: push eax
0x5f8685: call 006516BAh
0x5f868a: add esp,8
0x5f868d: mov ecx,esi
0x5f868f: mov [esi+20h],edi
0x5f8692: mov [esi+24h],edi
0x5f8695: mov [esi+28h],edi
0x5f8698: mov dword ptr [esp+18h],0FFFFFFFFh
0x5f86a0: call dword ptr ds:[77CD74h]
0x5f86a6: mov ecx,[esp+10h]
0x5f86aa: mov fs:[0],ecx
0x5f86b1: pop ecx
0x5f86b2: pop edi
0x5f86b3: pop esi
0x5f86b4: pop ebx
0x5f86b5: add esp,0Ch
0x5f86b8: ret 4
````

`sub_5f8640` is called by sub_5f88f0, sub_5f9360. It delegates to sub_5f9e20, j_ORDINAL 764 (2 callees).

### sub_5f88f0 at 0x5f88f0 (26 instructions)

````text
0x5f88f0: push ebx
0x5f88f1: push esi
0x5f88f2: push edi
0x5f88f3: mov edi,[esp+10h]
0x5f88f7: cmp byte ptr [edi+39h],0
0x5f88fb: mov ebx,ecx
0x5f88fd: mov esi,edi
0x5f88ff: jne short 005F8928h
0x5f8901: mov eax,[esi+8]
0x5f8904: push eax
0x5f8905: mov ecx,ebx
0x5f8907: call 005F88F0h
0x5f890c: mov esi,[esi]
0x5f890e: lea ecx,[edi+0Ch]
0x5f8911: push ecx
0x5f8912: call 005F8640h
0x5f8917: push edi
0x5f8918: call 006516BAh
0x5f891d: add esp,4
0x5f8920: cmp byte ptr [esi+39h],0
0x5f8924: mov edi,esi
0x5f8926: je short 005F8901h
0x5f8928: pop edi
0x5f8929: pop esi
0x5f892a: pop ebx
0x5f892b: ret 4
````

`sub_5f88f0` is called by sub_5f88f0, sub_5f8c50. It delegates to sub_5f8640, sub_5f88f0, j_ORDINAL 764 (3 callees).

### sub_5f8930 at 0x5f8930 (26 instructions)

````text
0x5f8930: push ebp
0x5f8931: mov ebp,esp
0x5f8933: and esp,0FFFFFFF8h
0x5f8936: sub esp,0Ch
0x5f8939: push edi
0x5f893a: mov edi,eax
0x5f893c: mov eax,[edi+4]
0x5f893f: mov ecx,[eax]
0x5f8941: push eax
0x5f8942: push edi
0x5f8943: push ecx
0x5f8944: push edi
0x5f8945: lea eax,[esp+18h]
0x5f8949: push eax
0x5f894a: call 005F8C50h
0x5f894f: mov ecx,[edi+4]
0x5f8952: push ecx
0x5f8953: call 006516BAh
0x5f8958: add esp,4
0x5f895b: xor eax,eax
0x5f895d: mov [edi+4],eax
0x5f8960: mov [edi+8],eax
0x5f8963: pop edi
0x5f8964: mov esp,ebp
0x5f8966: pop ebp
0x5f8967: ret
````

`sub_5f8930` is called by sub_77b4a0. It delegates to sub_5f8c50, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@VCHotKey@@@serialization@boost@@CAAAVCHotKey@@XZ at 0x5f8970 (24 instructions)

````text
0x5f8970: push 0FFFFFFFFh
0x5f8972: push 76D64Eh
0x5f8977: mov eax,fs:[0]
0x5f897d: push eax
0x5f897e: mov eax,ds:[858220h]
0x5f8983: xor eax,esp
0x5f8985: push eax
0x5f8986: lea eax,[esp+4]
0x5f898a: mov fs:[0],eax
0x5f8990: mov eax,1
0x5f8995: test ds:[876548h],al
0x5f899b: jne short 005F89BDh
0x5f899d: or ds:[876548h],eax
0x5f89a3: mov dword ptr [esp+0Ch],0
0x5f89ab: call 005F5590h
0x5f89b0: push 77B4A0h
0x5f89b5: call 006527EDh
0x5f89ba: add esp,4
0x5f89bd: mov eax,875F40h
0x5f89c2: mov ecx,[esp+4]
0x5f89c6: mov fs:[0],ecx
0x5f89cd: pop ecx
0x5f89ce: add esp,0Ch
0x5f89d1: ret
````

`?get_instance@?$singleton@VCHotKey@@@serialization@boost@@CAAAVCHotKey@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5f5590, sub_6527ed (2 callees).

### sub_5f8c50 at 0x5f8c50 (72 instructions)

````text
0x5f8c50: mov eax,[edi+4]
0x5f8c53: sub esp,0Ch
0x5f8c56: push ebx
0x5f8c57: mov ebx,[esp+18h]
0x5f8c5b: test ebx,ebx
0x5f8c5d: push ebp
0x5f8c5e: push esi
0x5f8c5f: mov esi,[eax]
0x5f8c61: je short 005F8C67h
0x5f8c63: cmp ebx,edi
0x5f8c65: je short 005F8C6Dh
0x5f8c67: call dword ptr ds:[77D0E4h]
0x5f8c6d: mov ebp,[esp+24h]
0x5f8c71: cmp ebp,esi
0x5f8c73: jne short 005F8CD0h
0x5f8c75: mov eax,[esp+28h]
0x5f8c79: test eax,eax
0x5f8c7b: mov esi,[edi+4]
0x5f8c7e: je short 005F8C84h
0x5f8c80: cmp eax,edi
0x5f8c82: je short 005F8C8Ah
0x5f8c84: call dword ptr ds:[77D0E4h]
0x5f8c8a: cmp [esp+2Ch],esi
0x5f8c8e: jne short 005F8CD0h
0x5f8c90: mov ecx,[edi+4]
0x5f8c93: mov edx,[ecx+4]
0x5f8c96: push edx
0x5f8c97: mov ecx,edi
0x5f8c99: call 005F88F0h
0x5f8c9e: mov eax,[edi+4]
0x5f8ca1: mov [eax+4],eax
0x5f8ca4: mov eax,[edi+4]
0x5f8ca7: mov dword ptr [edi+8],0
0x5f8cae: mov [eax],eax
0x5f8cb0: mov eax,[edi+4]
0x5f8cb3: mov [eax+8],eax
0x5f8cb6: mov eax,[edi+4]
0x5f8cb9: mov ecx,[eax]
0x5f8cbb: mov eax,[esp+1Ch]
0x5f8cbf: mov [eax+4],ecx
0x5f8cc2: mov [eax],edi
0x5f8cc4: pop esi
0x5f8cc5: pop ebp
0x5f8cc6: pop ebx
0x5f8cc7: add esp,0Ch
0x5f8cca: ret 14h
0x5f8cd0: test ebx,ebx
0x5f8cd2: je short 005F8CDAh
0x5f8cd4: cmp ebx,[esp+28h]
0x5f8cd8: je short 005F8CE0h
0x5f8cda: call dword ptr ds:[77D0E4h]
0x5f8ce0: cmp ebp,[esp+2Ch]
0x5f8ce4: je short 005F8D06h
0x5f8ce6: lea esi,[esp+20h]
0x5f8cea: call 00633EE0h
0x5f8cef: push ebp
0x5f8cf0: push ebx
0x5f8cf1: lea edx,[esp+18h]
0x5f8cf5: push edx
0x5f8cf6: push edi
0x5f8cf7: call 005F9360h
0x5f8cfc: mov ebp,[esp+24h]
0x5f8d00: mov ebx,[esp+20h]
0x5f8d04: jmp short 005F8CD0h
0x5f8d06: mov eax,[esp+1Ch]
0x5f8d0a: pop esi
0x5f8d0b: mov [eax+4],ebp
0x5f8d0e: pop ebp
0x5f8d0f: mov [eax],ebx
0x5f8d11: pop ebx
0x5f8d12: add esp,0Ch
0x5f8d15: ret 14h
````

`sub_5f8c50` is called by sub_5f8930. It delegates to sub_5f88f0, sub_5f9360, sub_633ee0 (3 callees).

### sub_5f9360 at 0x5f9360 (247 instructions)

````text
0x5f9360: push 0FFFFFFFFh
0x5f9362: push 7410D9h
0x5f9367: mov eax,fs:[0]
0x5f936d: push eax
0x5f936e: sub esp,44h
0x5f9371: push ebx
0x5f9372: push ebp
0x5f9373: push esi
0x5f9374: push edi
0x5f9375: mov eax,ds:[858220h]
0x5f937a: xor eax,esp
0x5f937c: push eax
0x5f937d: lea eax,[esp+58h]
0x5f9381: mov fs:[0],eax
0x5f9387: mov eax,[esp+74h]
0x5f938b: cmp byte ptr [eax+39h],0
0x5f938f: je short 005F93CDh
0x5f9391: push 7C5AECh
0x5f9396: lea ecx,[esp+18h]
0x5f939a: call dword ptr ds:[77CD7Ch]
0x5f93a0: lea eax,[esp+14h]
0x5f93a4: push eax
0x5f93a5: lea ecx,[esp+34h]
0x5f93a9: mov dword ptr [esp+64h],0
0x5f93b1: call 00401230h
0x5f93b6: push 80A4F8h
0x5f93bb: lea ecx,[esp+34h]
0x5f93bf: push ecx
0x5f93c0: mov dword ptr [esp+38h],790F90h
0x5f93c8: call 00652AC4h
0x5f93cd: lea esi,[esp+70h]
0x5f93d1: mov ebp,eax
0x5f93d3: call 00633EE0h
0x5f93d8: mov eax,[ebp]
0x5f93db: cmp byte ptr [eax+39h],0
0x5f93df: je short 005F93E6h
0x5f93e1: mov edi,[ebp+8]
0x5f93e4: jmp short 005F93FEh
0x5f93e6: mov edx,[ebp+8]
0x5f93e9: cmp byte ptr [edx+39h],0
0x5f93ed: je short 005F93F3h
0x5f93ef: mov edi,eax
0x5f93f1: jmp short 005F93FEh
0x5f93f3: mov ecx,[esp+74h]
0x5f93f7: cmp ecx,ebp
0x5f93f9: mov edi,[ecx+8]
0x5f93fc: jne short 005F9472h
0x5f93fe: cmp byte ptr [edi+39h],0
0x5f9402: mov esi,[ebp+4]
0x5f9405: jne short 005F940Ah
0x5f9407: mov [edi+4],esi
0x5f940a: mov ecx,[esp+68h]
0x5f940e: mov eax,[ecx+4]
0x5f9411: cmp [eax+4],ebp
0x5f9414: jne short 005F941Bh
0x5f9416: mov [eax+4],edi
0x5f9419: jmp short 005F9426h
0x5f941b: cmp [esi],ebp
0x5f941d: jne short 005F9423h
0x5f941f: mov [esi],edi
0x5f9421: jmp short 005F9426h
0x5f9423: mov [esi+8],edi
0x5f9426: mov edx,[ecx+4]
0x5f9429: cmp [edx],ebp
0x5f942b: jne short 005F944Dh
0x5f942d: cmp byte ptr [edi+39h],0
0x5f9431: je short 005F9437h
0x5f9433: mov ecx,esi
0x5f9435: jmp short 005F944Bh
0x5f9437: mov eax,[edi]
0x5f9439: cmp byte ptr [eax+39h],0
0x5f943d: mov ecx,edi
0x5f943f: jne short 005F944Bh
0x5f9441: mov ecx,eax
0x5f9443: mov eax,[ecx]
0x5f9445: cmp byte ptr [eax+39h],0
0x5f9449: je short 005F9441h
0x5f944b: mov [edx],ecx
0x5f944d: mov eax,[esp+68h]
0x5f9451: mov ebx,[eax+4]
0x5f9454: cmp [ebx+8],ebp
0x5f9457: jne short 005F94CEh
0x5f9459: cmp byte ptr [edi+39h],0
0x5f945d: je short 005F9466h
0x5f945f: mov eax,esi
0x5f9461: mov [ebx+8],eax
0x5f9464: jmp short 005F94CEh
0x5f9466: mov eax,edi
0x5f9468: call 00458540h
0x5f946d: mov [ebx+8],eax
0x5f9470: jmp short 005F94CEh
0x5f9472: mov [eax+4],ecx
0x5f9475: mov edx,[ebp]
0x5f9478: mov [ecx],edx
0x5f947a: cmp ecx,[ebp+8]
0x5f947d: jne short 005F9483h
0x5f947f: mov esi,ecx
0x5f9481: jmp short 005F949Dh
0x5f9483: cmp byte ptr [edi+39h],0
0x5f9487: mov esi,[ecx+4]
0x5f948a: jne short 005F948Fh
0x5f948c: mov [edi+4],esi
0x5f948f: mov [esi],edi
0x5f9491: mov eax,[ebp+8]
0x5f9494: mov [ecx+8],eax
0x5f9497: mov edx,[ebp+8]
0x5f949a: mov [edx+4],ecx
0x5f949d: mov eax,[esp+68h]
0x5f94a1: mov eax,[eax+4]
0x5f94a4: cmp [eax+4],ebp
0x5f94a7: jne short 005F94AEh
0x5f94a9: mov [eax+4],ecx
0x5f94ac: jmp short 005F94BCh
0x5f94ae: mov eax,[ebp+4]
0x5f94b1: cmp [eax],ebp
0x5f94b3: jne short 005F94B9h
0x5f94b5: mov [eax],ecx
0x5f94b7: jmp short 005F94BCh
0x5f94b9: mov [eax+8],ecx
0x5f94bc: mov edx,[ebp+4]
0x5f94bf: mov [ecx+4],edx
0x5f94c2: mov dl,[ebp+38h]
0x5f94c5: mov al,[ecx+38h]
0x5f94c8: mov [ecx+38h],dl
0x5f94cb: mov [ebp+38h],al
0x5f94ce: mov bl,1
0x5f94d0: cmp [ebp+38h],bl
0x5f94d3: jne near ptr 005F95FAh
0x5f94d9: mov eax,[esp+68h]
0x5f94dd: mov ecx,[eax+4]
0x5f94e0: cmp edi,[ecx+4]
0x5f94e3: je near ptr 005F95F7h
0x5f94e9: lea esp,[esp]
0x5f94f0: cmp [edi+38h],bl
0x5f94f3: jne near ptr 005F95F7h
0x5f94f9: mov ecx,[esi]
0x5f94fb: cmp edi,ecx
0x5f94fd: jne short 005F9575h
0x5f94ff: mov ecx,[esi+8]
0x5f9502: cmp byte ptr [ecx+38h],0
0x5f9506: jne short 005F951Eh
0x5f9508: mov edx,[esp+68h]
0x5f950c: mov [ecx+38h],bl
0x5f950f: push edx
0x5f9510: mov ecx,esi
0x5f9512: mov byte ptr [esi+38h],0
0x5f9516: call 005F9650h
0x5f951b: mov ecx,[esi+8]
0x5f951e: cmp byte ptr [ecx+39h],0
0x5f9522: jne near ptr 005F95A9h
0x5f9528: mov eax,[ecx]
0x5f952a: cmp [eax+38h],bl
0x5f952d: jne short 005F9537h
0x5f952f: mov edx,[ecx+8]
0x5f9532: cmp [edx+38h],bl
0x5f9535: je short 005F95A5h
0x5f9537: mov eax,[ecx+8]
0x5f953a: cmp [eax+38h],bl
0x5f953d: jne short 005F9555h
0x5f953f: mov edx,[ecx]
0x5f9541: mov eax,[esp+68h]
0x5f9545: mov [edx+38h],bl
0x5f9548: push eax
0x5f9549: mov byte ptr [ecx+38h],0
0x5f954d: call 004DD9C0h
0x5f9552: mov ecx,[esi+8]
0x5f9555: mov dl,[esi+38h]
0x5f9558: mov [ecx+38h],dl
0x5f955b: mov [esi+38h],bl
0x5f955e: mov eax,[ecx+8]
0x5f9561: mov ecx,[esp+68h]
0x5f9565: push ecx
0x5f9566: mov ecx,esi
0x5f9568: mov [eax+38h],bl
0x5f956b: call 005F9650h
0x5f9570: jmp near ptr 005F95F7h
0x5f9575: cmp byte ptr [ecx+38h],0
0x5f9579: jne short 005F9590h
0x5f957b: mov eax,[esp+68h]
0x5f957f: mov [ecx+38h],bl
0x5f9582: push eax
0x5f9583: mov ecx,esi
0x5f9585: mov byte ptr [esi+38h],0
0x5f9589: call 004DD9C0h
0x5f958e: mov ecx,[esi]
0x5f9590: cmp byte ptr [ecx+39h],0
0x5f9594: jne short 005F95A9h
0x5f9596: mov edx,[ecx+8]
0x5f9599: cmp [edx+38h],bl
0x5f959c: jne short 005F95C0h
0x5f959e: mov eax,[ecx]
0x5f95a0: cmp [eax+38h],bl
0x5f95a3: jne short 005F95C0h
0x5f95a5: mov byte ptr [ecx+38h],0
0x5f95a9: mov ecx,[esp+68h]
0x5f95ad: mov edx,[ecx+4]
0x5f95b0: mov edi,esi
0x5f95b2: cmp edi,[edx+4]
0x5f95b5: mov esi,[esi+4]
0x5f95b8: jne near ptr 005F94F0h
0x5f95be: jmp short 005F95F7h
0x5f95c0: mov edx,[ecx]
0x5f95c2: cmp [edx+38h],bl
0x5f95c5: jne short 005F95DDh
0x5f95c7: mov eax,[ecx+8]
0x5f95ca: mov edx,[esp+68h]
0x5f95ce: mov [eax+38h],bl
0x5f95d1: push edx
0x5f95d2: mov byte ptr [ecx+38h],0
0x5f95d6: call 005F9650h
0x5f95db: mov ecx,[esi]
0x5f95dd: mov al,[esi+38h]
0x5f95e0: mov edx,[esp+68h]
0x5f95e4: mov [ecx+38h],al
0x5f95e7: mov [esi+38h],bl
0x5f95ea: mov ecx,[ecx]
0x5f95ec: mov [ecx+38h],bl
0x5f95ef: push edx
0x5f95f0: mov ecx,esi
0x5f95f2: call 004DD9C0h
0x5f95f7: mov [edi+38h],bl
0x5f95fa: lea eax,[ebp+0Ch]
0x5f95fd: push eax
0x5f95fe: call 005F8640h
0x5f9603: push ebp
0x5f9604: call 006516BAh
0x5f9609: mov ecx,[esp+6Ch]
0x5f960d: mov eax,[ecx+8]
0x5f9610: add esp,4
0x5f9613: test eax,eax
0x5f9615: jbe short 005F961Dh
0x5f9617: add eax,0FFFFFFFFh
0x5f961a: mov [ecx+8],eax
0x5f961d: mov eax,[esp+6Ch]
0x5f9621: mov ecx,[esp+70h]
0x5f9625: mov edx,[esp+74h]
0x5f9629: mov [eax],ecx
0x5f962b: mov [eax+4],edx
0x5f962e: mov ecx,[esp+58h]
0x5f9632: mov fs:[0],ecx
0x5f9639: pop ecx
0x5f963a: pop edi
0x5f963b: pop esi
0x5f963c: pop ebp
0x5f963d: pop ebx
0x5f963e: add esp,50h
0x5f9641: ret 10h
````

`sub_5f9360` is called by sub_5f8c50. It delegates to sub_401230, sub_458540, sub_4dd9c0 (8 callees).

### sub_5f9650 at 0x5f9650 (28 instructions)

````text
0x5f9650: mov eax,[ecx+8]
0x5f9653: mov edx,[eax]
0x5f9655: mov [ecx+8],edx
0x5f9658: mov edx,[eax]
0x5f965a: cmp byte ptr [edx+39h],0
0x5f965e: jne short 005F9663h
0x5f9660: mov [edx+4],ecx
0x5f9663: mov edx,[ecx+4]
0x5f9666: mov [eax+4],edx
0x5f9669: mov edx,[esp+4]
0x5f966d: mov edx,[edx+4]
0x5f9670: cmp ecx,[edx+4]
0x5f9673: jne short 005F9680h
0x5f9675: mov [edx+4],eax
0x5f9678: mov [eax],ecx
0x5f967a: mov [ecx+4],eax
0x5f967d: ret 4
0x5f9680: mov edx,[ecx+4]
0x5f9683: cmp ecx,[edx]
0x5f9685: jne short 005F9691h
0x5f9687: mov [edx],eax
0x5f9689: mov [eax],ecx
0x5f968b: mov [ecx+4],eax
0x5f968e: ret 4
0x5f9691: mov [edx+8],eax
0x5f9694: mov [eax],ecx
0x5f9696: mov [ecx+4],eax
0x5f9699: ret 4
````

`sub_5f9650` is called by sub_4dd6d0, sub_506d20, sub_5e3ee0, sub_5e42e0, sub_5e6990, sub_5ef4e0, sub_5f9360, sub_6229f0, sub_633610. It calls nothing else.

### sub_5f9e20 at 0x5f9e20 (30 instructions)

````text
0x5f9e20: push edi
0x5f9e21: mov edi,eax
0x5f9e23: cmp edi,ebx
0x5f9e25: je short 005F9E61h
0x5f9e27: push esi
0x5f9e28: mov esi,[edi+8]
0x5f9e2b: test esi,esi
0x5f9e2d: je short 005F9E59h
0x5f9e2f: lea eax,[esi+4]
0x5f9e32: or ecx,0FFFFFFFFh
0x5f9e35: lock xadd [eax],ecx
0x5f9e39: jne short 005F9E59h
0x5f9e3b: mov edx,[esi]
0x5f9e3d: mov eax,[edx+4]
0x5f9e40: mov ecx,esi
0x5f9e42: call eax
0x5f9e44: lea ecx,[esi+8]
0x5f9e47: or edx,0FFFFFFFFh
0x5f9e4a: lock xadd [ecx],edx
0x5f9e4e: jne short 005F9E59h
0x5f9e50: mov eax,[esi]
0x5f9e52: mov edx,[eax+8]
0x5f9e55: mov ecx,esi
0x5f9e57: call edx
0x5f9e59: add edi,0Ch
0x5f9e5c: cmp edi,ebx
0x5f9e5e: jne short 005F9E28h
0x5f9e60: pop esi
0x5f9e61: pop edi
0x5f9e62: ret
````

`sub_5f9e20` is called by sub_5f8640. It calls nothing else.

### sub_602810 at 0x602810 (26 instructions)

````text
0x602810: or eax,0FFFFFFFFh
0x602813: xor edx,edx
0x602815: div ecx
0x602817: sub esp,10h
0x60281a: cmp eax,3Ch
0x60281d: jae short 0060284Ch
0x60281f: lea eax,[esp]
0x602822: push eax
0x602823: lea ecx,[esp+8]
0x602827: mov dword ptr [esp+4],0
0x60282f: call dword ptr ds:[77D0DCh]
0x602835: push 80A2ACh
0x60283a: lea ecx,[esp+8]
0x60283e: push ecx
0x60283f: mov dword ptr [esp+0Ch],78FFD4h
0x602847: call 00652AC4h
0x60284c: mov edx,ecx
0x60284e: shl edx,4
0x602851: sub edx,ecx
0x602853: add edx,edx
0x602855: add edx,edx
0x602857: push edx
0x602858: call 006516C0h
0x60285d: add esp,4
0x602860: add esp,10h
0x602863: ret
````

`sub_602810` is called by sub_633900. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_607960 at 0x607960 (47 instructions)

````text
0x607960: push 0FFFFFFFFh
0x607962: push 73EE74h
0x607967: mov eax,fs:[0]
0x60796d: push eax
0x60796e: sub esp,8
0x607971: push esi
0x607972: mov eax,ds:[858220h]
0x607977: xor eax,esp
0x607979: push eax
0x60797a: lea eax,[esp+10h]
0x60797e: mov fs:[0],eax
0x607984: mov ecx,874934h
0x607989: mov dword ptr [esp+0Ch],874934h
0x607991: call dword ptr ds:[77DF80h]
0x607997: xor esi,esi
0x607999: mov [esp+18h],esi
0x60799d: push 14h
0x60799f: mov ds:[87493Ch],esi
0x6079a5: mov ds:[874940h],esi
0x6079ab: call 006516C0h
0x6079b0: add esp,4
0x6079b3: cmp eax,esi
0x6079b5: je short 006079C8h
0x6079b7: mov dword ptr [eax],7F5520h
0x6079bd: mov [eax+8],esi
0x6079c0: mov [eax+0Ch],esi
0x6079c3: mov [eax+10h],esi
0x6079c6: jmp short 006079CAh
0x6079c8: xor eax,eax
0x6079ca: mov ds:[87493Ch],eax
0x6079cf: xor eax,eax
0x6079d1: mov ds:[874944h],eax
0x6079d6: mov ds:[874948h],eax
0x6079db: mov ds:[87494Ch],eax
0x6079e0: mov ds:[874950h],eax
0x6079e5: mov ds:[874954h],eax
0x6079ea: mov ds:[874958h],eax
0x6079ef: mov ds:[87495Ch],eax
0x6079f4: mov ds:[874960h],eax
0x6079f9: mov dword ptr ds:[874964h],8
0x607a03: mov eax,874934h
0x607a08: mov ecx,[esp+10h]
0x607a0c: mov fs:[0],ecx
0x607a13: pop ecx
0x607a14: pop esi
0x607a15: add esp,14h
0x607a18: ret
````

`sub_607960` is called by ?get_instance@?$singleton@VCFrameManager@@@serialization@boost@@CAAAVCFrameManager@@XZ. It delegates to j_ORDINAL 762 (1 callees).

### ?get_mutable_instance@?$singleton@VCFrameManager@@@serialization@boost@@SAAAVCFrameManager@@XZ at 0x608320 (4 instructions)

````text
0x608320: push ecx
0x608321: call 00608330h
0x608326: pop ecx
0x608327: ret
````

`?get_mutable_instance@?$singleton@VCFrameManager@@@serialization@boost@@SAAAVCFrameManager@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VCFrameManager@@@serialization@boost@@CAAAVCFrameManager@@XZ (1 callees).

### ?get_instance@?$singleton@VCFrameManager@@@serialization@boost@@CAAAVCFrameManager@@XZ at 0x608330 (25 instructions)

````text
0x608330: push 0FFFFFFFFh
0x608332: push 7438CEh
0x608337: mov eax,fs:[0]
0x60833d: push eax
0x60833e: mov eax,ds:[858220h]
0x608343: push ecx
0x608344: xor eax,esp
0x608346: push eax
0x608347: lea eax,[esp+8]
0x60834b: mov fs:[0],eax
0x608351: mov eax,1
0x608356: test ds:[875A48h],al
0x60835c: jne short 0060837Eh
0x60835e: or ds:[875A48h],eax
0x608364: mov dword ptr [esp+10h],0
0x60836c: call 00607960h
0x608371: push 77B4B0h
0x608376: call 006527EDh
0x60837b: add esp,4
0x60837e: mov eax,874934h
0x608383: mov ecx,[esp+8]
0x608387: mov fs:[0],ecx
0x60838e: pop ecx
0x60838f: add esp,10h
0x608392: ret
````

`?get_instance@?$singleton@VCFrameManager@@@serialization@boost@@CAAAVCFrameManager@@XZ` is called by ?get_mutable_instance@?$singleton@VCFrameManager@@@serialization@boost@@SAAAVCFrameManager@@XZ. It delegates to sub_607960, sub_6527ed (2 callees).

### sub_609e80 at 0x609e80 (39 instructions)

````text
0x609e80: push 0FFFFFFFFh
0x609e82: push 743818h
0x609e87: mov eax,fs:[0]
0x609e8d: push eax
0x609e8e: push esi
0x609e8f: mov eax,ds:[858220h]
0x609e94: xor eax,esp
0x609e96: push eax
0x609e97: lea eax,[esp+8]
0x609e9b: mov fs:[0],eax
0x609ea1: mov esi,[esp+18h]
0x609ea5: call 0050FCB0h
0x609eaa: mov [esi+4],eax
0x609ead: mov byte ptr [eax+21h],1
0x609eb1: mov eax,[esi+4]
0x609eb4: mov [eax+4],eax
0x609eb7: mov eax,[esi+4]
0x609eba: mov [eax],eax
0x609ebc: mov eax,[esi+4]
0x609ebf: mov [eax+8],eax
0x609ec2: mov dword ptr [esi+8],0
0x609ec9: mov dword ptr [esp+10h],0
0x609ed1: call 004B53B0h
0x609ed6: mov [esi+10h],eax
0x609ed9: mov byte ptr [eax+11h],1
0x609edd: mov eax,[esi+10h]
0x609ee0: mov [eax+4],eax
0x609ee3: mov eax,[esi+10h]
0x609ee6: mov [eax],eax
0x609ee8: mov eax,[esi+10h]
0x609eeb: mov [eax+8],eax
0x609eee: mov dword ptr [esi+14h],0
0x609ef5: mov eax,esi
0x609ef7: mov ecx,[esp+8]
0x609efb: mov fs:[0],ecx
0x609f02: pop ecx
0x609f03: pop esi
0x609f04: add esp,0Ch
0x609f07: ret 4
````

`sub_609e80` is called by sub_610980. It delegates to sub_4b53b0, sub_50fcb0 (2 callees).

### sub_609f20 at 0x609f20 (24 instructions)

````text
0x609f20: push 0FFFFFFFFh
0x609f22: push 74A798h
0x609f27: mov eax,fs:[0]
0x609f2d: push eax
0x609f2e: push ecx
0x609f2f: push esi
0x609f30: mov eax,ds:[858220h]
0x609f35: xor eax,esp
0x609f37: push eax
0x609f38: lea eax,[esp+0Ch]
0x609f3c: mov fs:[0],eax
0x609f42: mov esi,[esp+1Ch]
0x609f46: lea eax,[esi+0Ch]
0x609f49: mov dword ptr [esp+14h],0
0x609f51: call 0060AC80h
0x609f56: mov eax,esi
0x609f58: mov dword ptr [esp+14h],0FFFFFFFFh
0x609f60: call 005AFA10h
0x609f65: mov ecx,[esp+0Ch]
0x609f69: mov fs:[0],ecx
0x609f70: pop ecx
0x609f71: pop esi
0x609f72: add esp,10h
0x609f75: ret 4
````

`sub_609f20` is called by sub_610c30. It delegates to sub_5afa10, sub_60ac80 (2 callees).

### sub_60ac40 at 0x60ac40 (23 instructions)

````text
0x60ac40: push ebx
0x60ac41: push esi
0x60ac42: push edi
0x60ac43: mov edi,[esp+10h]
0x60ac47: cmp byte ptr [edi+11h],0
0x60ac4b: mov ebx,ecx
0x60ac4d: mov esi,edi
0x60ac4f: jne short 0060AC6Fh
0x60ac51: mov eax,[esi+8]
0x60ac54: push eax
0x60ac55: mov ecx,ebx
0x60ac57: call 0060AC40h
0x60ac5c: mov esi,[esi]
0x60ac5e: push edi
0x60ac5f: call 006516BAh
0x60ac64: add esp,4
0x60ac67: cmp byte ptr [esi+11h],0
0x60ac6b: mov edi,esi
0x60ac6d: je short 0060AC51h
0x60ac6f: pop edi
0x60ac70: pop esi
0x60ac71: pop ebx
0x60ac72: ret 4
````

`sub_60ac40` is called by sub_4b4030, sub_60ac40, sub_60b040. It delegates to sub_60ac40, j_ORDINAL 764 (2 callees).

### sub_60ac80 at 0x60ac80 (26 instructions)

````text
0x60ac80: push ebp
0x60ac81: mov ebp,esp
0x60ac83: and esp,0FFFFFFF8h
0x60ac86: sub esp,0Ch
0x60ac89: push edi
0x60ac8a: mov edi,eax
0x60ac8c: mov eax,[edi+4]
0x60ac8f: mov ecx,[eax]
0x60ac91: push eax
0x60ac92: push edi
0x60ac93: push ecx
0x60ac94: push edi
0x60ac95: lea eax,[esp+18h]
0x60ac99: push eax
0x60ac9a: call 0060B040h
0x60ac9f: mov ecx,[edi+4]
0x60aca2: push ecx
0x60aca3: call 006516BAh
0x60aca8: add esp,4
0x60acab: xor eax,eax
0x60acad: mov [edi+4],eax
0x60acb0: mov [edi+8],eax
0x60acb3: pop edi
0x60acb4: mov esp,ebp
0x60acb6: pop ebp
0x60acb7: ret
````

`sub_60ac80` is called by sub_4dde10, sub_609f20. It delegates to sub_60b040, j_ORDINAL 764 (2 callees).

### sub_60b040 at 0x60b040 (72 instructions)

````text
0x60b040: mov eax,[edi+4]
0x60b043: sub esp,0Ch
0x60b046: push ebx
0x60b047: mov ebx,[esp+18h]
0x60b04b: test ebx,ebx
0x60b04d: push ebp
0x60b04e: push esi
0x60b04f: mov esi,[eax]
0x60b051: je short 0060B057h
0x60b053: cmp ebx,edi
0x60b055: je short 0060B05Dh
0x60b057: call dword ptr ds:[77D0E4h]
0x60b05d: mov ebp,[esp+24h]
0x60b061: cmp ebp,esi
0x60b063: jne short 0060B0C0h
0x60b065: mov eax,[esp+28h]
0x60b069: test eax,eax
0x60b06b: mov esi,[edi+4]
0x60b06e: je short 0060B074h
0x60b070: cmp eax,edi
0x60b072: je short 0060B07Ah
0x60b074: call dword ptr ds:[77D0E4h]
0x60b07a: cmp [esp+2Ch],esi
0x60b07e: jne short 0060B0C0h
0x60b080: mov ecx,[edi+4]
0x60b083: mov edx,[ecx+4]
0x60b086: push edx
0x60b087: mov ecx,edi
0x60b089: call 0060AC40h
0x60b08e: mov eax,[edi+4]
0x60b091: mov [eax+4],eax
0x60b094: mov eax,[edi+4]
0x60b097: mov dword ptr [edi+8],0
0x60b09e: mov [eax],eax
0x60b0a0: mov eax,[edi+4]
0x60b0a3: mov [eax+8],eax
0x60b0a6: mov eax,[edi+4]
0x60b0a9: mov ecx,[eax]
0x60b0ab: mov eax,[esp+1Ch]
0x60b0af: mov [eax+4],ecx
0x60b0b2: mov [eax],edi
0x60b0b4: pop esi
0x60b0b5: pop ebp
0x60b0b6: pop ebx
0x60b0b7: add esp,0Ch
0x60b0ba: ret 14h
0x60b0c0: test ebx,ebx
0x60b0c2: je short 0060B0CAh
0x60b0c4: cmp ebx,[esp+28h]
0x60b0c8: je short 0060B0D0h
0x60b0ca: call dword ptr ds:[77D0E4h]
0x60b0d0: cmp ebp,[esp+2Ch]
0x60b0d4: je short 0060B0F6h
0x60b0d6: lea esi,[esp+20h]
0x60b0da: call 004B6490h
0x60b0df: push ebp
0x60b0e0: push ebx
0x60b0e1: lea edx,[esp+18h]
0x60b0e5: push edx
0x60b0e6: push edi
0x60b0e7: call 0060B1C0h
0x60b0ec: mov ebp,[esp+24h]
0x60b0f0: mov ebx,[esp+20h]
0x60b0f4: jmp short 0060B0C0h
0x60b0f6: mov eax,[esp+1Ch]
0x60b0fa: pop esi
0x60b0fb: mov [eax+4],ebp
0x60b0fe: pop ebp
0x60b0ff: mov [eax],ebx
0x60b101: pop ebx
0x60b102: add esp,0Ch
0x60b105: ret 14h
````

`sub_60b040` is called by sub_60ac80. It delegates to sub_4b6490, sub_60ac40, sub_60b1c0 (3 callees).

### sub_60b1c0 at 0x60b1c0 (236 instructions)

````text
0x60b1c0: push 0FFFFFFFFh
0x60b1c2: push 7410D9h
0x60b1c7: mov eax,fs:[0]
0x60b1cd: push eax
0x60b1ce: sub esp,44h
0x60b1d1: push ebx
0x60b1d2: push ebp
0x60b1d3: push esi
0x60b1d4: push edi
0x60b1d5: mov eax,ds:[858220h]
0x60b1da: xor eax,esp
0x60b1dc: push eax
0x60b1dd: lea eax,[esp+58h]
0x60b1e1: mov fs:[0],eax
0x60b1e7: mov ebp,[esp+68h]
0x60b1eb: mov eax,[esp+74h]
0x60b1ef: cmp byte ptr [eax+11h],0
0x60b1f3: je short 0060B231h
0x60b1f5: push 7C5AECh
0x60b1fa: lea ecx,[esp+18h]
0x60b1fe: call dword ptr ds:[77CD7Ch]
0x60b204: lea eax,[esp+14h]
0x60b208: push eax
0x60b209: lea ecx,[esp+34h]
0x60b20d: mov dword ptr [esp+64h],0
0x60b215: call 00401230h
0x60b21a: push 80A4F8h
0x60b21f: lea ecx,[esp+34h]
0x60b223: push ecx
0x60b224: mov dword ptr [esp+38h],790F90h
0x60b22c: call 00652AC4h
0x60b231: mov ebx,eax
0x60b233: lea esi,[esp+70h]
0x60b237: mov [esp+68h],ebx
0x60b23b: call 004B6490h
0x60b240: mov eax,[ebx]
0x60b242: cmp byte ptr [eax+11h],0
0x60b246: je short 0060B24Dh
0x60b248: mov edi,[ebx+8]
0x60b24b: jmp short 0060B265h
0x60b24d: mov edx,[ebx+8]
0x60b250: cmp byte ptr [edx+11h],0
0x60b254: je short 0060B25Ah
0x60b256: mov edi,eax
0x60b258: jmp short 0060B265h
0x60b25a: mov ecx,[esp+74h]
0x60b25e: cmp ecx,ebx
0x60b260: mov edi,[ecx+8]
0x60b263: jne short 0060B2D5h
0x60b265: cmp byte ptr [edi+11h],0
0x60b269: mov esi,[ebx+4]
0x60b26c: jne short 0060B271h
0x60b26e: mov [edi+4],esi
0x60b271: mov eax,[ebp+4]
0x60b274: cmp [eax+4],ebx
0x60b277: jne short 0060B27Eh
0x60b279: mov [eax+4],edi
0x60b27c: jmp short 0060B289h
0x60b27e: cmp [esi],ebx
0x60b280: jne short 0060B286h
0x60b282: mov [esi],edi
0x60b284: jmp short 0060B289h
0x60b286: mov [esi+8],edi
0x60b289: mov edx,[ebp+4]
0x60b28c: cmp [edx],ebx
0x60b28e: jne short 0060B2B0h
0x60b290: cmp byte ptr [edi+11h],0
0x60b294: je short 0060B29Ah
0x60b296: mov ecx,esi
0x60b298: jmp short 0060B2AEh
0x60b29a: mov eax,[edi]
0x60b29c: cmp byte ptr [eax+11h],0
0x60b2a0: mov ecx,edi
0x60b2a2: jne short 0060B2AEh
0x60b2a4: mov ecx,eax
0x60b2a6: mov eax,[ecx]
0x60b2a8: cmp byte ptr [eax+11h],0
0x60b2ac: je short 0060B2A4h
0x60b2ae: mov [edx],ecx
0x60b2b0: mov ebx,[ebp+4]
0x60b2b3: mov eax,[esp+68h]
0x60b2b7: cmp [ebx+8],eax
0x60b2ba: jne short 0060B32Ch
0x60b2bc: cmp byte ptr [edi+11h],0
0x60b2c0: je short 0060B2C9h
0x60b2c2: mov eax,esi
0x60b2c4: mov [ebx+8],eax
0x60b2c7: jmp short 0060B32Ch
0x60b2c9: mov eax,edi
0x60b2cb: call 004DE470h
0x60b2d0: mov [ebx+8],eax
0x60b2d3: jmp short 0060B32Ch
0x60b2d5: mov [eax+4],ecx
0x60b2d8: mov edx,[ebx]
0x60b2da: mov [ecx],edx
0x60b2dc: cmp ecx,[ebx+8]
0x60b2df: jne short 0060B2E5h
0x60b2e1: mov esi,ecx
0x60b2e3: jmp short 0060B2FFh
0x60b2e5: cmp byte ptr [edi+11h],0
0x60b2e9: mov esi,[ecx+4]
0x60b2ec: jne short 0060B2F1h
0x60b2ee: mov [edi+4],esi
0x60b2f1: mov [esi],edi
0x60b2f3: mov eax,[ebx+8]
0x60b2f6: mov [ecx+8],eax
0x60b2f9: mov edx,[ebx+8]
0x60b2fc: mov [edx+4],ecx
0x60b2ff: mov eax,[ebp+4]
0x60b302: cmp [eax+4],ebx
0x60b305: jne short 0060B30Ch
0x60b307: mov [eax+4],ecx
0x60b30a: jmp short 0060B31Ah
0x60b30c: mov eax,[ebx+4]
0x60b30f: cmp [eax],ebx
0x60b311: jne short 0060B317h
0x60b313: mov [eax],ecx
0x60b315: jmp short 0060B31Ah
0x60b317: mov [eax+8],ecx
0x60b31a: mov eax,[ebx+4]
0x60b31d: mov [ecx+4],eax
0x60b320: mov dl,[ebx+10h]
0x60b323: mov al,[ecx+10h]
0x60b326: mov [ecx+10h],dl
0x60b329: mov [ebx+10h],al
0x60b32c: mov eax,[esp+68h]
0x60b330: mov bl,1
0x60b332: cmp [eax+10h],bl
0x60b335: jne near ptr 0060B42Eh
0x60b33b: mov ecx,[ebp+4]
0x60b33e: cmp edi,[ecx+4]
0x60b341: je near ptr 0060B42Bh
0x60b347: cmp [edi+10h],bl
0x60b34a: jne near ptr 0060B42Bh
0x60b350: mov ecx,[esi]
0x60b352: cmp edi,ecx
0x60b354: jne short 0060B3B9h
0x60b356: mov ecx,[esi+8]
0x60b359: cmp byte ptr [ecx+10h],0
0x60b35d: jne short 0060B371h
0x60b35f: mov [ecx+10h],bl
0x60b362: push ebp
0x60b363: mov ecx,esi
0x60b365: mov byte ptr [esi+10h],0
0x60b369: call 0060B470h
0x60b36e: mov ecx,[esi+8]
0x60b371: cmp byte ptr [ecx+11h],0
0x60b375: jne short 0060B3E9h
0x60b377: mov edx,[ecx]
0x60b379: cmp [edx+10h],bl
0x60b37c: jne short 0060B386h
0x60b37e: mov eax,[ecx+8]
0x60b381: cmp [eax+10h],bl
0x60b384: je short 0060B3E5h
0x60b386: mov edx,[ecx+8]
0x60b389: cmp [edx+10h],bl
0x60b38c: jne short 0060B3A0h
0x60b38e: mov eax,[ecx]
0x60b390: mov [eax+10h],bl
0x60b393: push ebp
0x60b394: mov byte ptr [ecx+10h],0
0x60b398: call 004DE490h
0x60b39d: mov ecx,[esi+8]
0x60b3a0: mov dl,[esi+10h]
0x60b3a3: mov [ecx+10h],dl
0x60b3a6: mov [esi+10h],bl
0x60b3a9: mov eax,[ecx+8]
0x60b3ac: push ebp
0x60b3ad: mov ecx,esi
0x60b3af: mov [eax+10h],bl
0x60b3b2: call 0060B470h
0x60b3b7: jmp short 0060B42Bh
0x60b3b9: cmp byte ptr [ecx+10h],0
0x60b3bd: jne short 0060B3D0h
0x60b3bf: mov [ecx+10h],bl
0x60b3c2: push ebp
0x60b3c3: mov ecx,esi
0x60b3c5: mov byte ptr [esi+10h],0
0x60b3c9: call 004DE490h
0x60b3ce: mov ecx,[esi]
0x60b3d0: cmp byte ptr [ecx+11h],0
0x60b3d4: jne short 0060B3E9h
0x60b3d6: mov edx,[ecx+8]
0x60b3d9: cmp [edx+10h],bl
0x60b3dc: jne short 0060B3FCh
0x60b3de: mov eax,[ecx]
0x60b3e0: cmp [eax+10h],bl
0x60b3e3: jne short 0060B3FCh
0x60b3e5: mov byte ptr [ecx+10h],0
0x60b3e9: mov ecx,[ebp+4]
0x60b3ec: mov edi,esi
0x60b3ee: cmp edi,[ecx+4]
0x60b3f1: mov esi,[esi+4]
0x60b3f4: jne near ptr 0060B347h
0x60b3fa: jmp short 0060B42Bh
0x60b3fc: mov edx,[ecx]
0x60b3fe: cmp [edx+10h],bl
0x60b401: jne short 0060B415h
0x60b403: mov eax,[ecx+8]
0x60b406: mov [eax+10h],bl
0x60b409: push ebp
0x60b40a: mov byte ptr [ecx+10h],0
0x60b40e: call 0060B470h
0x60b413: mov ecx,[esi]
0x60b415: mov dl,[esi+10h]
0x60b418: mov [ecx+10h],dl
0x60b41b: mov [esi+10h],bl
0x60b41e: mov eax,[ecx]
0x60b420: push ebp
0x60b421: mov ecx,esi
0x60b423: mov [eax+10h],bl
0x60b426: call 004DE490h
0x60b42b: mov [edi+10h],bl
0x60b42e: mov ecx,[esp+68h]
0x60b432: push ecx
0x60b433: call 006516BAh
0x60b438: mov eax,[ebp+8]
0x60b43b: add esp,4
0x60b43e: test eax,eax
0x60b440: jbe short 0060B448h
0x60b442: add eax,0FFFFFFFFh
0x60b445: mov [ebp+8],eax
0x60b448: mov eax,[esp+6Ch]
0x60b44c: mov edx,[esp+70h]
0x60b450: mov ecx,[esp+74h]
0x60b454: mov [eax],edx
0x60b456: mov [eax+4],ecx
0x60b459: mov ecx,[esp+58h]
0x60b45d: mov fs:[0],ecx
0x60b464: pop ecx
0x60b465: pop edi
0x60b466: pop esi
0x60b467: pop ebp
0x60b468: pop ebx
0x60b469: add esp,50h
0x60b46c: ret 10h
````

`sub_60b1c0` is called by sub_60b040. It delegates to sub_401230, sub_4b6490, sub_4de470 (7 callees).

### sub_60b470 at 0x60b470 (28 instructions)

````text
0x60b470: mov eax,[ecx+8]
0x60b473: mov edx,[eax]
0x60b475: mov [ecx+8],edx
0x60b478: mov edx,[eax]
0x60b47a: cmp byte ptr [edx+11h],0
0x60b47e: jne short 0060B483h
0x60b480: mov [edx+4],ecx
0x60b483: mov edx,[ecx+4]
0x60b486: mov [eax+4],edx
0x60b489: mov edx,[esp+4]
0x60b48d: mov edx,[edx+4]
0x60b490: cmp ecx,[edx+4]
0x60b493: jne short 0060B4A0h
0x60b495: mov [edx+4],eax
0x60b498: mov [eax],ecx
0x60b49a: mov [ecx+4],eax
0x60b49d: ret 4
0x60b4a0: mov edx,[ecx+4]
0x60b4a3: cmp ecx,[edx]
0x60b4a5: jne short 0060B4B1h
0x60b4a7: mov [edx],eax
0x60b4a9: mov [eax],ecx
0x60b4ab: mov [ecx+4],eax
0x60b4ae: ret 4
0x60b4b1: mov [edx+8],eax
0x60b4b4: mov [eax],ecx
0x60b4b6: mov [ecx+4],eax
0x60b4b9: ret 4
````

`sub_60b470` is called by sub_4b5020, sub_60b1c0. It calls nothing else.

### sub_60b550 at 0x60b550 (2550 instructions)

````text
0x60b550: push 0FFFFFFFFh
0x60b552: push 74F4DCh
0x60b557: mov eax,fs:[0]
0x60b55d: push eax
0x60b55e: sub esp,40h
0x60b561: push ebx
0x60b562: push ebp
0x60b563: push esi
0x60b564: push edi
0x60b565: mov eax,ds:[858220h]
0x60b56a: xor eax,esp
0x60b56c: push eax
0x60b56d: lea eax,[esp+54h]
0x60b571: mov fs:[0],eax
0x60b577: mov edi,[esp+64h]
0x60b57b: push 7C31C7h
0x60b580: mov ecx,edi
0x60b582: call dword ptr ds:[77CD7Ch]
0x60b588: xor eax,eax
0x60b58a: lea esi,[edi+1Ch]
0x60b58d: mov [esp+5Ch],eax
0x60b591: mov [esi+4],eax
0x60b594: mov [esi+8],eax
0x60b597: mov [esi+0Ch],eax
0x60b59a: lea ebp,[edi+2Ch]
0x60b59d: mov ebx,1
0x60b5a2: mov ecx,ebp
0x60b5a4: mov [esp+5Ch],bl
0x60b5a8: call 006101D0h
0x60b5ad: mov [ebp+4],eax
0x60b5b0: mov [eax+2Dh],bl
0x60b5b3: mov eax,[ebp+4]
0x60b5b6: mov [eax+4],eax
0x60b5b9: mov eax,[ebp+4]
0x60b5bc: mov [eax],eax
0x60b5be: mov eax,[ebp+4]
0x60b5c1: mov [eax+8],eax
0x60b5c4: mov dword ptr [ebp+8],0
0x60b5cb: lea ebp,[edi+38h]
0x60b5ce: mov ecx,ebp
0x60b5d0: mov byte ptr [esp+5Ch],2
0x60b5d5: call 00610650h
0x60b5da: mov [ebp+4],eax
0x60b5dd: mov [eax+45h],bl
0x60b5e0: mov eax,[ebp+4]
0x60b5e3: mov [eax+4],eax
0x60b5e6: mov eax,[ebp+4]
0x60b5e9: mov [eax],eax
0x60b5eb: mov eax,[ebp+4]
0x60b5ee: mov [eax+8],eax
0x60b5f1: mov dword ptr [ebp+8],0
0x60b5f8: mov eax,esi
0x60b5fa: mov byte ptr [esp+5Ch],3
0x60b5ff: call 0060EF60h
0x60b604: mov eax,[esi+4]
0x60b607: test eax,eax
0x60b609: je short 0060B618h
0x60b60b: mov ecx,[esi+8]
0x60b60e: sub ecx,eax
0x60b610: sar ecx,2
0x60b613: cmp ecx,7Eh
0x60b616: ja short 0060B61Eh
0x60b618: call dword ptr ds:[77D0E4h]
0x60b61e: mov eax,[esi+4]
0x60b621: push 7Eh
0x60b623: sub esp,1Ch
0x60b626: mov ecx,esp
0x60b628: mov [esp+38h],esp
0x60b62c: push 7F5690h
0x60b631: mov dword ptr [eax+1F8h],0FFFFFFFFh
0x60b63b: call dword ptr ds:[77CD7Ch]
0x60b641: push edi
0x60b642: call 0060EAB0h
0x60b647: mov eax,[esi+4]
0x60b64a: xor ebp,ebp
0x60b64c: cmp eax,ebp
0x60b64e: je short 0060B65Ah
0x60b650: mov ecx,[esi+8]
0x60b653: sub ecx,eax
0x60b655: sar ecx,2
0x60b658: jne short 0060B660h
0x60b65a: call dword ptr ds:[77D0E4h]
0x60b660: mov edx,[esi+4]
0x60b663: push ebp
0x60b664: sub esp,1Ch
0x60b667: mov ecx,esp
0x60b669: mov [esp+38h],esp
0x60b66d: push 7F5698h
0x60b672: mov dword ptr [edx],0FFFFFFh
0x60b678: call dword ptr ds:[77CD7Ch]
0x60b67e: push edi
0x60b67f: call 0060EAB0h
0x60b684: mov ecx,[esi+4]
0x60b687: cmp ecx,ebp
0x60b689: je short 0060B697h
0x60b68b: mov eax,[esi+8]
0x60b68e: sub eax,ecx
0x60b690: sar eax,2
0x60b693: cmp eax,ebx
0x60b695: ja short 0060B69Dh
0x60b697: call dword ptr ds:[77D0E4h]
0x60b69d: mov eax,[esi+4]
0x60b6a0: push ebx
0x60b6a1: sub esp,1Ch
0x60b6a4: mov ecx,esp
0x60b6a6: mov [esp+38h],esp
0x60b6aa: push 7F56A0h
0x60b6af: mov [eax+4],ebp
0x60b6b2: call dword ptr ds:[77CD7Ch]
0x60b6b8: push edi
0x60b6b9: call 0060EAB0h
0x60b6be: mov ecx,[esi+4]
0x60b6c1: cmp ecx,ebp
0x60b6c3: je short 0060B6D2h
0x60b6c5: mov eax,[esi+8]
0x60b6c8: sub eax,ecx
0x60b6ca: sar eax,2
0x60b6cd: cmp eax,2
0x60b6d0: ja short 0060B6D8h
0x60b6d2: call dword ptr ds:[77D0E4h]
0x60b6d8: mov ecx,[esi+4]
0x60b6db: push 2
0x60b6dd: sub esp,1Ch
0x60b6e0: mov dword ptr [ecx+8],202020h
0x60b6e7: mov ecx,esp
0x60b6e9: mov [esp+38h],esp
0x60b6ed: push 7F56B0h
0x60b6f2: call dword ptr ds:[77CD7Ch]
0x60b6f8: push edi
0x60b6f9: call 0060EAB0h
0x60b6fe: mov ecx,[esi+4]
0x60b701: cmp ecx,ebp
0x60b703: je short 0060B712h
0x60b705: mov eax,[esi+8]
0x60b708: sub eax,ecx
0x60b70a: sar eax,2
0x60b70d: cmp eax,3
0x60b710: ja short 0060B71Ch
0x60b712: mov ebx,ds:[77D0E4h]
0x60b718: call ebx
0x60b71a: jmp short 0060B722h
0x60b71c: mov ebx,ds:[77D0E4h]
0x60b722: mov edx,[esi+4]
0x60b725: push 3
0x60b727: sub esp,1Ch
0x60b72a: mov ecx,esp
0x60b72c: mov [esp+38h],esp
0x60b730: push 7F56C0h
0x60b735: mov [edx+0Ch],ebp
0x60b738: call dword ptr ds:[77CD7Ch]
0x60b73e: push edi
0x60b73f: call 0060EAB0h
0x60b744: mov ecx,[esi+4]
0x60b747: cmp ecx,ebp
0x60b749: je short 0060B758h
0x60b74b: mov eax,[esi+8]
0x60b74e: sub eax,ecx
0x60b750: sar eax,2
0x60b753: cmp eax,4
0x60b756: ja short 0060B75Ah
0x60b758: call ebx
0x60b75a: mov eax,[esi+4]
0x60b75d: push 4
0x60b75f: sub esp,1Ch
0x60b762: mov ecx,esp
0x60b764: mov [esp+38h],esp
0x60b768: push 7F56D8h
0x60b76d: mov dword ptr [eax+10h],5Ah
0x60b774: call dword ptr ds:[77CD7Ch]
0x60b77a: push edi
0x60b77b: call 0060EAB0h
0x60b780: mov ecx,[esi+4]
0x60b783: cmp ecx,ebp
0x60b785: je short 0060B794h
0x60b787: mov eax,[esi+8]
0x60b78a: sub eax,ecx
0x60b78c: sar eax,2
0x60b78f: cmp eax,6Ch
0x60b792: ja short 0060B796h
0x60b794: call ebx
0x60b796: mov ecx,[esi+4]
0x60b799: push 6Ch
0x60b79b: sub esp,1Ch
0x60b79e: mov dword ptr [ecx+1B0h],0FFFFFFh
0x60b7a8: mov ecx,esp
0x60b7aa: mov [esp+38h],esp
0x60b7ae: push 7F56E4h
0x60b7b3: call dword ptr ds:[77CD7Ch]
0x60b7b9: push edi
0x60b7ba: call 0060EAB0h
0x60b7bf: mov ecx,[esi+4]
0x60b7c2: cmp ecx,ebp
0x60b7c4: je short 0060B7D3h
0x60b7c6: mov eax,[esi+8]
0x60b7c9: sub eax,ecx
0x60b7cb: sar eax,2
0x60b7ce: cmp eax,6Dh
0x60b7d1: ja short 0060B7D5h
0x60b7d3: call ebx
0x60b7d5: mov edx,[esi+4]
0x60b7d8: push 6Dh
0x60b7da: sub esp,1Ch
0x60b7dd: mov ecx,esp
0x60b7df: mov [esp+38h],esp
0x60b7e3: push 7F56ECh
0x60b7e8: mov [edx+1B4h],ebp
0x60b7ee: call dword ptr ds:[77CD7Ch]
0x60b7f4: push edi
0x60b7f5: call 0060EAB0h
0x60b7fa: mov ecx,[esi+4]
0x60b7fd: cmp ecx,ebp
0x60b7ff: je short 0060B80Eh
0x60b801: mov eax,[esi+8]
0x60b804: sub eax,ecx
0x60b806: sar eax,2
0x60b809: cmp eax,6Eh
0x60b80c: ja short 0060B810h
0x60b80e: call ebx
0x60b810: mov eax,[esi+4]
0x60b813: push 6Eh
0x60b815: sub esp,1Ch
0x60b818: mov ecx,esp
0x60b81a: mov [esp+38h],esp
0x60b81e: mov ebx,0C0C0h
0x60b823: push 7F56F8h
0x60b828: mov [eax+1B8h],ebx
0x60b82e: call dword ptr ds:[77CD7Ch]
0x60b834: push edi
0x60b835: call 0060EAB0h
0x60b83a: mov ecx,[esi+4]
0x60b83d: cmp ecx,ebp
0x60b83f: je short 0060B84Eh
0x60b841: mov eax,[esi+8]
0x60b844: sub eax,ecx
0x60b846: sar eax,2
0x60b849: cmp eax,5
0x60b84c: ja short 0060B854h
0x60b84e: call dword ptr ds:[77D0E4h]
0x60b854: mov ecx,[esi+4]
0x60b857: push 5
0x60b859: sub esp,1Ch
0x60b85c: mov dword ptr [ecx+14h],0FFFFFFh
0x60b863: mov ecx,esp
0x60b865: mov [esp+38h],esp
0x60b869: push 7F5704h
0x60b86e: call dword ptr ds:[77CD7Ch]
0x60b874: push edi
0x60b875: call 0060EAB0h
0x60b87a: mov ecx,[esi+4]
0x60b87d: cmp ecx,ebp
0x60b87f: je short 0060B88Eh
0x60b881: mov eax,[esi+8]
0x60b884: sub eax,ecx
0x60b886: sar eax,2
0x60b889: cmp eax,6
0x60b88c: ja short 0060B894h
0x60b88e: call dword ptr ds:[77D0E4h]
0x60b894: mov edx,[esi+4]
0x60b897: push 6
0x60b899: sub esp,1Ch
0x60b89c: mov ecx,esp
0x60b89e: mov [esp+38h],esp
0x60b8a2: push 7F570Ch
0x60b8a7: mov dword ptr [edx+18h],0FFh
0x60b8ae: call dword ptr ds:[77CD7Ch]
0x60b8b4: push edi
0x60b8b5: call 0060EAB0h
0x60b8ba: mov ecx,[esi+4]
0x60b8bd: cmp ecx,ebp
0x60b8bf: je short 0060B8CEh
0x60b8c1: mov eax,[esi+8]
0x60b8c4: sub eax,ecx
0x60b8c6: sar eax,2
0x60b8c9: cmp eax,7
0x60b8cc: ja short 0060B8D4h
0x60b8ce: call dword ptr ds:[77D0E4h]
0x60b8d4: mov eax,[esi+4]
0x60b8d7: push 7
0x60b8d9: sub esp,1Ch
0x60b8dc: mov ecx,esp
0x60b8de: mov [esp+38h],esp
0x60b8e2: push 7F5710h
0x60b8e7: mov dword ptr [eax+1Ch],0FF00h
0x60b8ee: call dword ptr ds:[77CD7Ch]
0x60b8f4: push edi
0x60b8f5: call 0060EAB0h
0x60b8fa: mov ecx,[esi+4]
0x60b8fd: cmp ecx,ebp
0x60b8ff: je short 0060B90Eh
0x60b901: mov eax,[esi+8]
0x60b904: sub eax,ecx
0x60b906: sar eax,2
0x60b909: cmp eax,8
0x60b90c: ja short 0060B914h
0x60b90e: call dword ptr ds:[77D0E4h]
0x60b914: mov ecx,[esi+4]
0x60b917: push 8
0x60b919: sub esp,1Ch
0x60b91c: mov dword ptr [ecx+20h],0FFFFFFh
0x60b923: mov ecx,esp
0x60b925: mov [esp+38h],esp
0x60b929: push 7F5718h
0x60b92e: call dword ptr ds:[77CD7Ch]
0x60b934: push edi
0x60b935: call 0060EAB0h
0x60b93a: mov ecx,[esi+4]
0x60b93d: cmp ecx,ebp
0x60b93f: je short 0060B94Eh
0x60b941: mov eax,[esi+8]
0x60b944: sub eax,ecx
0x60b946: sar eax,2
0x60b949: cmp eax,9
0x60b94c: ja short 0060B954h
0x60b94e: call dword ptr ds:[77D0E4h]
0x60b954: mov edx,[esi+4]
0x60b957: push 9
0x60b959: sub esp,1Ch
0x60b95c: mov ecx,esp
0x60b95e: mov [esp+38h],esp
0x60b962: mov ebp,0C0C0C0h
0x60b967: push 7F5724h
0x60b96c: mov [edx+24h],ebp
0x60b96f: call dword ptr ds:[77CD7Ch]
0x60b975: push edi
0x60b976: call 0060EAB0h
0x60b97b: mov ecx,[esi+4]
0x60b97e: test ecx,ecx
0x60b980: je short 0060B98Fh
0x60b982: mov eax,[esi+8]
0x60b985: sub eax,ecx
0x60b987: sar eax,2
0x60b98a: cmp eax,0Ah
0x60b98d: ja short 0060B995h
0x60b98f: call dword ptr ds:[77D0E4h]
0x60b995: mov eax,[esi+4]
0x60b998: push 0Ah
0x60b99a: sub esp,1Ch
0x60b99d: mov ecx,esp
0x60b99f: mov [esp+38h],esp
0x60b9a3: push 7F572Ch
0x60b9a8: mov [eax+28h],ebp
0x60b9ab: call dword ptr ds:[77CD7Ch]
0x60b9b1: push edi
0x60b9b2: call 0060EAB0h
0x60b9b7: mov ecx,[esi+4]
0x60b9ba: test ecx,ecx
0x60b9bc: je short 0060B9CBh
0x60b9be: mov eax,[esi+8]
0x60b9c1: sub eax,ecx
0x60b9c3: sar eax,2
0x60b9c6: cmp eax,0Bh
0x60b9c9: ja short 0060B9D1h
0x60b9cb: call dword ptr ds:[77D0E4h]
0x60b9d1: mov ecx,[esi+4]
0x60b9d4: push 0Bh
0x60b9d6: sub esp,1Ch
0x60b9d9: mov ebp,0FFFFh
0x60b9de: mov [ecx+2Ch],ebp
0x60b9e1: mov ecx,esp
0x60b9e3: mov [esp+38h],esp
0x60b9e7: push 7F5734h
0x60b9ec: call dword ptr ds:[77CD7Ch]
0x60b9f2: push edi
0x60b9f3: call 0060EAB0h
0x60b9f8: mov ecx,[esi+4]
0x60b9fb: test ecx,ecx
0x60b9fd: je short 0060BA0Ch
0x60b9ff: mov eax,[esi+8]
0x60ba02: sub eax,ecx
0x60ba04: sar eax,2
0x60ba07: cmp eax,0Ch
0x60ba0a: ja short 0060BA12h
0x60ba0c: call dword ptr ds:[77D0E4h]
0x60ba12: mov edx,[esi+4]
0x60ba15: push 0Ch
0x60ba17: sub esp,1Ch
0x60ba1a: mov ecx,esp
0x60ba1c: mov [esp+38h],esp
0x60ba20: push 7F573Ch
0x60ba25: mov dword ptr [edx+30h],1C2DFFh
0x60ba2c: call dword ptr ds:[77CD7Ch]
0x60ba32: push edi
0x60ba33: call 0060EAB0h
0x60ba38: mov ecx,[esi+4]
0x60ba3b: test ecx,ecx
0x60ba3d: je short 0060BA4Ch
0x60ba3f: mov eax,[esi+8]
0x60ba42: sub eax,ecx
0x60ba44: sar eax,2
0x60ba47: cmp eax,0Dh
0x60ba4a: ja short 0060BA52h
0x60ba4c: call dword ptr ds:[77D0E4h]
0x60ba52: mov eax,[esi+4]
0x60ba55: push 0Dh
0x60ba57: sub esp,1Ch
0x60ba5a: mov ecx,esp
0x60ba5c: mov [esp+38h],esp
0x60ba60: push 7F5744h
0x60ba65: mov dword ptr [eax+34h],30C700h
0x60ba6c: call dword ptr ds:[77CD7Ch]
0x60ba72: push edi
0x60ba73: call 0060EAB0h
0x60ba78: mov ecx,[esi+4]
0x60ba7b: test ecx,ecx
0x60ba7d: je short 0060BA8Ch
0x60ba7f: mov eax,[esi+8]
0x60ba82: sub eax,ecx
0x60ba84: sar eax,2
0x60ba87: cmp eax,0Eh
0x60ba8a: ja short 0060BA92h
0x60ba8c: call dword ptr ds:[77D0E4h]
0x60ba92: mov ecx,[esi+4]
0x60ba95: push 0Eh
0x60ba97: sub esp,1Ch
0x60ba9a: mov dword ptr [ecx+38h],0FFFFFFh
0x60baa1: mov ecx,esp
0x60baa3: mov [esp+38h],esp
0x60baa7: push 7F5750h
0x60baac: call dword ptr ds:[77CD7Ch]
0x60bab2: push edi
0x60bab3: call 0060EAB0h
0x60bab8: mov ecx,[esi+4]
0x60babb: test ecx,ecx
0x60babd: je short 0060BACCh
0x60babf: mov eax,[esi+8]
0x60bac2: sub eax,ecx
0x60bac4: sar eax,2
0x60bac7: cmp eax,0Fh
0x60baca: ja short 0060BAD2h
0x60bacc: call dword ptr ds:[77D0E4h]
0x60bad2: mov edx,[esi+4]
0x60bad5: push 0Fh
0x60bad7: sub esp,1Ch
0x60bada: mov ecx,esp
0x60badc: mov [esp+38h],esp
0x60bae0: push 7F575Ch
0x60bae5: mov dword ptr [edx+3Ch],0C4C4h
0x60baec: call dword ptr ds:[77CD7Ch]
0x60baf2: push edi
0x60baf3: call 0060EAB0h
0x60baf8: mov ecx,[esi+4]
0x60bafb: test ecx,ecx
0x60bafd: je short 0060BB0Ch
0x60baff: mov eax,[esi+8]
0x60bb02: sub eax,ecx
0x60bb04: sar eax,2
0x60bb07: cmp eax,10h
0x60bb0a: ja short 0060BB12h
0x60bb0c: call dword ptr ds:[77D0E4h]
0x60bb12: mov eax,[esi+4]
0x60bb15: push 10h
0x60bb17: sub esp,1Ch
0x60bb1a: mov ecx,esp
0x60bb1c: mov [esp+38h],esp
0x60bb20: push 7F5764h
0x60bb25: mov dword ptr [eax+40h],88F8F0h
0x60bb2c: call dword ptr ds:[77CD7Ch]
0x60bb32: push edi
0x60bb33: call 0060EAB0h
0x60bb38: mov ecx,[esi+4]
0x60bb3b: test ecx,ecx
0x60bb3d: je short 0060BB4Ch
0x60bb3f: mov eax,[esi+8]
0x60bb42: sub eax,ecx
0x60bb44: sar eax,2
0x60bb47: cmp eax,11h
0x60bb4a: ja short 0060BB52h
0x60bb4c: call dword ptr ds:[77D0E4h]
0x60bb52: mov ecx,[esi+4]
0x60bb55: push 11h
0x60bb57: sub esp,1Ch
0x60bb5a: mov dword ptr [ecx+44h],0F4E202h
0x60bb61: mov ecx,esp
0x60bb63: mov [esp+38h],esp
0x60bb67: push 7C3B34h
0x60bb6c: call dword ptr ds:[77CD7Ch]
0x60bb72: push edi
0x60bb73: call 0060EAB0h
0x60bb78: mov ecx,[esi+4]
0x60bb7b: test ecx,ecx
0x60bb7d: je short 0060BB8Ch
0x60bb7f: mov eax,[esi+8]
0x60bb82: sub eax,ecx
0x60bb84: sar eax,2
0x60bb87: cmp eax,12h
0x60bb8a: ja short 0060BB92h
0x60bb8c: call dword ptr ds:[77D0E4h]
0x60bb92: mov edx,[esi+4]
0x60bb95: push 12h
0x60bb97: sub esp,1Ch
0x60bb9a: mov ecx,esp
0x60bb9c: mov [esp+38h],esp
0x60bba0: push 7F576Ch
0x60bba5: mov [edx+48h],ebx
0x60bba8: call dword ptr ds:[77CD7Ch]
0x60bbae: push edi
0x60bbaf: call 0060EAB0h
0x60bbb4: mov ecx,[esi+4]
0x60bbb7: test ecx,ecx
0x60bbb9: je short 0060BBC8h
0x60bbbb: mov eax,[esi+8]
0x60bbbe: sub eax,ecx
0x60bbc0: sar eax,2
0x60bbc3: cmp eax,13h
0x60bbc6: ja short 0060BBD2h
0x60bbc8: mov ebx,ds:[77D0E4h]
0x60bbce: call ebx
0x60bbd0: jmp short 0060BBD8h
0x60bbd2: mov ebx,ds:[77D0E4h]
0x60bbd8: mov eax,[esi+4]
0x60bbdb: push 13h
0x60bbdd: sub esp,1Ch
0x60bbe0: mov ecx,esp
0x60bbe2: mov [esp+38h],esp
0x60bbe6: push 7F5774h
0x60bbeb: mov dword ptr [eax+4Ch],0C000C0h
0x60bbf2: call dword ptr ds:[77CD7Ch]
0x60bbf8: push edi
0x60bbf9: call 0060EAB0h
0x60bbfe: mov ecx,[esi+4]
0x60bc01: test ecx,ecx
0x60bc03: je short 0060BC12h
0x60bc05: mov eax,[esi+8]
0x60bc08: sub eax,ecx
0x60bc0a: sar eax,2
0x60bc0d: cmp eax,14h
0x60bc10: ja short 0060BC14h
0x60bc12: call ebx
0x60bc14: mov ecx,[esi+4]
0x60bc17: push 14h
0x60bc19: sub esp,1Ch
0x60bc1c: mov dword ptr [ecx+50h],808080h
0x60bc23: mov ecx,esp
0x60bc25: mov [esp+38h],esp
0x60bc29: push 7F5780h
0x60bc2e: call dword ptr ds:[77CD7Ch]
0x60bc34: push edi
0x60bc35: call 0060EAB0h
0x60bc3a: mov ecx,[esi+4]
0x60bc3d: test ecx,ecx
0x60bc3f: je short 0060BC4Eh
0x60bc41: mov eax,[esi+8]
0x60bc44: sub eax,ecx
0x60bc46: sar eax,2
0x60bc49: cmp eax,15h
0x60bc4c: ja short 0060BC50h
0x60bc4e: call ebx
0x60bc50: mov edx,[esi+4]
0x60bc53: push 15h
0x60bc55: sub esp,1Ch
0x60bc58: mov ecx,esp
0x60bc5a: mov [esp+38h],esp
0x60bc5e: push 7EE63Ch
0x60bc63: mov dword ptr [edx+54h],0A4A4A4h
0x60bc6a: call dword ptr ds:[77CD7Ch]
0x60bc70: push edi
0x60bc71: call 0060EAB0h
0x60bc76: mov ecx,[esi+4]
0x60bc79: test ecx,ecx
0x60bc7b: je short 0060BC8Ah
0x60bc7d: mov eax,[esi+8]
0x60bc80: sub eax,ecx
0x60bc82: sar eax,2
0x60bc85: cmp eax,16h
0x60bc88: ja short 0060BC8Ch
0x60bc8a: call ebx
0x60bc8c: mov eax,[esi+4]
0x60bc8f: push 16h
0x60bc91: sub esp,1Ch
0x60bc94: mov ecx,esp
0x60bc96: mov [esp+38h],esp
0x60bc9a: mov ebx,5Ah
0x60bc9f: push 7F5790h
0x60bca4: mov [eax+58h],ebx
0x60bca7: call dword ptr ds:[77CD7Ch]
0x60bcad: push edi
0x60bcae: call 0060EAB0h
0x60bcb3: mov ecx,[esi+4]
0x60bcb6: test ecx,ecx
0x60bcb8: je short 0060BCC7h
0x60bcba: mov eax,[esi+8]
0x60bcbd: sub eax,ecx
0x60bcbf: sar eax,2
0x60bcc2: cmp eax,17h
0x60bcc5: ja short 0060BCCDh
0x60bcc7: call dword ptr ds:[77D0E4h]
0x60bccd: mov ecx,[esi+4]
0x60bcd0: push 17h
0x60bcd2: sub esp,1Ch
0x60bcd5: mov [ecx+5Ch],ebx
0x60bcd8: mov ecx,esp
0x60bcda: mov [esp+38h],esp
0x60bcde: push 7F579Ch
0x60bce3: call dword ptr ds:[77CD7Ch]
0x60bce9: push edi
0x60bcea: call 0060EAB0h
0x60bcef: mov ecx,[esi+4]
0x60bcf2: test ecx,ecx
0x60bcf4: je short 0060BD03h
0x60bcf6: mov eax,[esi+8]
0x60bcf9: sub eax,ecx
0x60bcfb: sar eax,2
0x60bcfe: cmp eax,18h
0x60bd01: ja short 0060BD09h
0x60bd03: call dword ptr ds:[77D0E4h]
0x60bd09: mov edx,[esi+4]
0x60bd0c: push 18h
0x60bd0e: sub esp,1Ch
0x60bd11: mov ecx,esp
0x60bd13: mov [esp+38h],esp
0x60bd17: mov ebx,0FFFFFFh
0x60bd1c: push 7F57A8h
0x60bd21: mov [edx+60h],ebx
0x60bd24: call dword ptr ds:[77CD7Ch]
0x60bd2a: push edi
0x60bd2b: call 0060EAB0h
0x60bd30: mov ecx,[esi+4]
0x60bd33: test ecx,ecx
0x60bd35: je short 0060BD44h
0x60bd37: mov eax,[esi+8]
0x60bd3a: sub eax,ecx
0x60bd3c: sar eax,2
0x60bd3f: cmp eax,19h
0x60bd42: ja short 0060BD4Ah
0x60bd44: call dword ptr ds:[77D0E4h]
0x60bd4a: mov eax,[esi+4]
0x60bd4d: push 19h
0x60bd4f: sub esp,1Ch
0x60bd52: mov ecx,esp
0x60bd54: mov [esp+38h],esp
0x60bd58: push 7F57B4h
0x60bd5d: mov [eax+64h],ebp
0x60bd60: call dword ptr ds:[77CD7Ch]
0x60bd66: push edi
0x60bd67: call 0060EAB0h
0x60bd6c: mov ecx,[esi+4]
0x60bd6f: test ecx,ecx
0x60bd71: je short 0060BD80h
0x60bd73: mov eax,[esi+8]
0x60bd76: sub eax,ecx
0x60bd78: sar eax,2
0x60bd7b: cmp eax,1Ah
0x60bd7e: ja short 0060BD86h
0x60bd80: call dword ptr ds:[77D0E4h]
0x60bd86: mov ecx,[esi+4]
0x60bd89: push 1Ah
0x60bd8b: sub esp,1Ch
0x60bd8e: mov [ecx+68h],ebp
0x60bd91: mov ecx,esp
0x60bd93: mov [esp+38h],esp
0x60bd97: push 7F57C4h
0x60bd9c: call dword ptr ds:[77CD7Ch]
0x60bda2: push edi
0x60bda3: call 0060EAB0h
0x60bda8: mov ecx,[esi+4]
0x60bdab: test ecx,ecx
0x60bdad: je short 0060BDBCh
0x60bdaf: mov eax,[esi+8]
0x60bdb2: sub eax,ecx
0x60bdb4: sar eax,2
0x60bdb7: cmp eax,1Bh
0x60bdba: ja short 0060BDC6h
0x60bdbc: mov ebp,ds:[77D0E4h]
0x60bdc2: call ebp
0x60bdc4: jmp short 0060BDCCh
0x60bdc6: mov ebp,ds:[77D0E4h]
0x60bdcc: mov edx,[esi+4]
0x60bdcf: push 1Bh
0x60bdd1: sub esp,1Ch
0x60bdd4: mov ecx,esp
0x60bdd6: mov [esp+38h],esp
0x60bdda: push 7F57D0h
0x60bddf: mov dword ptr [edx+6Ch],0EBB682h
0x60bde6: call dword ptr ds:[77CD7Ch]
0x60bdec: push edi
0x60bded: call 0060EAB0h
0x60bdf2: mov ecx,[esi+4]
0x60bdf5: test ecx,ecx
0x60bdf7: je short 0060BE06h
0x60bdf9: mov eax,[esi+8]
0x60bdfc: sub eax,ecx
0x60bdfe: sar eax,2
0x60be01: cmp eax,1Ch
0x60be04: ja short 0060BE08h
0x60be06: call ebp
0x60be08: mov eax,[esi+4]
0x60be0b: push 1Ch
0x60be0d: sub esp,1Ch
0x60be10: mov ecx,esp
0x60be12: mov [esp+38h],esp
0x60be16: push 7F57E0h
0x60be1b: mov dword ptr [eax+70h],0EBECD9h
0x60be22: call dword ptr ds:[77CD7Ch]
0x60be28: push edi
0x60be29: call 0060EAB0h
0x60be2e: mov ecx,[esi+4]
0x60be31: test ecx,ecx
0x60be33: je short 0060BE42h
0x60be35: mov eax,[esi+8]
0x60be38: sub eax,ecx
0x60be3a: sar eax,2
0x60be3d: cmp eax,1Dh
0x60be40: ja short 0060BE44h
0x60be42: call ebp
0x60be44: mov ecx,[esi+4]
0x60be47: push 1Dh
0x60be49: sub esp,1Ch
0x60be4c: mov dword ptr [ecx+74h],3D3DFFh
0x60be53: mov ecx,esp
0x60be55: mov [esp+38h],esp
0x60be59: push 7F57F0h
0x60be5e: call dword ptr ds:[77CD7Ch]
0x60be64: push edi
0x60be65: call 0060EAB0h
0x60be6a: mov ecx,[esi+4]
0x60be6d: test ecx,ecx
0x60be6f: je short 0060BE7Eh
0x60be71: mov eax,[esi+8]
0x60be74: sub eax,ecx
0x60be76: sar eax,2
0x60be79: cmp eax,1Eh
0x60be7c: ja short 0060BE80h
0x60be7e: call ebp
0x60be80: mov edx,[esi+4]
0x60be83: push 1Eh
0x60be85: sub esp,1Ch
0x60be88: mov ecx,esp
0x60be8a: mov [esp+38h],esp
0x60be8e: push 7F57F8h
0x60be93: mov dword ptr [edx+78h],0FFFF54h
0x60be9a: call dword ptr ds:[77CD7Ch]
0x60bea0: push edi
0x60bea1: call 0060EAB0h
0x60bea6: mov ecx,[esi+4]
0x60bea9: test ecx,ecx
0x60beab: je short 0060BEBAh
0x60bead: mov eax,[esi+8]
0x60beb0: sub eax,ecx
0x60beb2: sar eax,2
0x60beb5: cmp eax,1Fh
0x60beb8: ja short 0060BEBCh
0x60beba: call ebp
0x60bebc: mov eax,[esi+4]
0x60bebf: push 1Fh
0x60bec1: sub esp,1Ch
0x60bec4: mov ecx,esp
0x60bec6: mov [esp+38h],esp
0x60beca: push 7F5804h
0x60becf: mov [eax+7Ch],ebx
0x60bed2: call dword ptr ds:[77CD7Ch]
0x60bed8: push edi
0x60bed9: call 0060EAB0h
0x60bede: mov ecx,[esi+4]
0x60bee1: test ecx,ecx
0x60bee3: je short 0060BEF2h
0x60bee5: mov eax,[esi+8]
0x60bee8: sub eax,ecx
0x60beea: sar eax,2
0x60beed: cmp eax,20h
0x60bef0: ja short 0060BEF4h
0x60bef2: call ebp
0x60bef4: mov ecx,[esi+4]
0x60bef7: push 20h
0x60bef9: sub esp,1Ch
0x60befc: mov dword ptr [ecx+80h],969696h
0x60bf06: mov ecx,esp
0x60bf08: mov [esp+38h],esp
0x60bf0c: push 7F5810h
0x60bf11: call dword ptr ds:[77CD7Ch]
0x60bf17: push edi
0x60bf18: call 0060EAB0h
0x60bf1d: mov ecx,[esi+4]
0x60bf20: test ecx,ecx
0x60bf22: je short 0060BF31h
0x60bf24: mov eax,[esi+8]
0x60bf27: sub eax,ecx
0x60bf29: sar eax,2
0x60bf2c: cmp eax,21h
0x60bf2f: ja short 0060BF33h
0x60bf31: call ebp
0x60bf33: mov edx,[esi+4]
0x60bf36: push 21h
0x60bf38: sub esp,1Ch
0x60bf3b: mov ecx,esp
0x60bf3d: mov [esp+38h],esp
0x60bf41: push 7F5820h
0x60bf46: mov dword ptr [edx+84h],40A8h
0x60bf50: call dword ptr ds:[77CD7Ch]
0x60bf56: push edi
0x60bf57: call 0060EAB0h
0x60bf5c: mov ecx,[esi+4]
0x60bf5f: test ecx,ecx
0x60bf61: je short 0060BF70h
0x60bf63: mov eax,[esi+8]
0x60bf66: sub eax,ecx
0x60bf68: sar eax,2
0x60bf6b: cmp eax,22h
0x60bf6e: ja short 0060BF72h
0x60bf70: call ebp
0x60bf72: mov eax,[esi+4]
0x60bf75: push 22h
0x60bf77: sub esp,1Ch
0x60bf7a: mov ecx,esp
0x60bf7c: mov [esp+38h],esp
0x60bf80: push 7F5830h
0x60bf85: mov dword ptr [eax+88h],549600h
0x60bf8f: call dword ptr ds:[77CD7Ch]
0x60bf95: push edi
0x60bf96: call 0060EAB0h
0x60bf9b: mov ecx,[esi+4]
0x60bf9e: test ecx,ecx
0x60bfa0: je short 0060BFAFh
0x60bfa2: mov eax,[esi+8]
0x60bfa5: sub eax,ecx
0x60bfa7: sar eax,2
0x60bfaa: cmp eax,23h
0x60bfad: ja short 0060BFB1h
0x60bfaf: call ebp
0x60bfb1: mov ecx,[esi+4]
0x60bfb4: push 23h
0x60bfb6: sub esp,1Ch
0x60bfb9: mov ebx,646464h
0x60bfbe: mov [ecx+8Ch],ebx
0x60bfc4: mov ecx,esp
0x60bfc6: mov [esp+38h],esp
0x60bfca: push 7F5840h
0x60bfcf: call dword ptr ds:[77CD7Ch]
0x60bfd5: push edi
0x60bfd6: call 0060EAB0h
0x60bfdb: mov ecx,[esi+4]
0x60bfde: test ecx,ecx
0x60bfe0: je short 0060BFEFh
0x60bfe2: mov eax,[esi+8]
0x60bfe5: sub eax,ecx
0x60bfe7: sar eax,2
0x60bfea: cmp eax,24h
0x60bfed: ja short 0060BFF9h
0x60bfef: mov ebp,ds:[77D0E4h]
0x60bff5: call ebp
0x60bff7: jmp short 0060BFFFh
0x60bff9: mov ebp,ds:[77D0E4h]
0x60bfff: mov edx,[esi+4]
0x60c002: push 24h
0x60c004: sub esp,1Ch
0x60c007: mov ecx,esp
0x60c009: mov [esp+38h],esp
0x60c00d: push 7F5850h
0x60c012: mov [edx+90h],ebx
0x60c018: call dword ptr ds:[77CD7Ch]
0x60c01e: push edi
0x60c01f: call 0060EAB0h
0x60c024: mov ecx,[esi+4]
0x60c027: test ecx,ecx
0x60c029: je short 0060C038h
0x60c02b: mov eax,[esi+8]
0x60c02e: sub eax,ecx
0x60c030: sar eax,2
0x60c033: cmp eax,25h
0x60c036: ja short 0060C03Ah
0x60c038: call ebp
0x60c03a: mov eax,[esi+4]
0x60c03d: push 25h
0x60c03f: sub esp,1Ch
0x60c042: mov ecx,esp
0x60c044: mov [esp+38h],esp
0x60c048: push 7F5860h
0x60c04d: mov dword ptr [eax+94h],808080h
0x60c057: call dword ptr ds:[77CD7Ch]
0x60c05d: push edi
0x60c05e: call 0060EAB0h
0x60c063: mov ecx,[esi+4]
0x60c066: test ecx,ecx
0x60c068: je short 0060C077h
0x60c06a: mov eax,[esi+8]
0x60c06d: sub eax,ecx
0x60c06f: sar eax,2
0x60c072: cmp eax,26h
0x60c075: ja short 0060C079h
0x60c077: call ebp
0x60c079: mov ecx,[esi+4]
0x60c07c: push 26h
0x60c07e: sub esp,1Ch
0x60c081: mov dword ptr [ecx+98h],0FFFFFFh
0x60c08b: mov ecx,esp
0x60c08d: mov [esp+38h],esp
0x60c091: push 7F586Ch
0x60c096: call dword ptr ds:[77CD7Ch]
0x60c09c: push edi
0x60c09d: call 0060EAB0h
0x60c0a2: mov ecx,[esi+4]
0x60c0a5: test ecx,ecx
0x60c0a7: je short 0060C0B6h
0x60c0a9: mov eax,[esi+8]
0x60c0ac: sub eax,ecx
0x60c0ae: sar eax,2
0x60c0b1: cmp eax,27h
0x60c0b4: ja short 0060C0B8h
0x60c0b6: call ebp
0x60c0b8: mov edx,[esi+4]
0x60c0bb: push 27h
0x60c0bd: sub esp,1Ch
0x60c0c0: mov ecx,esp
0x60c0c2: mov [esp+38h],esp
0x60c0c6: push 7F5874h
0x60c0cb: mov dword ptr [edx+9Ch],9C9E0h
0x60c0d5: call dword ptr ds:[77CD7Ch]
0x60c0db: push edi
0x60c0dc: call 0060EAB0h
0x60c0e1: mov ecx,[esi+4]
0x60c0e4: test ecx,ecx
0x60c0e6: je short 0060C0F5h
0x60c0e8: mov eax,[esi+8]
0x60c0eb: sub eax,ecx
0x60c0ed: sar eax,2
0x60c0f0: cmp eax,28h
0x60c0f3: ja short 0060C0F7h
0x60c0f5: call ebp
0x60c0f7: mov eax,[esi+4]
0x60c0fa: push 28h
0x60c0fc: sub esp,1Ch
0x60c0ff: mov ecx,esp
0x60c101: mov [esp+38h],esp
0x60c105: mov ebp,0E009C9h
0x60c10a: push 7F587Ch
0x60c10f: mov [eax+0A0h],ebp
0x60c115: call dword ptr ds:[77CD7Ch]
0x60c11b: push edi
0x60c11c: call 0060EAB0h
0x60c121: mov ecx,[esi+4]
0x60c124: test ecx,ecx
0x60c126: je short 0060C135h
0x60c128: mov eax,[esi+8]
0x60c12b: sub eax,ecx
0x60c12d: sar eax,2
0x60c130: cmp eax,29h
0x60c133: ja short 0060C13Bh
0x60c135: call dword ptr ds:[77D0E4h]
0x60c13b: mov ecx,[esi+4]
0x60c13e: push 29h
0x60c140: sub esp,1Ch
0x60c143: mov ebx,2DB60Dh
0x60c148: mov [ecx+0A4h],ebx
0x60c14e: mov ecx,esp
0x60c150: mov [esp+38h],esp
0x60c154: push 7F5884h
0x60c159: call dword ptr ds:[77CD7Ch]
0x60c15f: push edi
0x60c160: call 0060EAB0h
0x60c165: mov ecx,[esi+4]
0x60c168: test ecx,ecx
0x60c16a: je short 0060C179h
0x60c16c: mov eax,[esi+8]
0x60c16f: sub eax,ecx
0x60c171: sar eax,2
0x60c174: cmp eax,2Ah
0x60c177: ja short 0060C17Fh
0x60c179: call dword ptr ds:[77D0E4h]
0x60c17f: mov edx,[esi+4]
0x60c182: push 2Ah
0x60c184: sub esp,1Ch
0x60c187: mov ecx,esp
0x60c189: mov [esp+38h],esp
0x60c18d: push 7F588Ch
0x60c192: mov dword ptr [edx+0A8h],0FFFFh
0x60c19c: call dword ptr ds:[77CD7Ch]
0x60c1a2: push edi
0x60c1a3: call 0060EAB0h
0x60c1a8: mov ecx,[esi+4]
0x60c1ab: test ecx,ecx
0x60c1ad: je short 0060C1BCh
0x60c1af: mov eax,[esi+8]
0x60c1b2: sub eax,ecx
0x60c1b4: sar eax,2
0x60c1b7: cmp eax,2Bh
0x60c1ba: ja short 0060C1C2h
0x60c1bc: call dword ptr ds:[77D0E4h]
0x60c1c2: mov eax,[esi+4]
0x60c1c5: push 2Bh
0x60c1c7: sub esp,1Ch
0x60c1ca: mov ecx,esp
0x60c1cc: mov [esp+38h],esp
0x60c1d0: push 7F5894h
0x60c1d5: mov dword ptr [eax+0ACh],0FFFF00h
0x60c1df: call dword ptr ds:[77CD7Ch]
0x60c1e5: push edi
0x60c1e6: call 0060EAB0h
0x60c1eb: mov ecx,[esi+4]
0x60c1ee: test ecx,ecx
0x60c1f0: je short 0060C1FFh
0x60c1f2: mov eax,[esi+8]
0x60c1f5: sub eax,ecx
0x60c1f7: sar eax,2
0x60c1fa: cmp eax,2Ch
0x60c1fd: ja short 0060C205h
0x60c1ff: call dword ptr ds:[77D0E4h]
0x60c205: mov ecx,[esi+4]
0x60c208: push 2Ch
0x60c20a: sub esp,1Ch
0x60c20d: mov dword ptr [ecx+0B0h],0FFFFh
0x60c217: mov ecx,esp
0x60c219: mov [esp+38h],esp
0x60c21d: push 7F589Ch
0x60c222: call dword ptr ds:[77CD7Ch]
0x60c228: push edi
0x60c229: call 0060EAB0h
0x60c22e: mov ecx,[esi+4]
0x60c231: test ecx,ecx
0x60c233: je short 0060C242h
0x60c235: mov eax,[esi+8]
0x60c238: sub eax,ecx
0x60c23a: sar eax,2
0x60c23d: cmp eax,2Dh
0x60c240: ja short 0060C248h
0x60c242: call dword ptr ds:[77D0E4h]
0x60c248: mov edx,[esi+4]
0x60c24b: push 2Dh
0x60c24d: sub esp,1Ch
0x60c250: mov ecx,esp
0x60c252: mov [esp+38h],esp
0x60c256: push 7F58A4h
0x60c25b: mov dword ptr [edx+0B4h],0FFFFh
0x60c265: call dword ptr ds:[77CD7Ch]
0x60c26b: push edi
0x60c26c: call 0060EAB0h
0x60c271: mov ecx,[esi+4]
0x60c274: test ecx,ecx
0x60c276: je short 0060C285h
0x60c278: mov eax,[esi+8]
0x60c27b: sub eax,ecx
0x60c27d: sar eax,2
0x60c280: cmp eax,2Eh
0x60c283: ja short 0060C28Bh
0x60c285: call dword ptr ds:[77D0E4h]
0x60c28b: mov eax,[esi+4]
0x60c28e: push 2Eh
0x60c290: sub esp,1Ch
0x60c293: mov ecx,esp
0x60c295: mov [esp+38h],esp
0x60c299: push 7F58ACh
0x60c29e: mov dword ptr [eax+0B8h],0FFFFh
0x60c2a8: call dword ptr ds:[77CD7Ch]
0x60c2ae: push edi
0x60c2af: call 0060EAB0h
0x60c2b4: mov ecx,[esi+4]
0x60c2b7: test ecx,ecx
0x60c2b9: je short 0060C2C8h
0x60c2bb: mov eax,[esi+8]
0x60c2be: sub eax,ecx
0x60c2c0: sar eax,2
0x60c2c3: cmp eax,2Fh
0x60c2c6: ja short 0060C2CEh
0x60c2c8: call dword ptr ds:[77D0E4h]
0x60c2ce: mov ecx,[esi+4]
0x60c2d1: push 2Fh
0x60c2d3: sub esp,1Ch
0x60c2d6: mov dword ptr [ecx+0BCh],0FFFFh
0x60c2e0: mov ecx,esp
0x60c2e2: mov [esp+38h],esp
0x60c2e6: push 7F58B4h
0x60c2eb: call dword ptr ds:[77CD7Ch]
0x60c2f1: push edi
0x60c2f2: call 0060EAB0h
0x60c2f7: mov ecx,[esi+4]
0x60c2fa: test ecx,ecx
0x60c2fc: je short 0060C30Bh
0x60c2fe: mov eax,[esi+8]
0x60c301: sub eax,ecx
0x60c303: sar eax,2
0x60c306: cmp eax,30h
0x60c309: ja short 0060C311h
0x60c30b: call dword ptr ds:[77D0E4h]
0x60c311: mov edx,[esi+4]
0x60c314: push 30h
0x60c316: sub esp,1Ch
0x60c319: mov ecx,esp
0x60c31b: mov [esp+38h],esp
0x60c31f: push 7F58BCh
0x60c324: mov dword ptr [edx+0C0h],0FFFFFFh
0x60c32e: call dword ptr ds:[77CD7Ch]
0x60c334: push edi
0x60c335: call 0060EAB0h
0x60c33a: mov ecx,[esi+4]
0x60c33d: test ecx,ecx
0x60c33f: je short 0060C34Eh
0x60c341: mov eax,[esi+8]
0x60c344: sub eax,ecx
0x60c346: sar eax,2
0x60c349: cmp eax,31h
0x60c34c: ja short 0060C354h
0x60c34e: call dword ptr ds:[77D0E4h]
0x60c354: mov eax,[esi+4]
0x60c357: push 31h
0x60c359: sub esp,1Ch
0x60c35c: mov ecx,esp
0x60c35e: mov [esp+38h],esp
0x60c362: push 7F58C4h
0x60c367: mov dword ptr [eax+0C4h],0FFFFh
0x60c371: call dword ptr ds:[77CD7Ch]
0x60c377: push edi
0x60c378: call 0060EAB0h
0x60c37d: mov ecx,[esi+4]
0x60c380: test ecx,ecx
0x60c382: je short 0060C391h
0x60c384: mov eax,[esi+8]
0x60c387: sub eax,ecx
0x60c389: sar eax,2
0x60c38c: cmp eax,32h
0x60c38f: ja short 0060C397h
0x60c391: call dword ptr ds:[77D0E4h]
0x60c397: mov ecx,[esi+4]
0x60c39a: push 32h
0x60c39c: sub esp,1Ch
0x60c39f: mov dword ptr [ecx+0C8h],0FFFFh
0x60c3a9: mov ecx,esp
0x60c3ab: mov [esp+38h],esp
0x60c3af: push 7F58CCh
0x60c3b4: call dword ptr ds:[77CD7Ch]
0x60c3ba: push edi
0x60c3bb: call 0060EAB0h
0x60c3c0: mov ecx,[esi+4]
0x60c3c3: test ecx,ecx
0x60c3c5: je short 0060C3D4h
0x60c3c7: mov eax,[esi+8]
0x60c3ca: sub eax,ecx
0x60c3cc: sar eax,2
0x60c3cf: cmp eax,33h
0x60c3d2: ja short 0060C3DAh
0x60c3d4: call dword ptr ds:[77D0E4h]
0x60c3da: mov edx,[esi+4]
0x60c3dd: push 33h
0x60c3df: sub esp,1Ch
0x60c3e2: mov ecx,esp
0x60c3e4: mov [esp+38h],esp
0x60c3e8: push 7F58D4h
0x60c3ed: mov dword ptr [edx+0CCh],0FFFFh
0x60c3f7: call dword ptr ds:[77CD7Ch]
0x60c3fd: push edi
0x60c3fe: call 0060EAB0h
0x60c403: mov ecx,[esi+4]
0x60c406: test ecx,ecx
0x60c408: je short 0060C417h
0x60c40a: mov eax,[esi+8]
0x60c40d: sub eax,ecx
0x60c40f: sar eax,2
0x60c412: cmp eax,34h
0x60c415: ja short 0060C41Dh
0x60c417: call dword ptr ds:[77D0E4h]
0x60c41d: mov eax,[esi+4]
0x60c420: push 34h
0x60c422: sub esp,1Ch
0x60c425: mov ecx,esp
0x60c427: mov [esp+38h],esp
0x60c42b: push 7F58DCh
0x60c430: mov dword ptr [eax+0D0h],0FFFFh
0x60c43a: call dword ptr ds:[77CD7Ch]
0x60c440: push edi
0x60c441: call 0060EAB0h
0x60c446: mov ecx,[esi+4]
0x60c449: test ecx,ecx
0x60c44b: je short 0060C45Ah
0x60c44d: mov eax,[esi+8]
0x60c450: sub eax,ecx
0x60c452: sar eax,2
0x60c455: cmp eax,35h
0x60c458: ja short 0060C460h
0x60c45a: call dword ptr ds:[77D0E4h]
0x60c460: mov ecx,[esi+4]
0x60c463: push 35h
0x60c465: sub esp,1Ch
0x60c468: mov dword ptr [ecx+0D4h],0FFFFFFh
0x60c472: mov ecx,esp
0x60c474: mov [esp+38h],esp
0x60c478: push 7F58E4h
0x60c47d: call dword ptr ds:[77CD7Ch]
0x60c483: push edi
0x60c484: call 0060EAB0h
0x60c489: mov ecx,[esi+4]
0x60c48c: test ecx,ecx
0x60c48e: je short 0060C49Dh
0x60c490: mov eax,[esi+8]
0x60c493: sub eax,ecx
0x60c495: sar eax,2
0x60c498: cmp eax,36h
0x60c49b: ja short 0060C4A3h
0x60c49d: call dword ptr ds:[77D0E4h]
0x60c4a3: mov edx,[esi+4]
0x60c4a6: push 36h
0x60c4a8: sub esp,1Ch
0x60c4ab: mov ecx,esp
0x60c4ad: mov [esp+38h],esp
0x60c4b1: push 7F58ECh
0x60c4b6: mov dword ptr [edx+0D8h],0FFFFh
0x60c4c0: call dword ptr ds:[77CD7Ch]
0x60c4c6: push edi
0x60c4c7: call 0060EAB0h
0x60c4cc: mov ecx,[esi+4]
0x60c4cf: test ecx,ecx
0x60c4d1: je short 0060C4E0h
0x60c4d3: mov eax,[esi+8]
0x60c4d6: sub eax,ecx
0x60c4d8: sar eax,2
0x60c4db: cmp eax,37h
0x60c4de: ja short 0060C4E6h
0x60c4e0: call dword ptr ds:[77D0E4h]
0x60c4e6: mov eax,[esi+4]
0x60c4e9: push 37h
0x60c4eb: sub esp,1Ch
0x60c4ee: mov ecx,esp
0x60c4f0: mov [esp+38h],esp
0x60c4f4: push 7F58F4h
0x60c4f9: mov dword ptr [eax+0DCh],0FFFFh
0x60c503: call dword ptr ds:[77CD7Ch]
0x60c509: push edi
0x60c50a: call 0060EAB0h
0x60c50f: mov ecx,[esi+4]
0x60c512: test ecx,ecx
0x60c514: je short 0060C523h
0x60c516: mov eax,[esi+8]
0x60c519: sub eax,ecx
0x60c51b: sar eax,2
0x60c51e: cmp eax,38h
0x60c521: ja short 0060C529h
0x60c523: call dword ptr ds:[77D0E4h]
0x60c529: mov ecx,[esi+4]
0x60c52c: push 38h
0x60c52e: sub esp,1Ch
0x60c531: mov dword ptr [ecx+0E0h],0FFFFh
0x60c53b: mov ecx,esp
0x60c53d: mov [esp+38h],esp
0x60c541: push 7F58FCh
0x60c546: call dword ptr ds:[77CD7Ch]
0x60c54c: push edi
0x60c54d: call 0060EAB0h
0x60c552: mov ecx,[esi+4]
0x60c555: test ecx,ecx
0x60c557: je short 0060C566h
0x60c559: mov eax,[esi+8]
0x60c55c: sub eax,ecx
0x60c55e: sar eax,2
0x60c561: cmp eax,39h
0x60c564: ja short 0060C56Ch
0x60c566: call dword ptr ds:[77D0E4h]
0x60c56c: mov edx,[esi+4]
0x60c56f: push 39h
0x60c571: sub esp,1Ch
0x60c574: mov ecx,esp
0x60c576: mov [esp+38h],esp
0x60c57a: push 7F5904h
0x60c57f: mov dword ptr [edx+0E4h],0FFFFh
0x60c589: call dword ptr ds:[77CD7Ch]
0x60c58f: push edi
0x60c590: call 0060EAB0h
0x60c595: mov ecx,[esi+4]
0x60c598: test ecx,ecx
0x60c59a: je short 0060C5A9h
0x60c59c: mov eax,[esi+8]
0x60c59f: sub eax,ecx
0x60c5a1: sar eax,2
0x60c5a4: cmp eax,3Ah
0x60c5a7: ja short 0060C5AFh
0x60c5a9: call dword ptr ds:[77D0E4h]
0x60c5af: mov eax,[esi+4]
0x60c5b2: push 3Ah
0x60c5b4: sub esp,1Ch
0x60c5b7: mov ecx,esp
0x60c5b9: mov [esp+38h],esp
0x60c5bd: push 7F590Ch
0x60c5c2: mov dword ptr [eax+0E8h],0F4E202h
0x60c5cc: call dword ptr ds:[77CD7Ch]
0x60c5d2: push edi
0x60c5d3: call 0060EAB0h
0x60c5d8: mov ecx,[esi+4]
0x60c5db: test ecx,ecx
0x60c5dd: je short 0060C5ECh
0x60c5df: mov eax,[esi+8]
0x60c5e2: sub eax,ecx
0x60c5e4: sar eax,2
0x60c5e7: cmp eax,3Bh
0x60c5ea: ja short 0060C5F2h
0x60c5ec: call dword ptr ds:[77D0E4h]
0x60c5f2: mov ecx,[esi+4]
0x60c5f5: push 3Bh
0x60c5f7: sub esp,1Ch
0x60c5fa: mov dword ptr [ecx+0ECh],808080h
0x60c604: mov ecx,esp
0x60c606: mov [esp+38h],esp
0x60c60a: push 7F5920h
0x60c60f: call dword ptr ds:[77CD7Ch]
0x60c615: push edi
0x60c616: call 0060EAB0h
0x60c61b: mov ecx,[esi+4]
0x60c61e: test ecx,ecx
0x60c620: je short 0060C62Fh
0x60c622: mov eax,[esi+8]
0x60c625: sub eax,ecx
0x60c627: sar eax,2
0x60c62a: cmp eax,3Ch
0x60c62d: ja short 0060C635h
0x60c62f: call dword ptr ds:[77D0E4h]
0x60c635: mov edx,[esi+4]
0x60c638: push 3Ch
0x60c63a: sub esp,1Ch
0x60c63d: mov ecx,esp
0x60c63f: mov [esp+38h],esp
0x60c643: push 7F5934h
0x60c648: mov [edx+0F0h],ebp
0x60c64e: call dword ptr ds:[77CD7Ch]
0x60c654: push edi
0x60c655: call 0060EAB0h
0x60c65a: mov ecx,[esi+4]
0x60c65d: test ecx,ecx
0x60c65f: je short 0060C66Eh
0x60c661: mov eax,[esi+8]
0x60c664: sub eax,ecx
0x60c666: sar eax,2
0x60c669: cmp eax,3Dh
0x60c66c: ja short 0060C674h
0x60c66e: call dword ptr ds:[77D0E4h]
0x60c674: mov eax,[esi+4]
0x60c677: push 3Dh
0x60c679: sub esp,1Ch
0x60c67c: mov ecx,esp
0x60c67e: mov [esp+38h],esp
0x60c682: push 7F5948h
0x60c687: mov [eax+0F4h],ebx
0x60c68d: call dword ptr ds:[77CD7Ch]
0x60c693: push edi
0x60c694: call 0060EAB0h
0x60c699: mov ecx,[esi+4]
0x60c69c: test ecx,ecx
0x60c69e: je short 0060C6ADh
0x60c6a0: mov eax,[esi+8]
0x60c6a3: sub eax,ecx
0x60c6a5: sar eax,2
0x60c6a8: cmp eax,3Eh
0x60c6ab: ja short 0060C6B3h
0x60c6ad: call dword ptr ds:[77D0E4h]
0x60c6b3: mov ecx,[esi+4]
0x60c6b6: push 3Eh
0x60c6b8: sub esp,1Ch
0x60c6bb: mov ebx,0FFFFh
0x60c6c0: mov [ecx+0F8h],ebx
0x60c6c6: mov ecx,esp
0x60c6c8: mov [esp+38h],esp
0x60c6cc: push 7F595Ch
0x60c6d1: call dword ptr ds:[77CD7Ch]
0x60c6d7: push edi
0x60c6d8: call 0060EAB0h
0x60c6dd: mov ecx,[esi+4]
0x60c6e0: test ecx,ecx
0x60c6e2: je short 0060C6F1h
0x60c6e4: mov eax,[esi+8]
0x60c6e7: sub eax,ecx
0x60c6e9: sar eax,2
0x60c6ec: cmp eax,3Fh
0x60c6ef: ja short 0060C6F7h
0x60c6f1: call dword ptr ds:[77D0E4h]
0x60c6f7: mov edx,[esi+4]
0x60c6fa: push 3Fh
0x60c6fc: sub esp,1Ch
0x60c6ff: mov ecx,esp
0x60c701: mov [esp+38h],esp
0x60c705: mov ebp,0FFFFFFh
0x60c70a: push 7F5970h
0x60c70f: mov [edx+0FCh],ebp
0x60c715: call dword ptr ds:[77CD7Ch]
0x60c71b: push edi
0x60c71c: call 0060EAB0h
0x60c721: mov ecx,[esi+4]
0x60c724: test ecx,ecx
0x60c726: je short 0060C735h
0x60c728: mov eax,[esi+8]
0x60c72b: sub eax,ecx
0x60c72d: sar eax,2
0x60c730: cmp eax,40h
0x60c733: ja short 0060C73Bh
0x60c735: call dword ptr ds:[77D0E4h]
0x60c73b: mov eax,[esi+4]
0x60c73e: push 40h
0x60c740: sub esp,1Ch
0x60c743: mov ecx,esp
0x60c745: mov [esp+38h],esp
0x60c749: push 7F597Ch
0x60c74e: mov [eax+100h],ebp
0x60c754: call dword ptr ds:[77CD7Ch]
0x60c75a: push edi
0x60c75b: call 0060EAB0h
0x60c760: mov ecx,[esi+4]
0x60c763: test ecx,ecx
0x60c765: je short 0060C774h
0x60c767: mov eax,[esi+8]
0x60c76a: sub eax,ecx
0x60c76c: sar eax,2
0x60c76f: cmp eax,41h
0x60c772: ja short 0060C77Ah
0x60c774: call dword ptr ds:[77D0E4h]
0x60c77a: mov ecx,[esi+4]
0x60c77d: push 41h
0x60c77f: sub esp,1Ch
0x60c782: mov dword ptr [ecx+104h],303030h
0x60c78c: mov ecx,esp
0x60c78e: mov [esp+38h],esp
0x60c792: push 7F5988h
0x60c797: call dword ptr ds:[77CD7Ch]
0x60c79d: push edi
0x60c79e: call 0060EAB0h
0x60c7a3: mov ecx,[esi+4]
0x60c7a6: test ecx,ecx
0x60c7a8: je short 0060C7B7h
0x60c7aa: mov eax,[esi+8]
0x60c7ad: sub eax,ecx
0x60c7af: sar eax,2
0x60c7b2: cmp eax,42h
0x60c7b5: ja short 0060C7BDh
0x60c7b7: call dword ptr ds:[77D0E4h]
0x60c7bd: mov edx,[esi+4]
0x60c7c0: push 42h
0x60c7c2: sub esp,1Ch
0x60c7c5: mov ecx,esp
0x60c7c7: mov [esp+38h],esp
0x60c7cb: push 7F599Ch
0x60c7d0: mov dword ptr [edx+108h],808000h
0x60c7da: call dword ptr ds:[77CD7Ch]
0x60c7e0: push edi
0x60c7e1: call 0060EAB0h
0x60c7e6: mov ecx,[esi+4]
0x60c7e9: test ecx,ecx
0x60c7eb: je short 0060C7FAh
0x60c7ed: mov eax,[esi+8]
0x60c7f0: sub eax,ecx
0x60c7f2: sar eax,2
0x60c7f5: cmp eax,43h
0x60c7f8: ja short 0060C800h
0x60c7fa: call dword ptr ds:[77D0E4h]
0x60c800: mov eax,[esi+4]
0x60c803: push 43h
0x60c805: sub esp,1Ch
0x60c808: mov ecx,esp
0x60c80a: mov [esp+38h],esp
0x60c80e: push 7F59A8h
0x60c813: mov [eax+10Ch],ebx
0x60c819: call dword ptr ds:[77CD7Ch]
0x60c81f: push edi
0x60c820: call 0060EAB0h
0x60c825: mov ecx,[esi+4]
0x60c828: test ecx,ecx
0x60c82a: je short 0060C839h
0x60c82c: mov eax,[esi+8]
0x60c82f: sub eax,ecx
0x60c831: sar eax,2
0x60c834: cmp eax,44h
0x60c837: ja short 0060C83Fh
0x60c839: call dword ptr ds:[77D0E4h]
0x60c83f: mov ecx,[esi+4]
0x60c842: push 44h
0x60c844: sub esp,1Ch
0x60c847: mov [ecx+110h],ebx
0x60c84d: mov ecx,esp
0x60c84f: mov [esp+38h],esp
0x60c853: push 7F59B4h
0x60c858: call dword ptr ds:[77CD7Ch]
0x60c85e: push edi
0x60c85f: call 0060EAB0h
0x60c864: mov ecx,[esi+4]
0x60c867: test ecx,ecx
0x60c869: je short 0060C878h
0x60c86b: mov eax,[esi+8]
0x60c86e: sub eax,ecx
0x60c870: sar eax,2
0x60c873: cmp eax,45h
0x60c876: ja short 0060C87Eh
0x60c878: call dword ptr ds:[77D0E4h]
0x60c87e: mov edx,[esi+4]
0x60c881: push 45h
0x60c883: sub esp,1Ch
0x60c886: mov ecx,esp
0x60c888: mov [esp+38h],esp
0x60c88c: push 7F59C4h
0x60c891: mov dword ptr [edx+114h],0FF0000h
0x60c89b: call dword ptr ds:[77CD7Ch]
0x60c8a1: push edi
0x60c8a2: call 0060EAB0h
0x60c8a7: mov ecx,[esi+4]
0x60c8aa: test ecx,ecx
0x60c8ac: je short 0060C8BBh
0x60c8ae: mov eax,[esi+8]
0x60c8b1: sub eax,ecx
0x60c8b3: sar eax,2
0x60c8b6: cmp eax,46h
0x60c8b9: ja short 0060C8C1h
0x60c8bb: call dword ptr ds:[77D0E4h]
0x60c8c1: mov eax,[esi+4]
0x60c8c4: push 46h
0x60c8c6: sub esp,1Ch
0x60c8c9: mov ecx,esp
0x60c8cb: mov [esp+38h],esp
0x60c8cf: push 7F59D4h
0x60c8d4: mov dword ptr [eax+118h],0C0C0C0h
0x60c8de: call dword ptr ds:[77CD7Ch]
0x60c8e4: push edi
0x60c8e5: call 0060EAB0h
0x60c8ea: mov ecx,[esi+4]
0x60c8ed: test ecx,ecx
0x60c8ef: je short 0060C8FEh
0x60c8f1: mov eax,[esi+8]
0x60c8f4: sub eax,ecx
0x60c8f6: sar eax,2
0x60c8f9: cmp eax,47h
0x60c8fc: ja short 0060C904h
0x60c8fe: call dword ptr ds:[77D0E4h]
0x60c904: mov ecx,[esi+4]
0x60c907: push 47h
0x60c909: sub esp,1Ch
0x60c90c: mov [ecx+11Ch],ebx
0x60c912: mov ecx,esp
0x60c914: mov [esp+38h],esp
0x60c918: push 7F59E4h
0x60c91d: call dword ptr ds:[77CD7Ch]
0x60c923: push edi
0x60c924: call 0060EAB0h
0x60c929: mov ecx,[esi+4]
0x60c92c: test ecx,ecx
0x60c92e: je short 0060C93Dh
0x60c930: mov eax,[esi+8]
0x60c933: sub eax,ecx
0x60c935: sar eax,2
0x60c938: cmp eax,48h
0x60c93b: ja short 0060C947h
0x60c93d: mov ebx,ds:[77D0E4h]
0x60c943: call ebx
0x60c945: jmp short 0060C94Dh
0x60c947: mov ebx,ds:[77D0E4h]
0x60c94d: mov edx,[esi+4]
0x60c950: push 48h
0x60c952: sub esp,1Ch
0x60c955: mov ecx,esp
0x60c957: mov [esp+38h],esp
0x60c95b: push 7F59F8h
0x60c960: mov [edx+120h],ebp
0x60c966: call dword ptr ds:[77CD7Ch]
0x60c96c: push edi
0x60c96d: call 0060EAB0h
0x60c972: mov ecx,[esi+4]
0x60c975: test ecx,ecx
0x60c977: je short 0060C986h
0x60c979: mov eax,[esi+8]
0x60c97c: sub eax,ecx
0x60c97e: sar eax,2
0x60c981: cmp eax,49h
0x60c984: ja short 0060C988h
0x60c986: call ebx
0x60c988: mov eax,[esi+4]
0x60c98b: push 49h
0x60c98d: sub esp,1Ch
0x60c990: mov ecx,esp
0x60c992: mov [esp+38h],esp
0x60c996: push 7F5A0Ch
0x60c99b: mov dword ptr [eax+124h],606060h
0x60c9a5: call dword ptr ds:[77CD7Ch]
0x60c9ab: push edi
0x60c9ac: call 0060EAB0h
0x60c9b1: mov ecx,[esi+4]
0x60c9b4: test ecx,ecx
0x60c9b6: je short 0060C9C5h
0x60c9b8: mov eax,[esi+8]
0x60c9bb: sub eax,ecx
0x60c9bd: sar eax,2
0x60c9c0: cmp eax,4Ah
0x60c9c3: ja short 0060C9C7h
0x60c9c5: call ebx
0x60c9c7: mov ecx,[esi+4]
0x60c9ca: push 4Ah
0x60c9cc: sub esp,1Ch
0x60c9cf: mov dword ptr [ecx+128h],242424h
0x60c9d9: mov ecx,esp
0x60c9db: mov [esp+38h],esp
0x60c9df: push 7F5A24h
0x60c9e4: call dword ptr ds:[77CD7Ch]
0x60c9ea: push edi
0x60c9eb: call 0060EAB0h
0x60c9f0: mov ecx,[esi+4]
0x60c9f3: test ecx,ecx
0x60c9f5: je short 0060CA04h
0x60c9f7: mov eax,[esi+8]
0x60c9fa: sub eax,ecx
0x60c9fc: sar eax,2
0x60c9ff: cmp eax,4Bh
0x60ca02: ja short 0060CA06h
0x60ca04: call ebx
0x60ca06: mov edx,[esi+4]
0x60ca09: push 4Bh
0x60ca0b: sub esp,1Ch
0x60ca0e: mov ecx,esp
0x60ca10: mov [esp+38h],esp
0x60ca14: push 7F5A34h
0x60ca19: mov [edx+12Ch],ebp
0x60ca1f: call dword ptr ds:[77CD7Ch]
0x60ca25: push edi
0x60ca26: call 0060EAB0h
0x60ca2b: mov ecx,[esi+4]
0x60ca2e: test ecx,ecx
0x60ca30: je short 0060CA3Fh
0x60ca32: mov eax,[esi+8]
0x60ca35: sub eax,ecx
0x60ca37: sar eax,2
0x60ca3a: cmp eax,4Ch
0x60ca3d: ja short 0060CA41h
0x60ca3f: call ebx
0x60ca41: mov eax,[esi+4]
0x60ca44: push 4Ch
0x60ca46: sub esp,1Ch
0x60ca49: mov ecx,esp
0x60ca4b: mov [esp+38h],esp
0x60ca4f: push 7F5A44h
0x60ca54: mov [eax+130h],ebp
0x60ca5a: call dword ptr ds:[77CD7Ch]
0x60ca60: push edi
0x60ca61: call 0060EAB0h
0x60ca66: mov ecx,[esi+4]
0x60ca69: test ecx,ecx
0x60ca6b: je short 0060CA7Ah
0x60ca6d: mov eax,[esi+8]
0x60ca70: sub eax,ecx
0x60ca72: sar eax,2
0x60ca75: cmp eax,4Dh
0x60ca78: ja short 0060CA7Ch
0x60ca7a: call ebx
0x60ca7c: mov ecx,[esi+4]
0x60ca7f: push 4Dh
0x60ca81: sub esp,1Ch
0x60ca84: mov [ecx+134h],ebp
0x60ca8a: mov ecx,esp
0x60ca8c: mov [esp+38h],esp
0x60ca90: push 7F5A58h
0x60ca95: call dword ptr ds:[77CD7Ch]
0x60ca9b: push edi
0x60ca9c: call 0060EAB0h
0x60caa1: mov ecx,[esi+4]
0x60caa4: test ecx,ecx
0x60caa6: je short 0060CAB5h
0x60caa8: mov eax,[esi+8]
0x60caab: sub eax,ecx
0x60caad: sar eax,2
0x60cab0: cmp eax,4Eh
0x60cab3: ja short 0060CAB7h
0x60cab5: call ebx
0x60cab7: mov edx,[esi+4]
0x60caba: push 4Eh
0x60cabc: sub esp,1Ch
0x60cabf: mov ecx,esp
0x60cac1: mov [esp+38h],esp
0x60cac5: push 7F5A6Ch
0x60caca: mov dword ptr [edx+138h],0C8C8C8h
0x60cad4: call dword ptr ds:[77CD7Ch]
0x60cada: push edi
0x60cadb: call 0060EAB0h
0x60cae0: mov ecx,[esi+4]
0x60cae3: test ecx,ecx
0x60cae5: je short 0060CAF4h
0x60cae7: mov eax,[esi+8]
0x60caea: sub eax,ecx
0x60caec: sar eax,2
0x60caef: cmp eax,4Fh
0x60caf2: ja short 0060CAF6h
0x60caf4: call ebx
0x60caf6: mov eax,[esi+4]
0x60caf9: push 4Fh
0x60cafb: sub esp,1Ch
0x60cafe: mov ecx,esp
0x60cb00: mov [esp+38h],esp
0x60cb04: push 7F5A7Ch
0x60cb09: mov dword ptr [eax+13Ch],0E8E8E8h
0x60cb13: call dword ptr ds:[77CD7Ch]
0x60cb19: push edi
0x60cb1a: call 0060EAB0h
0x60cb1f: mov ecx,[esi+4]
0x60cb22: test ecx,ecx
0x60cb24: je short 0060CB33h
0x60cb26: mov eax,[esi+8]
0x60cb29: sub eax,ecx
0x60cb2b: sar eax,2
0x60cb2e: cmp eax,50h
0x60cb31: ja short 0060CB35h
0x60cb33: call ebx
0x60cb35: mov ecx,[esi+4]
0x60cb38: push 50h
0x60cb3a: sub esp,1Ch
0x60cb3d: mov ebp,808080h
0x60cb42: mov [ecx+140h],ebp
0x60cb48: mov ecx,esp
0x60cb4a: mov [esp+38h],esp
0x60cb4e: push 7F5A94h
0x60cb53: call dword ptr ds:[77CD7Ch]
0x60cb59: push edi
0x60cb5a: call 0060EAB0h
0x60cb5f: mov ecx,[esi+4]
0x60cb62: test ecx,ecx
0x60cb64: je short 0060CB73h
0x60cb66: mov eax,[esi+8]
0x60cb69: sub eax,ecx
0x60cb6b: sar eax,2
0x60cb6e: cmp eax,51h
0x60cb71: ja short 0060CB7Dh
0x60cb73: mov ebx,ds:[77D0E4h]
0x60cb79: call ebx
0x60cb7b: jmp short 0060CB83h
0x60cb7d: mov ebx,ds:[77D0E4h]
0x60cb83: mov edx,[esi+4]
0x60cb86: push 51h
0x60cb88: sub esp,1Ch
0x60cb8b: mov ecx,esp
0x60cb8d: mov [esp+38h],esp
0x60cb91: push 7F5AACh
0x60cb96: mov dword ptr [edx+144h],0
0x60cba0: call dword ptr ds:[77CD7Ch]
0x60cba6: push edi
0x60cba7: call 0060EAB0h
0x60cbac: mov ecx,[esi+4]
0x60cbaf: test ecx,ecx
0x60cbb1: je short 0060CBC0h
0x60cbb3: mov eax,[esi+8]
0x60cbb6: sub eax,ecx
0x60cbb8: sar eax,2
0x60cbbb: cmp eax,52h
0x60cbbe: ja short 0060CBC2h
0x60cbc0: call ebx
0x60cbc2: mov eax,[esi+4]
0x60cbc5: push 52h
0x60cbc7: sub esp,1Ch
0x60cbca: mov ecx,esp
0x60cbcc: mov [esp+38h],esp
0x60cbd0: push 7F5AC0h
0x60cbd5: mov dword ptr [eax+148h],0E0E0E0h
0x60cbdf: call dword ptr ds:[77CD7Ch]
0x60cbe5: push edi
0x60cbe6: call 0060EAB0h
0x60cbeb: mov ecx,[esi+4]
0x60cbee: test ecx,ecx
0x60cbf0: je short 0060CBFFh
0x60cbf2: mov eax,[esi+8]
0x60cbf5: sub eax,ecx
0x60cbf7: sar eax,2
0x60cbfa: cmp eax,53h
0x60cbfd: ja short 0060CC01h
0x60cbff: call ebx
0x60cc01: mov ecx,[esi+4]
0x60cc04: push 53h
0x60cc06: sub esp,1Ch
0x60cc09: mov dword ptr [ecx+14Ch],0FFFFFFh
0x60cc13: mov ecx,esp
0x60cc15: mov [esp+38h],esp
0x60cc19: push 7F5ACCh
0x60cc1e: call dword ptr ds:[77CD7Ch]
0x60cc24: push edi
0x60cc25: call 0060EAB0h
0x60cc2a: mov ecx,[esi+4]
0x60cc2d: test ecx,ecx
0x60cc2f: je short 0060CC3Eh
0x60cc31: mov eax,[esi+8]
0x60cc34: sub eax,ecx
0x60cc36: sar eax,2
0x60cc39: cmp eax,54h
0x60cc3c: ja short 0060CC40h
0x60cc3e: call ebx
0x60cc40: mov edx,[esi+4]
0x60cc43: push 54h
0x60cc45: sub esp,1Ch
0x60cc48: mov ecx,esp
0x60cc4a: mov [esp+38h],esp
0x60cc4e: push 7F5AE0h
0x60cc53: mov dword ptr [edx+150h],707070h
0x60cc5d: call dword ptr ds:[77CD7Ch]
0x60cc63: push edi
0x60cc64: call 0060EAB0h
0x60cc69: mov ecx,[esi+4]
0x60cc6c: test ecx,ecx
0x60cc6e: je short 0060CC7Dh
0x60cc70: mov eax,[esi+8]
0x60cc73: sub eax,ecx
0x60cc75: sar eax,2
0x60cc78: cmp eax,55h
0x60cc7b: ja short 0060CC7Fh
0x60cc7d: call ebx
0x60cc7f: mov eax,[esi+4]
0x60cc82: push 55h
0x60cc84: sub esp,1Ch
0x60cc87: mov ecx,esp
0x60cc89: mov [esp+38h],esp
0x60cc8d: push 7F5AF4h
0x60cc92: mov [eax+154h],ebp
0x60cc98: call dword ptr ds:[77CD7Ch]
0x60cc9e: push edi
0x60cc9f: call 0060EAB0h
0x60cca4: mov ecx,[esi+4]
0x60cca7: test ecx,ecx
0x60cca9: je short 0060CCB8h
0x60ccab: mov eax,[esi+8]
0x60ccae: sub eax,ecx
0x60ccb0: sar eax,2
0x60ccb3: cmp eax,56h
0x60ccb6: ja short 0060CCBAh
0x60ccb8: call ebx
0x60ccba: mov ecx,[esi+4]
0x60ccbd: push 56h
0x60ccbf: sub esp,1Ch
0x60ccc2: mov [ecx+158h],ebp
0x60ccc8: mov ecx,esp
0x60ccca: mov [esp+38h],esp
0x60ccce: push 7F5B04h
0x60ccd3: call dword ptr ds:[77CD7Ch]
0x60ccd9: push edi
0x60ccda: call 0060EAB0h
0x60ccdf: mov ecx,[esi+4]
0x60cce2: test ecx,ecx
0x60cce4: je short 0060CCF3h
0x60cce6: mov eax,[esi+8]
0x60cce9: sub eax,ecx
0x60cceb: sar eax,2
0x60ccee: cmp eax,57h
0x60ccf1: ja short 0060CCF5h
0x60ccf3: call ebx
0x60ccf5: mov edx,[esi+4]
0x60ccf8: push 57h
0x60ccfa: sub esp,1Ch
0x60ccfd: mov ecx,esp
0x60ccff: mov [esp+38h],esp
0x60cd03: push 7F5B18h
0x60cd08: mov [edx+15Ch],ebp
0x60cd0e: call dword ptr ds:[77CD7Ch]
0x60cd14: push edi
0x60cd15: call 0060EAB0h
0x60cd1a: mov ecx,[esi+4]
0x60cd1d: test ecx,ecx
0x60cd1f: je short 0060CD2Eh
0x60cd21: mov eax,[esi+8]
0x60cd24: sub eax,ecx
0x60cd26: sar eax,2
0x60cd29: cmp eax,58h
0x60cd2c: ja short 0060CD30h
0x60cd2e: call ebx
0x60cd30: mov eax,[esi+4]
0x60cd33: push 58h
0x60cd35: sub esp,1Ch
0x60cd38: mov ecx,esp
0x60cd3a: mov [esp+38h],esp
0x60cd3e: push 7F5B30h
0x60cd43: mov [eax+160h],ebp
0x60cd49: call dword ptr ds:[77CD7Ch]
0x60cd4f: push edi
0x60cd50: call 0060EAB0h
0x60cd55: mov ecx,[esi+4]
0x60cd58: test ecx,ecx
0x60cd5a: je short 0060CD69h
0x60cd5c: mov eax,[esi+8]
0x60cd5f: sub eax,ecx
0x60cd61: sar eax,2
0x60cd64: cmp eax,59h
0x60cd67: ja short 0060CD6Bh
0x60cd69: call ebx
0x60cd6b: mov ecx,[esi+4]
0x60cd6e: push 59h
0x60cd70: sub esp,1Ch
0x60cd73: mov [ecx+164h],ebp
0x60cd79: mov ecx,esp
0x60cd7b: mov [esp+38h],esp
0x60cd7f: push 7F5B40h
0x60cd84: call dword ptr ds:[77CD7Ch]
0x60cd8a: push edi
0x60cd8b: call 0060EAB0h
0x60cd90: mov ecx,[esi+4]
0x60cd93: test ecx,ecx
0x60cd95: je short 0060CDA4h
0x60cd97: mov eax,[esi+8]
0x60cd9a: sub eax,ecx
0x60cd9c: sar eax,2
0x60cd9f: cmp eax,5Ah
0x60cda2: ja short 0060CDA6h
0x60cda4: call ebx
0x60cda6: mov edx,[esi+4]
0x60cda9: push 5Ah
0x60cdab: sub esp,1Ch
0x60cdae: mov ecx,esp
0x60cdb0: mov [esp+38h],esp
0x60cdb4: push 7F5B50h
0x60cdb9: mov [edx+168h],ebp
0x60cdbf: call dword ptr ds:[77CD7Ch]
0x60cdc5: push edi
0x60cdc6: call 0060EAB0h
0x60cdcb: mov ecx,[esi+4]
0x60cdce: test ecx,ecx
0x60cdd0: je short 0060CDDFh
0x60cdd2: mov eax,[esi+8]
0x60cdd5: sub eax,ecx
0x60cdd7: sar eax,2
0x60cdda: cmp eax,5Bh
0x60cddd: ja short 0060CDE1h
0x60cddf: call ebx
0x60cde1: mov eax,[esi+4]
0x60cde4: push 5Bh
0x60cde6: sub esp,1Ch
0x60cde9: mov ecx,esp
0x60cdeb: mov [esp+38h],esp
0x60cdef: push 7F5B68h
0x60cdf4: mov [eax+16Ch],ebp
0x60cdfa: call dword ptr ds:[77CD7Ch]
0x60ce00: push edi
0x60ce01: call 0060EAB0h
0x60ce06: mov ecx,[esi+4]
0x60ce09: test ecx,ecx
0x60ce0b: je short 0060CE1Ah
0x60ce0d: mov eax,[esi+8]
0x60ce10: sub eax,ecx
0x60ce12: sar eax,2
0x60ce15: cmp eax,5Ch
0x60ce18: ja short 0060CE1Ch
0x60ce1a: call ebx
0x60ce1c: mov ecx,[esi+4]
0x60ce1f: push 5Ch
0x60ce21: sub esp,1Ch
0x60ce24: mov ebx,404040h
0x60ce29: mov [ecx+170h],ebx
0x60ce2f: mov ecx,esp
0x60ce31: mov [esp+38h],esp
0x60ce35: push 7F5B74h
0x60ce3a: call dword ptr ds:[77CD7Ch]
0x60ce40: push edi
0x60ce41: call 0060EAB0h
0x60ce46: mov ecx,[esi+4]
0x60ce49: test ecx,ecx
0x60ce4b: je short 0060CE5Ah
0x60ce4d: mov eax,[esi+8]
0x60ce50: sub eax,ecx
0x60ce52: sar eax,2
0x60ce55: cmp eax,5Dh
0x60ce58: ja short 0060CE60h
0x60ce5a: call dword ptr ds:[77D0E4h]
0x60ce60: mov edx,[esi+4]
0x60ce63: push 5Dh
0x60ce65: sub esp,1Ch
0x60ce68: mov ecx,esp
0x60ce6a: mov [esp+38h],esp
0x60ce6e: push 7F5B88h
0x60ce73: mov [edx+174h],ebp
0x60ce79: call dword ptr ds:[77CD7Ch]
0x60ce7f: push edi
0x60ce80: call 0060EAB0h
0x60ce85: mov ecx,[esi+4]
0x60ce88: test ecx,ecx
0x60ce8a: je short 0060CE99h
0x60ce8c: mov eax,[esi+8]
0x60ce8f: sub eax,ecx
0x60ce91: sar eax,2
0x60ce94: cmp eax,5Eh
0x60ce97: ja short 0060CE9Fh
0x60ce99: call dword ptr ds:[77D0E4h]
0x60ce9f: mov eax,[esi+4]
0x60cea2: push 5Eh
0x60cea4: sub esp,1Ch
0x60cea7: mov ecx,esp
0x60cea9: mov [esp+38h],esp
0x60cead: push 7F5B98h
0x60ceb2: mov [eax+178h],ebp
0x60ceb8: call dword ptr ds:[77CD7Ch]
0x60cebe: push edi
0x60cebf: call 0060EAB0h
0x60cec4: mov ecx,[esi+4]
0x60cec7: test ecx,ecx
0x60cec9: je short 0060CED8h
0x60cecb: mov eax,[esi+8]
0x60cece: sub eax,ecx
0x60ced0: sar eax,2
0x60ced3: cmp eax,5Fh
0x60ced6: ja short 0060CEDEh
0x60ced8: call dword ptr ds:[77D0E4h]
0x60cede: mov ecx,[esi+4]
0x60cee1: push 5Fh
0x60cee3: sub esp,1Ch
0x60cee6: mov [ecx+17Ch],ebp
0x60ceec: mov ecx,esp
0x60ceee: mov [esp+38h],esp
0x60cef2: push 7F5BA8h
0x60cef7: call dword ptr ds:[77CD7Ch]
0x60cefd: push edi
0x60cefe: call 0060EAB0h
0x60cf03: mov ecx,[esi+4]
0x60cf06: test ecx,ecx
0x60cf08: je short 0060CF17h
0x60cf0a: mov eax,[esi+8]
0x60cf0d: sub eax,ecx
0x60cf0f: sar eax,2
0x60cf12: cmp eax,60h
0x60cf15: ja short 0060CF21h
0x60cf17: mov ebp,ds:[77D0E4h]
0x60cf1d: call ebp
0x60cf1f: jmp short 0060CF27h
0x60cf21: mov ebp,ds:[77D0E4h]
0x60cf27: mov edx,[esi+4]
0x60cf2a: push 60h
0x60cf2c: sub esp,1Ch
0x60cf2f: mov ecx,esp
0x60cf31: mov [esp+38h],esp
0x60cf35: push 7F5BB4h
0x60cf3a: mov dword ptr [edx+180h],181818h
0x60cf44: call dword ptr ds:[77CD7Ch]
0x60cf4a: push edi
0x60cf4b: call 0060EAB0h
0x60cf50: mov ecx,[esi+4]
0x60cf53: test ecx,ecx
0x60cf55: je short 0060CF64h
0x60cf57: mov eax,[esi+8]
0x60cf5a: sub eax,ecx
0x60cf5c: sar eax,2
0x60cf5f: cmp eax,61h
0x60cf62: ja short 0060CF66h
0x60cf64: call ebp
0x60cf66: mov eax,[esi+4]
0x60cf69: push 61h
0x60cf6b: sub esp,1Ch
0x60cf6e: mov ecx,esp
0x60cf70: mov [esp+38h],esp
0x60cf74: push 7F5BCCh
0x60cf79: mov dword ptr [eax+184h],202020h
0x60cf83: call dword ptr ds:[77CD7Ch]
0x60cf89: push edi
0x60cf8a: call 0060EAB0h
0x60cf8f: mov ecx,[esi+4]
0x60cf92: test ecx,ecx
0x60cf94: je short 0060CFA3h
0x60cf96: mov eax,[esi+8]
0x60cf99: sub eax,ecx
0x60cf9b: sar eax,2
0x60cf9e: cmp eax,63h
0x60cfa1: ja short 0060CFA5h
0x60cfa3: call ebp
0x60cfa5: mov ecx,[esi+4]
0x60cfa8: push 63h
0x60cfaa: sub esp,1Ch
0x60cfad: mov [ecx+18Ch],ebx
0x60cfb3: mov ecx,esp
0x60cfb5: mov [esp+38h],esp
0x60cfb9: push 7F5BECh
0x60cfbe: call dword ptr ds:[77CD7Ch]
0x60cfc4: push edi
0x60cfc5: call 0060EAB0h
0x60cfca: mov ecx,[esi+4]
0x60cfcd: test ecx,ecx
0x60cfcf: je short 0060CFDEh
0x60cfd1: mov eax,[esi+8]
0x60cfd4: sub eax,ecx
0x60cfd6: sar eax,2
0x60cfd9: cmp eax,64h
0x60cfdc: ja short 0060CFE0h
0x60cfde: call ebp
0x60cfe0: mov edx,[esi+4]
0x60cfe3: push 64h
0x60cfe5: sub esp,1Ch
0x60cfe8: mov ecx,esp
0x60cfea: mov [esp+38h],esp
0x60cfee: push 7F5C08h
0x60cff3: mov [edx+190h],ebx
0x60cff9: call dword ptr ds:[77CD7Ch]
0x60cfff: push edi
0x60d000: call 0060EAB0h
0x60d005: mov ecx,[esi+4]
0x60d008: test ecx,ecx
0x60d00a: je short 0060D019h
0x60d00c: mov eax,[esi+8]
0x60d00f: sub eax,ecx
0x60d011: sar eax,2
0x60d014: cmp eax,62h
0x60d017: ja short 0060D01Bh
0x60d019: call ebp
0x60d01b: mov eax,[esi+4]
0x60d01e: push 62h
0x60d020: sub esp,1Ch
0x60d023: mov ecx,esp
0x60d025: mov [esp+38h],esp
0x60d029: push 7F5C20h
0x60d02e: mov dword ptr [eax+188h],9C9C9Ch
0x60d038: call dword ptr ds:[77CD7Ch]
0x60d03e: push edi
0x60d03f: call 0060EAB0h
0x60d044: mov ecx,[esi+4]
0x60d047: test ecx,ecx
0x60d049: je short 0060D058h
0x60d04b: mov eax,[esi+8]
0x60d04e: sub eax,ecx
0x60d050: sar eax,2
0x60d053: cmp eax,65h
0x60d056: ja short 0060D05Ah
0x60d058: call ebp
0x60d05a: mov ecx,[esi+4]
0x60d05d: push 65h
0x60d05f: sub esp,1Ch
0x60d062: mov dword ptr [ecx+194h],0FFFFFFh
0x60d06c: mov ecx,esp
0x60d06e: mov [esp+38h],esp
0x60d072: push 7F5C30h
0x60d077: call dword ptr ds:[77CD7Ch]
0x60d07d: push edi
0x60d07e: call 0060EAB0h
0x60d083: mov ecx,[esi+4]
0x60d086: test ecx,ecx
0x60d088: je short 0060D097h
0x60d08a: mov eax,[esi+8]
0x60d08d: sub eax,ecx
0x60d08f: sar eax,2
0x60d092: cmp eax,6Fh
0x60d095: ja short 0060D099h
0x60d097: call ebp
0x60d099: mov edx,[esi+4]
0x60d09c: push 6Fh
0x60d09e: sub esp,1Ch
0x60d0a1: mov ecx,esp
0x60d0a3: mov [esp+38h],esp
0x60d0a7: mov ebx,362C25h
0x60d0ac: push 7F5C48h
0x60d0b1: mov [edx+1BCh],ebx
0x60d0b7: call dword ptr ds:[77CD7Ch]
0x60d0bd: push edi
0x60d0be: call 0060EAB0h
0x60d0c3: mov ecx,[esi+4]
0x60d0c6: test ecx,ecx
0x60d0c8: je short 0060D0D7h
0x60d0ca: mov eax,[esi+8]
0x60d0cd: sub eax,ecx
0x60d0cf: sar eax,2
0x60d0d2: cmp eax,70h
0x60d0d5: ja short 0060D0D9h
0x60d0d7: call ebp
0x60d0d9: mov eax,[esi+4]
0x60d0dc: push 70h
0x60d0de: sub esp,1Ch
0x60d0e1: mov ecx,esp
0x60d0e3: mov [esp+38h],esp
0x60d0e7: push 7F5C5Ch
0x60d0ec: mov [eax+1C0h],ebx
0x60d0f2: call dword ptr ds:[77CD7Ch]
0x60d0f8: push edi
0x60d0f9: call 0060EAB0h
0x60d0fe: mov ecx,[esi+4]
0x60d101: test ecx,ecx
0x60d103: je short 0060D112h
0x60d105: mov eax,[esi+8]
0x60d108: sub eax,ecx
0x60d10a: sar eax,2
0x60d10d: cmp eax,71h
0x60d110: ja short 0060D114h
0x60d112: call ebp
0x60d114: mov ecx,[esi+4]
0x60d117: push 71h
0x60d119: sub esp,1Ch
0x60d11c: mov dword ptr [ecx+1C4h],0C0C0C0h
0x60d126: mov ecx,esp
0x60d128: mov [esp+38h],esp
0x60d12c: push 7F5C70h
0x60d131: call dword ptr ds:[77CD7Ch]
0x60d137: push edi
0x60d138: call 0060EAB0h
0x60d13d: mov ecx,[esi+4]
0x60d140: test ecx,ecx
0x60d142: je short 0060D151h
0x60d144: mov eax,[esi+8]
0x60d147: sub eax,ecx
0x60d149: sar eax,2
0x60d14c: cmp eax,72h
0x60d14f: ja short 0060D153h
0x60d151: call ebp
0x60d153: mov edx,[esi+4]
0x60d156: push 72h
0x60d158: sub esp,1Ch
0x60d15b: mov ecx,esp
0x60d15d: mov [esp+38h],esp
0x60d161: mov ebp,0FFh
0x60d166: push 7F5C80h
0x60d16b: mov [edx+1C8h],ebp
0x60d171: call dword ptr ds:[77CD7Ch]
0x60d177: push edi
0x60d178: call 0060EAB0h
0x60d17d: mov ecx,[esi+4]
0x60d180: test ecx,ecx
0x60d182: je short 0060D191h
0x60d184: mov eax,[esi+8]
0x60d187: sub eax,ecx
0x60d189: sar eax,2
0x60d18c: cmp eax,73h
0x60d18f: ja short 0060D197h
0x60d191: call dword ptr ds:[77D0E4h]
0x60d197: mov eax,[esi+4]
0x60d19a: push 73h
0x60d19c: sub esp,1Ch
0x60d19f: mov ecx,esp
0x60d1a1: mov [esp+38h],esp
0x60d1a5: mov ebx,0FFFFFFh
0x60d1aa: push 7F5C90h
0x60d1af: mov [eax+1CCh],ebx
0x60d1b5: call dword ptr ds:[77CD7Ch]
0x60d1bb: push edi
0x60d1bc: call 0060EAB0h
0x60d1c1: mov ecx,[esi+4]
0x60d1c4: test ecx,ecx
0x60d1c6: je short 0060D1D5h
0x60d1c8: mov eax,[esi+8]
0x60d1cb: sub eax,ecx
0x60d1cd: sar eax,2
0x60d1d0: cmp eax,66h
0x60d1d3: ja short 0060D1DBh
0x60d1d5: call dword ptr ds:[77D0E4h]
0x60d1db: mov ecx,[esi+4]
0x60d1de: push 66h
0x60d1e0: sub esp,1Ch
0x60d1e3: mov dword ptr [ecx+198h],0FFFF00h
0x60d1ed: mov ecx,esp
0x60d1ef: mov [esp+38h],esp
0x60d1f3: push 7F5CA4h
0x60d1f8: call dword ptr ds:[77CD7Ch]
0x60d1fe: push edi
0x60d1ff: call 0060EAB0h
0x60d204: mov ecx,[esi+4]
0x60d207: test ecx,ecx
0x60d209: je short 0060D218h
0x60d20b: mov eax,[esi+8]
0x60d20e: sub eax,ecx
0x60d210: sar eax,2
0x60d213: cmp eax,67h
0x60d216: ja short 0060D21Eh
0x60d218: call dword ptr ds:[77D0E4h]
0x60d21e: mov edx,[esi+4]
0x60d221: push 67h
0x60d223: sub esp,1Ch
0x60d226: mov ecx,esp
0x60d228: mov [esp+38h],esp
0x60d22c: push 7F5CB0h
0x60d231: mov dword ptr [edx+19Ch],0FFFFh
0x60d23b: call dword ptr ds:[77CD7Ch]
0x60d241: push edi
0x60d242: call 0060EAB0h
0x60d247: mov ecx,[esi+4]
0x60d24a: test ecx,ecx
0x60d24c: je short 0060D25Bh
0x60d24e: mov eax,[esi+8]
0x60d251: sub eax,ecx
0x60d253: sar eax,2
0x60d256: cmp eax,68h
0x60d259: ja short 0060D261h
0x60d25b: call dword ptr ds:[77D0E4h]
0x60d261: mov eax,[esi+4]
0x60d264: push 68h
0x60d266: sub esp,1Ch
0x60d269: mov ecx,esp
0x60d26b: mov [esp+38h],esp
0x60d26f: push 7F5CC0h
0x60d274: mov [eax+1A0h],ebx
0x60d27a: call dword ptr ds:[77CD7Ch]
0x60d280: push edi
0x60d281: call 0060EAB0h
0x60d286: mov ecx,[esi+4]
0x60d289: test ecx,ecx
0x60d28b: je short 0060D29Ah
0x60d28d: mov eax,[esi+8]
0x60d290: sub eax,ecx
0x60d292: sar eax,2
0x60d295: cmp eax,69h
0x60d298: ja short 0060D2A4h
0x60d29a: mov ebx,ds:[77D0E4h]
0x60d2a0: call ebx
0x60d2a2: jmp short 0060D2AAh
0x60d2a4: mov ebx,ds:[77D0E4h]
0x60d2aa: mov ecx,[esi+4]
0x60d2ad: push 69h
0x60d2af: sub esp,1Ch
0x60d2b2: mov dword ptr [ecx+1A4h],0E1h
0x60d2bc: mov ecx,esp
0x60d2be: mov [esp+38h],esp
0x60d2c2: push 7F5CCCh
0x60d2c7: call dword ptr ds:[77CD7Ch]
0x60d2cd: push edi
0x60d2ce: call 0060EAB0h
0x60d2d3: mov ecx,[esi+4]
0x60d2d6: test ecx,ecx
0x60d2d8: je short 0060D2E7h
0x60d2da: mov eax,[esi+8]
0x60d2dd: sub eax,ecx
0x60d2df: sar eax,2
0x60d2e2: cmp eax,6Ah
0x60d2e5: ja short 0060D2E9h
0x60d2e7: call ebx
0x60d2e9: mov edx,[esi+4]
0x60d2ec: push 6Ah
0x60d2ee: sub esp,1Ch
0x60d2f1: mov ecx,esp
0x60d2f3: mov [esp+38h],esp
0x60d2f7: push 7F5CD4h
0x60d2fc: mov dword ptr [edx+1A8h],0FF0000h
0x60d306: call dword ptr ds:[77CD7Ch]
0x60d30c: push edi
0x60d30d: call 0060EAB0h
0x60d312: mov ecx,[esi+4]
0x60d315: test ecx,ecx
0x60d317: je short 0060D326h
0x60d319: mov eax,[esi+8]
0x60d31c: sub eax,ecx
0x60d31e: sar eax,2
0x60d321: cmp eax,6Bh
0x60d324: ja short 0060D328h
0x60d326: call ebx
0x60d328: mov eax,[esi+4]
0x60d32b: push 6Bh
0x60d32d: sub esp,1Ch
0x60d330: mov ecx,esp
0x60d332: mov [esp+38h],esp
0x60d336: push 7F5CE0h
0x60d33b: mov dword ptr [eax+1ACh],0FF40h
0x60d345: call dword ptr ds:[77CD7Ch]
0x60d34b: push edi
0x60d34c: call 0060EAB0h
0x60d351: mov ecx,[esi+4]
0x60d354: test ecx,ecx
0x60d356: je short 0060D365h
0x60d358: mov eax,[esi+8]
0x60d35b: sub eax,ecx
0x60d35d: sar eax,2
0x60d360: cmp eax,74h
0x60d363: ja short 0060D367h
0x60d365: call ebx
0x60d367: mov ecx,[esi+4]
0x60d36a: push 74h
0x60d36c: sub esp,1Ch
0x60d36f: mov dword ptr [ecx+1D0h],808080h
0x60d379: mov ecx,esp
0x60d37b: mov [esp+38h],esp
0x60d37f: push 7F5CECh
0x60d384: call dword ptr ds:[77CD7Ch]
0x60d38a: push edi
0x60d38b: call 0060EAB0h
0x60d390: mov ecx,[esi+4]
0x60d393: test ecx,ecx
0x60d395: je short 0060D3A4h
0x60d397: mov eax,[esi+8]
0x60d39a: sub eax,ecx
0x60d39c: sar eax,2
0x60d39f: cmp eax,75h
0x60d3a2: ja short 0060D3A6h
0x60d3a4: call ebx
0x60d3a6: mov edx,[esi+4]
0x60d3a9: push 75h
0x60d3ab: sub esp,1Ch
0x60d3ae: mov ecx,esp
0x60d3b0: mov [esp+38h],esp
0x60d3b4: push 7F5D00h
0x60d3b9: mov dword ptr [edx+1D4h],8080h
0x60d3c3: call dword ptr ds:[77CD7Ch]
0x60d3c9: push edi
0x60d3ca: call 0060EAB0h
0x60d3cf: mov ecx,[esi+4]
0x60d3d2: test ecx,ecx
0x60d3d4: je short 0060D3E3h
0x60d3d6: mov eax,[esi+8]
0x60d3d9: sub eax,ecx
0x60d3db: sar eax,2
0x60d3de: cmp eax,76h
0x60d3e1: ja short 0060D3E5h
0x60d3e3: call ebx
0x60d3e5: mov eax,[esi+4]
0x60d3e8: push 76h
0x60d3ea: sub esp,1Ch
0x60d3ed: mov ecx,esp
0x60d3ef: mov [esp+38h],esp
0x60d3f3: mov ebx,0A42020h
0x60d3f8: push 7F5D18h
0x60d3fd: mov [eax+1D8h],ebx
0x60d403: call dword ptr ds:[77CD7Ch]
0x60d409: push edi
0x60d40a: call 0060EAB0h
0x60d40f: mov ecx,[esi+4]
0x60d412: test ecx,ecx
0x60d414: je short 0060D423h
0x60d416: mov eax,[esi+8]
0x60d419: sub eax,ecx
0x60d41b: sar eax,2
0x60d41e: cmp eax,77h
0x60d421: ja short 0060D429h
0x60d423: call dword ptr ds:[77D0E4h]
0x60d429: mov ecx,[esi+4]
0x60d42c: push 77h
0x60d42e: sub esp,1Ch
0x60d431: mov [ecx+1DCh],ebx
0x60d437: mov ecx,esp
0x60d439: mov [esp+38h],esp
0x60d43d: push 7F5D2Ch
0x60d442: call dword ptr ds:[77CD7Ch]
0x60d448: push edi
0x60d449: call 0060EAB0h
0x60d44e: mov ecx,[esi+4]
0x60d451: test ecx,ecx
0x60d453: je short 0060D462h
0x60d455: mov eax,[esi+8]
0x60d458: sub eax,ecx
0x60d45a: sar eax,2
0x60d45d: cmp eax,78h
0x60d460: ja short 0060D468h
0x60d462: call dword ptr ds:[77D0E4h]
0x60d468: mov edx,[esi+4]
0x60d46b: push 78h
0x60d46d: sub esp,1Ch
0x60d470: mov ecx,esp
0x60d472: mov [esp+38h],esp
0x60d476: push 7F5D3Ch
0x60d47b: mov [edx+1E0h],ebx
0x60d481: call dword ptr ds:[77CD7Ch]
0x60d487: push edi
0x60d488: call 0060EAB0h
0x60d48d: mov ecx,[esi+4]
0x60d490: test ecx,ecx
0x60d492: je short 0060D4A1h
0x60d494: mov eax,[esi+8]
0x60d497: sub eax,ecx
0x60d499: sar eax,2
0x60d49c: cmp eax,79h
0x60d49f: ja short 0060D4A7h
0x60d4a1: call dword ptr ds:[77D0E4h]
0x60d4a7: mov eax,[esi+4]
0x60d4aa: push 79h
0x60d4ac: sub esp,1Ch
0x60d4af: mov ecx,esp
0x60d4b1: mov [esp+38h],esp
0x60d4b5: mov ebx,0FF0000h
0x60d4ba: push 7F5D54h
0x60d4bf: mov [eax+1E4h],ebx
0x60d4c5: call dword ptr ds:[77CD7Ch]
0x60d4cb: push edi
0x60d4cc: call 0060EAB0h
0x60d4d1: mov ecx,[esi+4]
0x60d4d4: test ecx,ecx
0x60d4d6: je short 0060D4E5h
0x60d4d8: mov eax,[esi+8]
0x60d4db: sub eax,ecx
0x60d4dd: sar eax,2
0x60d4e0: cmp eax,7Ah
0x60d4e3: ja short 0060D4EBh
0x60d4e5: call dword ptr ds:[77D0E4h]
0x60d4eb: mov ecx,[esi+4]
0x60d4ee: push 7Ah
0x60d4f0: sub esp,1Ch
0x60d4f3: mov [ecx+1E8h],ebx
0x60d4f9: mov ecx,esp
0x60d4fb: mov [esp+38h],esp
0x60d4ff: push 7F5D60h
0x60d504: call dword ptr ds:[77CD7Ch]
0x60d50a: push edi
0x60d50b: call 0060EAB0h
0x60d510: mov ecx,[esi+4]
0x60d513: test ecx,ecx
0x60d515: je short 0060D524h
0x60d517: mov eax,[esi+8]
0x60d51a: sub eax,ecx
0x60d51c: sar eax,2
0x60d51f: cmp eax,7Bh
0x60d522: ja short 0060D52Eh
0x60d524: mov ebx,ds:[77D0E4h]
0x60d52a: call ebx
0x60d52c: jmp short 0060D534h
0x60d52e: mov ebx,ds:[77D0E4h]
0x60d534: mov edx,[esi+4]
0x60d537: push 7Bh
0x60d539: sub esp,1Ch
0x60d53c: mov ecx,esp
0x60d53e: mov [esp+38h],esp
0x60d542: push 7F5D6Ch
0x60d547: mov [edx+1ECh],ebp
0x60d54d: call dword ptr ds:[77CD7Ch]
0x60d553: push edi
0x60d554: call 0060EAB0h
0x60d559: mov ecx,[esi+4]
0x60d55c: test ecx,ecx
0x60d55e: je short 0060D56Dh
0x60d560: mov eax,[esi+8]
0x60d563: sub eax,ecx
0x60d565: sar eax,2
0x60d568: cmp eax,7Ch
0x60d56b: ja short 0060D56Fh
0x60d56d: call ebx
0x60d56f: mov eax,[esi+4]
0x60d572: push 7Ch
0x60d574: sub esp,1Ch
0x60d577: mov ecx,esp
0x60d579: mov [esp+38h],esp
0x60d57d: push 7F5D7Ch
0x60d582: mov dword ptr [eax+1F0h],0FF00h
0x60d58c: call dword ptr ds:[77CD7Ch]
0x60d592: push edi
0x60d593: call 0060EAB0h
0x60d598: mov ecx,[esi+4]
0x60d59b: test ecx,ecx
0x60d59d: je short 0060D5ACh
0x60d59f: mov eax,[esi+8]
0x60d5a2: sub eax,ecx
0x60d5a4: sar eax,2
0x60d5a7: cmp eax,7Dh
0x60d5aa: ja short 0060D5AEh
0x60d5ac: call ebx
0x60d5ae: mov ecx,[esi+4]
0x60d5b1: push 7Dh
0x60d5b3: sub esp,1Ch
0x60d5b6: mov dword ptr [ecx+1F4h],0FFFFh
0x60d5c0: mov ecx,esp
0x60d5c2: mov [esp+38h],esp
0x60d5c6: push 7F5D8Ch
0x60d5cb: call dword ptr ds:[77CD7Ch]
0x60d5d1: push edi
0x60d5d2: call 0060EAB0h
0x60d5d7: push 7DFE7Ch
0x60d5dc: lea ecx,[esp+20h]
0x60d5e0: call dword ptr ds:[77CD7Ch]
0x60d5e6: push 7F5D98h
0x60d5eb: lea edx,[esp+20h]
0x60d5ef: lea esi,[edi+38h]
0x60d5f2: push edx
0x60d5f3: mov ecx,esi
0x60d5f5: mov byte ptr [esp+64h],4
0x60d5fa: call 0060ED90h
0x60d5ff: mov ecx,eax
0x60d601: call dword ptr ds:[77CD50h]
0x60d607: lea ecx,[esp+1Ch]
0x60d60b: mov byte ptr [esp+5Ch],3
0x60d610: call dword ptr ds:[77CD74h]
0x60d616: push 7DFE84h
0x60d61b: lea ecx,[esp+3Ch]
0x60d61f: call dword ptr ds:[77CD7Ch]
0x60d625: push 7F5DA4h
0x60d62a: lea eax,[esp+3Ch]
0x60d62e: push eax
0x60d62f: mov ecx,esi
0x60d631: mov byte ptr [esp+64h],5
0x60d636: call 0060ED90h
0x60d63b: mov ecx,eax
0x60d63d: call dword ptr ds:[77CD50h]
0x60d643: lea ecx,[esp+38h]
0x60d647: mov byte ptr [esp+5Ch],3
0x60d64c: call dword ptr ds:[77CD74h]
0x60d652: mov eax,edi
0x60d654: mov ecx,[esp+54h]
0x60d658: mov fs:[0],ecx
0x60d65f: pop ecx
0x60d660: pop edi
0x60d661: pop esi
0x60d662: pop ebp
0x60d663: pop ebx
0x60d664: add esp,4Ch
0x60d667: ret 4
````

`sub_60b550` is called by ?get_instance@?$singleton@VColorScheme@@@serialization@boost@@CAAAVColorScheme@@XZ. It works with the text "Default", "ViewBorder", "FloatBk". It delegates to sub_60eab0, sub_60ed90, sub_60ef60 (5 callees).

### sub_60d680 at 0x60d680 (36 instructions)

````text
0x60d680: push 0FFFFFFFFh
0x60d682: push 74A69Fh
0x60d687: mov eax,fs:[0]
0x60d68d: push eax
0x60d68e: push ecx
0x60d68f: push esi
0x60d690: mov eax,ds:[858220h]
0x60d695: xor eax,esp
0x60d697: push eax
0x60d698: lea eax,[esp+0Ch]
0x60d69c: mov fs:[0],eax
0x60d6a2: mov esi,[esp+1Ch]
0x60d6a6: lea ecx,[esi+38h]
0x60d6a9: mov dword ptr [esp+14h],2
0x60d6b1: call 0060F470h
0x60d6b6: lea ecx,[esi+2Ch]
0x60d6b9: mov byte ptr [esp+14h],1
0x60d6be: call 0060F240h
0x60d6c3: mov eax,[esi+20h]
0x60d6c6: test eax,eax
0x60d6c8: je short 0060D6D3h
0x60d6ca: push eax
0x60d6cb: call 006516BAh
0x60d6d0: add esp,4
0x60d6d3: mov ecx,esi
0x60d6d5: mov dword ptr [esi+20h],0
0x60d6dc: mov dword ptr [esi+24h],0
0x60d6e3: mov dword ptr [esi+28h],0
0x60d6ea: mov dword ptr [esp+14h],0FFFFFFFFh
0x60d6f2: call dword ptr ds:[77CD74h]
0x60d6f8: mov ecx,[esp+0Ch]
0x60d6fc: mov fs:[0],ecx
0x60d703: pop ecx
0x60d704: pop esi
0x60d705: add esp,10h
0x60d708: ret 4
````

`sub_60d680` is called by sub_77b4c0. It delegates to sub_60f240, sub_60f470, j_ORDINAL 764 (3 callees).

### sub_60eab0 at 0x60eab0 (25 instructions)

````text
0x60eab0: push 0FFFFFFFFh
0x60eab2: push 739E19h
0x60eab7: mov eax,fs:[0]
0x60eabd: push eax
0x60eabe: mov eax,ds:[858220h]
0x60eac3: xor eax,esp
0x60eac5: push eax
0x60eac6: lea eax,[esp+4]
0x60eaca: mov fs:[0],eax
0x60ead0: mov eax,[esp+14h]
0x60ead4: lea ecx,[esp+18h]
0x60ead8: push ecx
0x60ead9: lea ecx,[eax+2Ch]
0x60eadc: mov dword ptr [esp+10h],0
0x60eae4: call 0060EC50h
0x60eae9: mov edx,[esp+34h]
0x60eaed: lea ecx,[esp+18h]
0x60eaf1: mov [eax],edx
0x60eaf3: mov dword ptr [esp+0Ch],0FFFFFFFFh
0x60eafb: call dword ptr ds:[77CD74h]
0x60eb01: mov ecx,[esp+4]
0x60eb05: mov fs:[0],ecx
0x60eb0c: pop ecx
0x60eb0d: add esp,0Ch
0x60eb10: ret 24h
````

`sub_60eab0` is called by sub_60b550. It delegates to sub_60ec50 (1 callees).

### sub_60ec50 at 0x60ec50 (68 instructions)

````text
0x60ec50: push ebp
0x60ec51: mov ebp,esp
0x60ec53: and esp,0FFFFFFF8h
0x60ec56: push 0FFFFFFFFh
0x60ec58: push 746EE8h
0x60ec5d: mov eax,fs:[0]
0x60ec63: push eax
0x60ec64: sub esp,30h
0x60ec67: push ebx
0x60ec68: push esi
0x60ec69: push edi
0x60ec6a: mov eax,ds:[858220h]
0x60ec6f: xor eax,esp
0x60ec71: push eax
0x60ec72: lea eax,[esp+40h]
0x60ec76: mov fs:[0],eax
0x60ec7c: mov esi,ecx
0x60ec7e: mov ebx,[ebp+8]
0x60ec81: push ebx
0x60ec82: call 0060F9D0h
0x60ec87: test esi,esi
0x60ec89: mov edi,eax
0x60ec8b: jne short 0060EC93h
0x60ec8d: call dword ptr ds:[77D0E4h]
0x60ec93: cmp edi,[esi+4]
0x60ec96: je short 0060ECAAh
0x60ec98: lea eax,[edi+0Ch]
0x60ec9b: push eax
0x60ec9c: push ebx
0x60ec9d: call dword ptr ds:[77CDA0h]
0x60eca3: add esp,8
0x60eca6: test al,al
0x60eca8: je short 0060ECE9h
0x60ecaa: push ebx
0x60ecab: lea ecx,[esp+20h]
0x60ecaf: call dword ptr ds:[77CD78h]
0x60ecb5: xor eax,eax
0x60ecb7: mov [esp+38h],eax
0x60ecbb: lea ecx,[esp+1Ch]
0x60ecbf: push ecx
0x60ecc0: push edi
0x60ecc1: push esi
0x60ecc2: lea edx,[esp+20h]
0x60ecc6: push edx
0x60ecc7: mov ecx,esi
0x60ecc9: mov [esp+58h],eax
0x60eccd: call 0060F020h
0x60ecd2: mov esi,[eax]
0x60ecd4: mov edi,[eax+4]
0x60ecd7: lea ecx,[esp+1Ch]
0x60ecdb: mov dword ptr [esp+48h],0FFFFFFFFh
0x60ece3: call dword ptr ds:[77CD74h]
0x60ece9: test esi,esi
0x60eceb: jne short 0060ECF3h
0x60eced: call dword ptr ds:[77D0E4h]
0x60ecf3: cmp edi,[esi+4]
0x60ecf6: jne short 0060ECFEh
0x60ecf8: call dword ptr ds:[77D0E4h]
0x60ecfe: lea eax,[edi+28h]
0x60ed01: mov ecx,[esp+40h]
0x60ed05: mov fs:[0],ecx
0x60ed0c: pop ecx
0x60ed0d: pop edi
0x60ed0e: pop esi
0x60ed0f: pop ebx
0x60ed10: mov esp,ebp
0x60ed12: pop ebp
0x60ed13: ret 4
````

`sub_60ec50` is called by sub_60eab0. It delegates to sub_60f020, sub_60f9d0 (2 callees).

### sub_60ed90 at 0x60ed90 (73 instructions)

````text
0x60ed90: push ebp
0x60ed91: mov ebp,esp
0x60ed93: and esp,0FFFFFFF8h
0x60ed96: push 0FFFFFFFFh
0x60ed98: push 7437F1h
0x60ed9d: mov eax,fs:[0]
0x60eda3: push eax
0x60eda4: sub esp,60h
0x60eda7: push ebx
0x60eda8: push esi
0x60eda9: push edi
0x60edaa: mov eax,ds:[858220h]
0x60edaf: xor eax,esp
0x60edb1: push eax
0x60edb2: lea eax,[esp+70h]
0x60edb6: mov fs:[0],eax
0x60edbc: mov ebx,[ebp+8]
0x60edbf: mov edi,ecx
0x60edc1: push ebx
0x60edc2: call 0060FDD0h
0x60edc7: test edi,edi
0x60edc9: mov esi,eax
0x60edcb: jne short 0060EDD3h
0x60edcd: call dword ptr ds:[77D0E4h]
0x60edd3: cmp esi,[edi+4]
0x60edd6: je short 0060EDEAh
0x60edd8: lea eax,[esi+0Ch]
0x60eddb: push eax
0x60eddc: push ebx
0x60eddd: call dword ptr ds:[77CDA0h]
0x60ede3: add esp,8
0x60ede6: test al,al
0x60ede8: je short 0060EE49h
0x60edea: lea ecx,[esp+18h]
0x60edee: call dword ptr ds:[77CD80h]
0x60edf4: mov ecx,[ebp+8]
0x60edf7: push eax
0x60edf8: push ecx
0x60edf9: lea edx,[esp+3Ch]
0x60edfd: push edx
0x60edfe: mov dword ptr [esp+84h],0
0x60ee09: call 004DE690h
0x60ee0e: push esi
0x60ee0f: push edi
0x60ee10: lea ecx,[esp+18h]
0x60ee14: push ecx
0x60ee15: mov ecx,edi
0x60ee17: mov byte ptr [esp+84h],1
0x60ee1f: call 0060F280h
0x60ee24: mov edi,[eax]
0x60ee26: mov esi,[eax+4]
0x60ee29: lea ecx,[esp+34h]
0x60ee2d: mov byte ptr [esp+78h],0
0x60ee32: call 0060EF00h
0x60ee37: lea ecx,[esp+18h]
0x60ee3b: mov dword ptr [esp+78h],0FFFFFFFFh
0x60ee43: call dword ptr ds:[77CD74h]
0x60ee49: test edi,edi
0x60ee4b: jne short 0060EE53h
0x60ee4d: call dword ptr ds:[77D0E4h]
0x60ee53: cmp esi,[edi+4]
0x60ee56: jne short 0060EE5Eh
0x60ee58: call dword ptr ds:[77D0E4h]
0x60ee5e: lea eax,[esi+28h]
0x60ee61: mov ecx,[esp+70h]
0x60ee65: mov fs:[0],ecx
0x60ee6c: pop ecx
0x60ee6d: pop edi
0x60ee6e: pop esi
0x60ee6f: pop ebx
0x60ee70: mov esp,ebp
0x60ee72: pop ebp
0x60ee73: ret 4
````

`sub_60ed90` is called by sub_60b550. It delegates to sub_4de690, sub_60ef00, sub_60f280 (4 callees).

### ?get_mutable_instance@?$singleton@VColorScheme@@@serialization@boost@@SAAAVColorScheme@@XZ at 0x60eef0 (4 instructions)

````text
0x60eef0: push ecx
0x60eef1: call 0060F4B0h
0x60eef6: pop ecx
0x60eef7: ret
````

`?get_mutable_instance@?$singleton@VColorScheme@@@serialization@boost@@SAAAVColorScheme@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VColorScheme@@@serialization@boost@@CAAAVColorScheme@@XZ (1 callees).

### sub_60ef00 at 0x60ef00 (25 instructions)

````text
0x60ef00: push 0FFFFFFFFh
0x60ef02: push 738F69h
0x60ef07: mov eax,fs:[0]
0x60ef0d: push eax
0x60ef0e: push ecx
0x60ef0f: push esi
0x60ef10: mov eax,ds:[858220h]
0x60ef15: xor eax,esp
0x60ef17: push eax
0x60ef18: lea eax,[esp+0Ch]
0x60ef1c: mov fs:[0],eax
0x60ef22: mov esi,ecx
0x60ef24: mov [esp+8],esi
0x60ef28: lea ecx,[esi+1Ch]
0x60ef2b: mov dword ptr [esp+14h],0
0x60ef33: call dword ptr ds:[77CD74h]
0x60ef39: mov ecx,esi
0x60ef3b: mov dword ptr [esp+14h],0FFFFFFFFh
0x60ef43: call dword ptr ds:[77CD74h]
0x60ef49: mov ecx,[esp+0Ch]
0x60ef4d: mov fs:[0],ecx
0x60ef54: pop ecx
0x60ef55: pop esi
0x60ef56: add esp,10h
0x60ef59: ret
````

`sub_60ef00` is called by sub_60ed90, sub_6102c0. It calls nothing else.

### sub_60ef60 at 0x60ef60 (72 instructions)

````text
0x60ef60: push ebp
0x60ef61: mov ebp,esp
0x60ef63: and esp,0FFFFFFF8h
0x60ef66: sub esp,0Ch
0x60ef69: push ebx
0x60ef6a: mov ebx,eax
0x60ef6c: mov ecx,[ebx+4]
0x60ef6f: test ecx,ecx
0x60ef71: push esi
0x60ef72: push edi
0x60ef73: mov dword ptr [esp+10h],0
0x60ef7b: je short 0060EF8Ch
0x60ef7d: mov edi,[ebx+8]
0x60ef80: mov eax,edi
0x60ef82: sub eax,ecx
0x60ef84: sar eax,2
0x60ef87: cmp eax,7Fh
0x60ef8a: jae short 0060EFC6h
0x60ef8c: mov esi,[ebx+8]
0x60ef8f: cmp ecx,esi
0x60ef91: jbe short 0060EF99h
0x60ef93: call dword ptr ds:[77D0E4h]
0x60ef99: mov ecx,[ebx+4]
0x60ef9c: test ecx,ecx
0x60ef9e: jne short 0060EFA4h
0x60efa0: xor eax,eax
0x60efa2: jmp short 0060EFACh
0x60efa4: mov eax,[ebx+8]
0x60efa7: sub eax,ecx
0x60efa9: sar eax,2
0x60efac: push esi
0x60efad: push ebx
0x60efae: mov ecx,7Fh
0x60efb3: sub ecx,eax
0x60efb5: push ebx
0x60efb6: lea eax,[esp+1Ch]
0x60efba: call 00425810h
0x60efbf: pop edi
0x60efc0: pop esi
0x60efc1: pop ebx
0x60efc2: mov esp,ebp
0x60efc4: pop ebp
0x60efc5: ret
0x60efc6: jbe short 0060F00Ah
0x60efc8: cmp ecx,edi
0x60efca: jbe short 0060EFD2h
0x60efcc: call dword ptr ds:[77D0E4h]
0x60efd2: mov esi,[ebx+4]
0x60efd5: cmp esi,[ebx+8]
0x60efd8: jbe short 0060EFE0h
0x60efda: call dword ptr ds:[77D0E4h]
0x60efe0: mov [esp+14h],esi
0x60efe4: add esi,1FCh
0x60efea: cmp esi,[ebx+8]
0x60efed: ja short 0060EFF4h
0x60efef: cmp esi,[ebx+4]
0x60eff2: jae short 0060EFFAh
0x60eff4: call dword ptr ds:[77D0E4h]
0x60effa: push edi
0x60effb: push ebx
0x60effc: push esi
0x60effd: mov eax,ebx
0x60efff: push eax
0x60f000: lea eax,[esp+20h]
0x60f004: push eax
0x60f005: call 0041FB70h
0x60f00a: pop edi
0x60f00b: pop esi
0x60f00c: pop ebx
0x60f00d: mov esp,ebp
0x60f00f: pop ebp
0x60f010: ret
````

`sub_60ef60` is called by sub_60b550. It delegates to sub_41fb70, sub_425810 (2 callees).

### sub_60f020 at 0x60f020 (219 instructions)

````text
0x60f020: push ebp
0x60f021: mov ebp,esp
0x60f023: and esp,0FFFFFFF8h
0x60f026: sub esp,14h
0x60f029: push ebx
0x60f02a: push esi
0x60f02b: mov esi,ecx
0x60f02d: cmp dword ptr [esi+8],0
0x60f031: push edi
0x60f032: jne short 0060F054h
0x60f034: mov eax,[ebp+14h]
0x60f037: mov ecx,[esi+4]
0x60f03a: mov edi,[ebp+8]
0x60f03d: push eax
0x60f03e: push ecx
0x60f03f: push 1
0x60f041: push edi
0x60f042: mov ecx,esi
0x60f044: call 0060F810h
0x60f049: mov eax,edi
0x60f04b: pop edi
0x60f04c: pop esi
0x60f04d: pop ebx
0x60f04e: mov esp,ebp
0x60f050: pop ebp
0x60f051: ret 10h
0x60f054: mov edx,[esi+4]
0x60f057: mov edi,[ebp+0Ch]
0x60f05a: test edi,edi
0x60f05c: mov eax,[edx]
0x60f05e: mov [esp+18h],eax
0x60f062: je short 0060F068h
0x60f064: cmp edi,esi
0x60f066: je short 0060F06Eh
0x60f068: call dword ptr ds:[77D0E4h]
0x60f06e: mov ebx,[ebp+10h]
0x60f071: cmp ebx,[esp+18h]
0x60f075: jne short 0060F0AAh
0x60f077: mov edi,[ebp+14h]
0x60f07a: lea ecx,[ebx+0Ch]
0x60f07d: push ecx
0x60f07e: push edi
0x60f07f: call dword ptr ds:[77CDA0h]
0x60f085: add esp,8
0x60f088: test al,al
0x60f08a: je near ptr 0060F20Fh
0x60f090: push edi
0x60f091: mov edi,[ebp+8]
0x60f094: push ebx
0x60f095: push 1
0x60f097: push edi
0x60f098: mov ecx,esi
0x60f09a: call 0060F810h
0x60f09f: mov eax,edi
0x60f0a1: pop edi
0x60f0a2: pop esi
0x60f0a3: pop ebx
0x60f0a4: mov esp,ebp
0x60f0a6: pop ebp
0x60f0a7: ret 10h
0x60f0aa: test edi,edi
0x60f0ac: mov edx,[esi+4]
0x60f0af: mov [esp+18h],edx
0x60f0b3: je short 0060F0B9h
0x60f0b5: cmp edi,esi
0x60f0b7: je short 0060F0BFh
0x60f0b9: call dword ptr ds:[77D0E4h]
0x60f0bf: cmp ebx,[esp+18h]
0x60f0c3: mov edi,[ebp+14h]
0x60f0c6: jne short 0060F104h
0x60f0c8: mov eax,[esi+4]
0x60f0cb: mov eax,[eax+8]
0x60f0ce: add eax,0Ch
0x60f0d1: push edi
0x60f0d2: push eax
0x60f0d3: call dword ptr ds:[77CDA0h]
0x60f0d9: add esp,8
0x60f0dc: test al,al
0x60f0de: je near ptr 0060F20Fh
0x60f0e4: mov ecx,[esi+4]
0x60f0e7: mov edx,[ecx+8]
0x60f0ea: push edi
0x60f0eb: mov edi,[ebp+8]
0x60f0ee: push edx
0x60f0ef: push 0
0x60f0f1: push edi
0x60f0f2: mov ecx,esi
0x60f0f4: call 0060F810h
0x60f0f9: mov eax,edi
0x60f0fb: pop edi
0x60f0fc: pop esi
0x60f0fd: pop ebx
0x60f0fe: mov esp,ebp
0x60f100: pop ebp
0x60f101: ret 10h
0x60f104: lea eax,[ebx+0Ch]
0x60f107: push eax
0x60f108: push edi
0x60f109: call dword ptr ds:[77CDA0h]
0x60f10f: add esp,8
0x60f112: test al,al
0x60f114: je short 0060F179h
0x60f116: mov eax,[ebp+0Ch]
0x60f119: lea ecx,[esp+0Ch]
0x60f11d: mov [esp+0Ch],eax
0x60f121: mov [esp+10h],ebx
0x60f125: call 00610890h
0x60f12a: mov ecx,[esp+10h]
0x60f12e: add ecx,0Ch
0x60f131: push edi
0x60f132: push ecx
0x60f133: mov ecx,esi
0x60f135: call 0040C260h
0x60f13a: test al,al
0x60f13c: je short 0060F179h
0x60f13e: mov eax,[esp+10h]
0x60f142: mov edx,[eax+8]
0x60f145: cmp byte ptr [edx+2Dh],0
0x60f149: push edi
0x60f14a: mov edi,[ebp+8]
0x60f14d: mov ecx,esi
0x60f14f: je short 0060F165h
0x60f151: push eax
0x60f152: push 0
0x60f154: push edi
0x60f155: call 0060F810h
0x60f15a: mov eax,edi
0x60f15c: pop edi
0x60f15d: pop esi
0x60f15e: pop ebx
0x60f15f: mov esp,ebp
0x60f161: pop ebp
0x60f162: ret 10h
0x60f165: push ebx
0x60f166: push 1
0x60f168: push edi
0x60f169: call 0060F810h
0x60f16e: mov eax,edi
0x60f170: pop edi
0x60f171: pop esi
0x60f172: pop ebx
0x60f173: mov esp,ebp
0x60f175: pop ebp
0x60f176: ret 10h
0x60f179: lea eax,[ebx+0Ch]
0x60f17c: push edi
0x60f17d: push eax
0x60f17e: call dword ptr ds:[77CDA0h]
0x60f184: add esp,8
0x60f187: test al,al
0x60f189: je near ptr 0060F20Fh
0x60f18f: mov ecx,[esi+4]
0x60f192: mov eax,[ebp+0Ch]
0x60f195: mov [esp+18h],ecx
0x60f199: lea ecx,[esp+0Ch]
0x60f19d: mov [esp+0Ch],eax
0x60f1a1: mov [esp+10h],ebx
0x60f1a5: mov [esp+14h],esi
0x60f1a9: call 0060F5C0h
0x60f1ae: lea edx,[esp+14h]
0x60f1b2: push edx
0x60f1b3: lea ecx,[esp+10h]
0x60f1b7: call 0060F520h
0x60f1bc: test al,al
0x60f1be: jne short 0060F1D4h
0x60f1c0: mov eax,[esp+10h]
0x60f1c4: add eax,0Ch
0x60f1c7: push eax
0x60f1c8: push edi
0x60f1c9: mov ecx,esi
0x60f1cb: call 0040C260h
0x60f1d0: test al,al
0x60f1d2: je short 0060F20Fh
0x60f1d4: mov ecx,[ebx+8]
0x60f1d7: cmp byte ptr [ecx+2Dh],0
0x60f1db: push edi
0x60f1dc: mov edi,[ebp+8]
0x60f1df: mov ecx,esi
0x60f1e1: je short 0060F1F7h
0x60f1e3: push ebx
0x60f1e4: push 0
0x60f1e6: push edi
0x60f1e7: call 0060F810h
0x60f1ec: mov eax,edi
0x60f1ee: pop edi
0x60f1ef: pop esi
0x60f1f0: pop ebx
0x60f1f1: mov esp,ebp
0x60f1f3: pop ebp
0x60f1f4: ret 10h
0x60f1f7: mov edx,[esp+14h]
0x60f1fb: push edx
0x60f1fc: push 1
0x60f1fe: push edi
0x60f1ff: call 0060F810h
0x60f204: mov eax,edi
0x60f206: pop edi
0x60f207: pop esi
0x60f208: pop ebx
0x60f209: mov esp,ebp
0x60f20b: pop ebp
0x60f20c: ret 10h
0x60f20f: push edi
0x60f210: lea eax,[esp+18h]
0x60f214: push eax
0x60f215: mov ecx,esi
0x60f217: call 0060F630h
0x60f21c: mov edx,[eax]
0x60f21e: mov ecx,[ebp+8]
0x60f221: pop edi
0x60f222: mov [ecx],edx
0x60f224: mov eax,[eax+4]
0x60f227: pop esi
0x60f228: mov [ecx+4],eax
0x60f22b: mov eax,ecx
0x60f22d: pop ebx
0x60f22e: mov esp,ebp
0x60f230: pop ebp
0x60f231: ret 10h
````

`sub_60f020` is called by sub_60ec50. It delegates to sub_40c260, sub_60f520, sub_60f5c0 (6 callees).

### sub_60f240 at 0x60f240 (27 instructions)

````text
0x60f240: push ebp
0x60f241: mov ebp,esp
0x60f243: and esp,0FFFFFFF8h
0x60f246: sub esp,0Ch
0x60f249: push esi
0x60f24a: mov esi,ecx
0x60f24c: mov eax,[esi+4]
0x60f24f: mov ecx,[eax]
0x60f251: push eax
0x60f252: push esi
0x60f253: push ecx
0x60f254: push esi
0x60f255: lea eax,[esp+18h]
0x60f259: push eax
0x60f25a: mov ecx,esi
0x60f25c: call 0060F730h
0x60f261: mov ecx,[esi+4]
0x60f264: push ecx
0x60f265: call 006516BAh
0x60f26a: add esp,4
0x60f26d: xor eax,eax
0x60f26f: mov [esi+4],eax
0x60f272: mov [esi+8],eax
0x60f275: pop esi
0x60f276: mov esp,ebp
0x60f278: pop ebp
0x60f279: ret
````

`sub_60f240` is called by sub_60d680. It delegates to sub_60f730, j_ORDINAL 764 (2 callees).

### sub_60f280 at 0x60f280 (192 instructions)

````text
0x60f280: sub esp,10h
0x60f283: push ebx
0x60f284: push ebp
0x60f285: mov ebp,[esp+1Ch]
0x60f289: push esi
0x60f28a: push edi
0x60f28b: mov edi,ecx
0x60f28d: cmp dword ptr [edi+8],0
0x60f291: mov ebx,eax
0x60f293: jne short 0060F2ADh
0x60f295: mov ecx,[edi+4]
0x60f298: push ebx
0x60f299: push 1
0x60f29b: push ebp
0x60f29c: call 0060FC20h
0x60f2a1: mov eax,ebp
0x60f2a3: pop edi
0x60f2a4: pop esi
0x60f2a5: pop ebp
0x60f2a6: pop ebx
0x60f2a7: add esp,10h
0x60f2aa: ret 0Ch
0x60f2ad: mov eax,[edi+4]
0x60f2b0: mov ecx,[eax]
0x60f2b2: mov eax,[esp+28h]
0x60f2b6: test eax,eax
0x60f2b8: mov [esp+18h],ecx
0x60f2bc: je short 0060F2C2h
0x60f2be: cmp eax,edi
0x60f2c0: je short 0060F2C8h
0x60f2c2: call dword ptr ds:[77D0E4h]
0x60f2c8: mov esi,[esp+2Ch]
0x60f2cc: cmp esi,[esp+18h]
0x60f2d0: jne short 0060F2FFh
0x60f2d2: lea edx,[esi+0Ch]
0x60f2d5: push edx
0x60f2d6: push ebx
0x60f2d7: call dword ptr ds:[77CDA0h]
0x60f2dd: add esp,8
0x60f2e0: test al,al
0x60f2e2: je near ptr 0060F44Ah
0x60f2e8: push ebx
0x60f2e9: push 1
0x60f2eb: push ebp
0x60f2ec: mov ecx,esi
0x60f2ee: call 0060FC20h
0x60f2f3: mov eax,ebp
0x60f2f5: pop edi
0x60f2f6: pop esi
0x60f2f7: pop ebp
0x60f2f8: pop ebx
0x60f2f9: add esp,10h
0x60f2fc: ret 0Ch
0x60f2ff: mov eax,[edi+4]
0x60f302: mov [esp+18h],eax
0x60f306: mov eax,[esp+28h]
0x60f30a: test eax,eax
0x60f30c: je short 0060F312h
0x60f30e: cmp eax,edi
0x60f310: je short 0060F318h
0x60f312: call dword ptr ds:[77D0E4h]
0x60f318: cmp esi,[esp+18h]
0x60f31c: jne short 0060F355h
0x60f31e: mov ecx,[edi+4]
0x60f321: mov eax,[ecx+8]
0x60f324: add eax,0Ch
0x60f327: push ebx
0x60f328: push eax
0x60f329: call dword ptr ds:[77CDA0h]
0x60f32f: add esp,8
0x60f332: test al,al
0x60f334: je near ptr 0060F44Ah
0x60f33a: mov edx,[edi+4]
0x60f33d: mov ecx,[edx+8]
0x60f340: push ebx
0x60f341: push 0
0x60f343: push ebp
0x60f344: call 0060FC20h
0x60f349: mov eax,ebp
0x60f34b: pop edi
0x60f34c: pop esi
0x60f34d: pop ebp
0x60f34e: pop ebx
0x60f34f: add esp,10h
0x60f352: ret 0Ch
0x60f355: lea eax,[esi+0Ch]
0x60f358: push eax
0x60f359: push ebx
0x60f35a: call dword ptr ds:[77CDA0h]
0x60f360: add esp,8
0x60f363: test al,al
0x60f365: je short 0060F3CCh
0x60f367: mov eax,[esp+28h]
0x60f36b: mov [esp+18h],esi
0x60f36f: lea esi,[esp+14h]
0x60f373: mov [esp+14h],eax
0x60f377: call 00610800h
0x60f37c: mov esi,[esp+18h]
0x60f380: push ebx
0x60f381: lea ecx,[esi+0Ch]
0x60f384: push ecx
0x60f385: mov ecx,edi
0x60f387: call 0040C260h
0x60f38c: test al,al
0x60f38e: je short 0060F3C8h
0x60f390: mov edx,[esi+8]
0x60f393: cmp byte ptr [edx+45h],0
0x60f397: push ebx
0x60f398: je short 0060F3B0h
0x60f39a: push 0
0x60f39c: push ebp
0x60f39d: mov ecx,esi
0x60f39f: call 0060FC20h
0x60f3a4: mov eax,ebp
0x60f3a6: pop edi
0x60f3a7: pop esi
0x60f3a8: pop ebp
0x60f3a9: pop ebx
0x60f3aa: add esp,10h
0x60f3ad: ret 0Ch
0x60f3b0: mov ecx,[esp+30h]
0x60f3b4: push 1
0x60f3b6: push ebp
0x60f3b7: call 0060FC20h
0x60f3bc: mov eax,ebp
0x60f3be: pop edi
0x60f3bf: pop esi
0x60f3c0: pop ebp
0x60f3c1: pop ebx
0x60f3c2: add esp,10h
0x60f3c5: ret 0Ch
0x60f3c8: mov esi,[esp+2Ch]
0x60f3cc: lea eax,[esi+0Ch]
0x60f3cf: push ebx
0x60f3d0: push eax
0x60f3d1: call dword ptr ds:[77CDA0h]
0x60f3d7: add esp,8
0x60f3da: test al,al
0x60f3dc: je short 0060F44Ah
0x60f3de: mov ecx,[edi+4]
0x60f3e1: mov eax,[esp+28h]
0x60f3e5: mov [esp+2Ch],ecx
0x60f3e9: lea ecx,[esp+14h]
0x60f3ed: mov [esp+14h],eax
0x60f3f1: mov [esp+18h],esi
0x60f3f5: mov [esp+28h],edi
0x60f3f9: call 0060F550h
0x60f3fe: lea edx,[esp+28h]
0x60f402: push edx
0x60f403: lea ecx,[esp+18h]
0x60f407: call 0060F520h
0x60f40c: test al,al
0x60f40e: jne short 0060F424h
0x60f410: mov eax,[esp+18h]
0x60f414: add eax,0Ch
0x60f417: push eax
0x60f418: push ebx
0x60f419: mov ecx,edi
0x60f41b: call 0040C260h
0x60f420: test al,al
0x60f422: je short 0060F44Ah
0x60f424: mov ecx,[esi+8]
0x60f427: cmp byte ptr [ecx+45h],0
0x60f42b: push ebx
0x60f42c: jne near ptr 0060F39Ah
0x60f432: mov ecx,[esp+1Ch]
0x60f436: push 1
0x60f438: push ebp
0x60f439: call 0060FC20h
0x60f43e: mov eax,ebp
0x60f440: pop edi
0x60f441: pop esi
0x60f442: pop ebp
0x60f443: pop ebx
0x60f444: add esp,10h
0x60f447: ret 0Ch
0x60f44a: push ebx
0x60f44b: lea edx,[esp+18h]
0x60f44f: push edx
0x60f450: mov ebx,edi
0x60f452: call 0060FA40h
0x60f457: mov ecx,[eax]
0x60f459: pop edi
0x60f45a: mov [ebp],ecx
0x60f45d: mov edx,[eax+4]
0x60f460: pop esi
0x60f461: mov [ebp+4],edx
0x60f464: mov eax,ebp
0x60f466: pop ebp
0x60f467: pop ebx
0x60f468: add esp,10h
0x60f46b: ret 0Ch
````

`sub_60f280` is called by sub_60ed90. It delegates to sub_40c260, sub_60f520, sub_60f550 (6 callees).

### sub_60f470 at 0x60f470 (27 instructions)

````text
0x60f470: push ebp
0x60f471: mov ebp,esp
0x60f473: and esp,0FFFFFFF8h
0x60f476: sub esp,0Ch
0x60f479: push esi
0x60f47a: mov esi,ecx
0x60f47c: mov eax,[esi+4]
0x60f47f: mov ecx,[eax]
0x60f481: push eax
0x60f482: push esi
0x60f483: push ecx
0x60f484: push esi
0x60f485: lea eax,[esp+18h]
0x60f489: push eax
0x60f48a: mov ecx,esi
0x60f48c: call 0060FB40h
0x60f491: mov ecx,[esi+4]
0x60f494: push ecx
0x60f495: call 006516BAh
0x60f49a: add esp,4
0x60f49d: xor eax,eax
0x60f49f: mov [esi+4],eax
0x60f4a2: mov [esi+8],eax
0x60f4a5: pop esi
0x60f4a6: mov esp,ebp
0x60f4a8: pop ebp
0x60f4a9: ret
````

`sub_60f470` is called by sub_60d680, sub_610c30. It delegates to sub_60fb40, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@VColorScheme@@@serialization@boost@@CAAAVColorScheme@@XZ at 0x60f4b0 (26 instructions)

````text
0x60f4b0: push 0FFFFFFFFh
0x60f4b2: push 75457Eh
0x60f4b7: mov eax,fs:[0]
0x60f4bd: push eax
0x60f4be: mov eax,ds:[858220h]
0x60f4c3: push ecx
0x60f4c4: xor eax,esp
0x60f4c6: push eax
0x60f4c7: lea eax,[esp+8]
0x60f4cb: mov fs:[0],eax
0x60f4d1: mov eax,1
0x60f4d6: test ds:[875EB8h],al
0x60f4dc: jne short 0060F503h
0x60f4de: or ds:[875EB8h],eax
0x60f4e4: push 875D50h
0x60f4e9: mov dword ptr [esp+14h],0
0x60f4f1: call 0060B550h
0x60f4f6: push 77B4C0h
0x60f4fb: call 006527EDh
0x60f500: add esp,4
0x60f503: mov eax,875D50h
0x60f508: mov ecx,[esp+8]
0x60f50c: mov fs:[0],ecx
0x60f513: pop ecx
0x60f514: add esp,10h
0x60f517: ret
````

`?get_instance@?$singleton@VColorScheme@@@serialization@boost@@CAAAVColorScheme@@XZ` is called by ?get_mutable_instance@?$singleton@VColorScheme@@@serialization@boost@@SAAAVColorScheme@@XZ. It delegates to sub_60b550, sub_6527ed (2 callees).

### sub_60f520 at 0x60f520 (18 instructions)

````text
0x60f520: push esi
0x60f521: mov esi,ecx
0x60f523: mov eax,[esi]
0x60f525: test eax,eax
0x60f527: push edi
0x60f528: mov edi,[esp+0Ch]
0x60f52c: je short 0060F532h
0x60f52e: cmp eax,[edi]
0x60f530: je short 0060F538h
0x60f532: call dword ptr ds:[77D0E4h]
0x60f538: mov eax,[esi+4]
0x60f53b: xor ecx,ecx
0x60f53d: cmp eax,[edi+4]
0x60f540: pop edi
0x60f541: sete cl
0x60f544: mov al,cl
0x60f546: pop esi
0x60f547: ret 4
````

`sub_60f520` is called by sub_60f020, sub_60f280. It calls nothing else.

### sub_60f550 at 0x60f550 (44 instructions)

````text
0x60f550: push esi
0x60f551: mov esi,ecx
0x60f553: cmp dword ptr [esi],0
0x60f556: push edi
0x60f557: mov edi,ds:[77D0E4h]
0x60f55d: jne short 0060F561h
0x60f55f: call edi
0x60f561: mov eax,[esi+4]
0x60f564: cmp byte ptr [eax+45h],0
0x60f568: je short 0060F56Fh
0x60f56a: call edi
0x60f56c: pop edi
0x60f56d: pop esi
0x60f56e: ret
0x60f56f: mov ecx,[eax+8]
0x60f572: cmp byte ptr [ecx+45h],0
0x60f576: jne short 0060F590h
0x60f578: mov eax,[ecx]
0x60f57a: cmp byte ptr [eax+45h],0
0x60f57e: jne short 0060F58Ah
0x60f580: mov ecx,eax
0x60f582: mov eax,[ecx]
0x60f584: cmp byte ptr [eax+45h],0
0x60f588: je short 0060F580h
0x60f58a: pop edi
0x60f58b: mov [esi+4],ecx
0x60f58e: pop esi
0x60f58f: ret
0x60f590: mov eax,[eax+4]
0x60f593: cmp byte ptr [eax+45h],0
0x60f597: jne short 0060F5B6h
0x60f599: lea esp,[esp]
0x60f5a0: mov ecx,[esi+4]
0x60f5a3: cmp ecx,[eax+8]
0x60f5a6: jne short 0060F5B6h
0x60f5a8: mov [esi+4],eax
0x60f5ab: mov edx,eax
0x60f5ad: mov eax,[edx+4]
0x60f5b0: cmp byte ptr [eax+45h],0
0x60f5b4: je short 0060F5A0h
0x60f5b6: pop edi
0x60f5b7: mov [esi+4],eax
0x60f5ba: pop esi
0x60f5bb: ret
````

`sub_60f550` is called by sub_60f280, sub_60fb40, sub_6102c0. It calls nothing else.

### sub_60f5c0 at 0x60f5c0 (44 instructions)

````text
0x60f5c0: push esi
0x60f5c1: mov esi,ecx
0x60f5c3: cmp dword ptr [esi],0
0x60f5c6: push edi
0x60f5c7: mov edi,ds:[77D0E4h]
0x60f5cd: jne short 0060F5D1h
0x60f5cf: call edi
0x60f5d1: mov eax,[esi+4]
0x60f5d4: cmp byte ptr [eax+2Dh],0
0x60f5d8: je short 0060F5DFh
0x60f5da: call edi
0x60f5dc: pop edi
0x60f5dd: pop esi
0x60f5de: ret
0x60f5df: mov ecx,[eax+8]
0x60f5e2: cmp byte ptr [ecx+2Dh],0
0x60f5e6: jne short 0060F600h
0x60f5e8: mov eax,[ecx]
0x60f5ea: cmp byte ptr [eax+2Dh],0
0x60f5ee: jne short 0060F5FAh
0x60f5f0: mov ecx,eax
0x60f5f2: mov eax,[ecx]
0x60f5f4: cmp byte ptr [eax+2Dh],0
0x60f5f8: je short 0060F5F0h
0x60f5fa: pop edi
0x60f5fb: mov [esi+4],ecx
0x60f5fe: pop esi
0x60f5ff: ret
0x60f600: mov eax,[eax+4]
0x60f603: cmp byte ptr [eax+2Dh],0
0x60f607: jne short 0060F626h
0x60f609: lea esp,[esp]
0x60f610: mov ecx,[esi+4]
0x60f613: cmp ecx,[eax+8]
0x60f616: jne short 0060F626h
0x60f618: mov [esi+4],eax
0x60f61b: mov edx,eax
0x60f61d: mov eax,[edx+4]
0x60f620: cmp byte ptr [eax+2Dh],0
0x60f624: je short 0060F610h
0x60f626: pop edi
0x60f627: mov [esi+4],eax
0x60f62a: pop esi
0x60f62b: ret
````

`sub_60f5c0` is called by sub_60f020, sub_60f730, sub_60fe40. It calls nothing else.

### sub_60f630 at 0x60f630 (101 instructions)

````text
0x60f630: push ebp
0x60f631: mov ebp,esp
0x60f633: and esp,0FFFFFFF8h
0x60f636: sub esp,0Ch
0x60f639: push ebx
0x60f63a: push esi
0x60f63b: mov ebx,ecx
0x60f63d: push edi
0x60f63e: mov edi,[ebx+4]
0x60f641: mov esi,[edi+4]
0x60f644: cmp byte ptr [esi+2Dh],0
0x60f648: mov al,1
0x60f64a: mov [esp+0Ch],al
0x60f64e: jne short 0060F678h
0x60f650: mov ecx,[ebp+0Ch]
0x60f653: lea eax,[esi+0Ch]
0x60f656: push eax
0x60f657: push ecx
0x60f658: mov edi,esi
0x60f65a: call dword ptr ds:[77CDA0h]
0x60f660: add esp,8
0x60f663: test al,al
0x60f665: mov [esp+0Ch],al
0x60f669: je short 0060F66Fh
0x60f66b: mov esi,[esi]
0x60f66d: jmp short 0060F672h
0x60f66f: mov esi,[esi+8]
0x60f672: cmp byte ptr [esi+2Dh],0
0x60f676: je short 0060F650h
0x60f678: test al,al
0x60f67a: mov esi,edi
0x60f67c: mov [esp+14h],esi
0x60f680: mov [esp+10h],ebx
0x60f684: je short 0060F6C5h
0x60f686: mov edx,[ebx+4]
0x60f689: cmp edi,[edx]
0x60f68b: lea ecx,[esp+10h]
0x60f68f: jne short 0060F6BCh
0x60f691: mov eax,[ebp+0Ch]
0x60f694: push eax
0x60f695: push edi
0x60f696: push 1
0x60f698: push ecx
0x60f699: mov ecx,ebx
0x60f69b: call 0060F810h
0x60f6a0: mov ecx,eax
0x60f6a2: mov edx,[ecx]
0x60f6a4: mov eax,[ebp+8]
0x60f6a7: mov ecx,[ecx+4]
0x60f6aa: mov [eax],edx
0x60f6ac: mov [eax+4],ecx
0x60f6af: mov byte ptr [eax+8],1
0x60f6b3: pop edi
0x60f6b4: pop esi
0x60f6b5: pop ebx
0x60f6b6: mov esp,ebp
0x60f6b8: pop ebp
0x60f6b9: ret 8
0x60f6bc: call 00610890h
0x60f6c1: mov esi,[esp+14h]
0x60f6c5: mov edx,[ebp+0Ch]
0x60f6c8: push edx
0x60f6c9: lea eax,[esi+0Ch]
0x60f6cc: push eax
0x60f6cd: call dword ptr ds:[77CDA0h]
0x60f6d3: add esp,8
0x60f6d6: test al,al
0x60f6d8: je short 0060F70Ch
0x60f6da: mov ecx,[ebp+0Ch]
0x60f6dd: mov edx,[esp+0Ch]
0x60f6e1: push ecx
0x60f6e2: push edi
0x60f6e3: push edx
0x60f6e4: lea eax,[esp+1Ch]
0x60f6e8: push eax
0x60f6e9: mov ecx,ebx
0x60f6eb: call 0060F810h
0x60f6f0: mov edx,[eax]
0x60f6f2: mov ecx,[ebp+8]
0x60f6f5: mov eax,[eax+4]
0x60f6f8: mov [ecx+4],eax
0x60f6fb: mov [ecx],edx
0x60f6fd: mov byte ptr [ecx+8],1
0x60f701: mov eax,ecx
0x60f703: pop edi
0x60f704: pop esi
0x60f705: pop ebx
0x60f706: mov esp,ebp
0x60f708: pop ebp
0x60f709: ret 8
0x60f70c: mov eax,[ebp+8]
0x60f70f: mov ecx,[esp+10h]
0x60f713: pop edi
0x60f714: mov [eax+4],esi
0x60f717: pop esi
0x60f718: mov [eax],ecx
0x60f71a: mov byte ptr [eax+8],0
0x60f71e: pop ebx
0x60f71f: mov esp,ebp
0x60f721: pop ebp
0x60f722: ret 8
````

`sub_60f630` is called by sub_60f020. It delegates to sub_60f810, sub_610890 (2 callees).

### sub_60f730 at 0x60f730 (81 instructions)

````text
0x60f730: push ebp
0x60f731: mov ebp,esp
0x60f733: and esp,0FFFFFFF8h
0x60f736: sub esp,0Ch
0x60f739: push ebx
0x60f73a: push esi
0x60f73b: mov esi,ecx
0x60f73d: mov eax,[esi+4]
0x60f740: mov ecx,[eax]
0x60f742: push edi
0x60f743: mov edi,[ebp+0Ch]
0x60f746: test edi,edi
0x60f748: mov [esp+14h],ecx
0x60f74c: je short 0060F752h
0x60f74e: cmp edi,esi
0x60f750: je short 0060F758h
0x60f752: call dword ptr ds:[77D0E4h]
0x60f758: mov ebx,[ebp+10h]
0x60f75b: cmp ebx,[esp+14h]
0x60f75f: jne short 0060F7C0h
0x60f761: mov eax,[ebp+14h]
0x60f764: test eax,eax
0x60f766: mov edx,[esi+4]
0x60f769: mov [esp+14h],edx
0x60f76d: je short 0060F773h
0x60f76f: cmp eax,esi
0x60f771: je short 0060F779h
0x60f773: call dword ptr ds:[77D0E4h]
0x60f779: mov eax,[ebp+18h]
0x60f77c: cmp eax,[esp+14h]
0x60f780: jne short 0060F7C0h
0x60f782: mov ecx,[esi+4]
0x60f785: mov edx,[ecx+4]
0x60f788: push edx
0x60f789: mov ecx,esi
0x60f78b: call 00573610h
0x60f790: mov eax,[esi+4]
0x60f793: mov [eax+4],eax
0x60f796: mov eax,[esi+4]
0x60f799: mov dword ptr [esi+8],0
0x60f7a0: mov [eax],eax
0x60f7a2: mov eax,[esi+4]
0x60f7a5: mov [eax+8],eax
0x60f7a8: mov eax,[esi+4]
0x60f7ab: mov ecx,[eax]
0x60f7ad: mov eax,[ebp+8]
0x60f7b0: mov [eax+4],ecx
0x60f7b3: mov [eax],esi
0x60f7b5: pop edi
0x60f7b6: pop esi
0x60f7b7: pop ebx
0x60f7b8: mov esp,ebp
0x60f7ba: pop ebp
0x60f7bb: ret 14h
0x60f7c0: test edi,edi
0x60f7c2: je short 0060F7C9h
0x60f7c4: cmp edi,[ebp+14h]
0x60f7c7: je short 0060F7CFh
0x60f7c9: call dword ptr ds:[77D0E4h]
0x60f7cf: cmp ebx,[ebp+18h]
0x60f7d2: je short 0060F7F2h
0x60f7d4: lea ecx,[ebp+0Ch]
0x60f7d7: call 0060F5C0h
0x60f7dc: push ebx
0x60f7dd: push edi
0x60f7de: lea edx,[esp+18h]
0x60f7e2: push edx
0x60f7e3: mov ecx,esi
0x60f7e5: call 0060FE40h
0x60f7ea: mov ebx,[ebp+10h]
0x60f7ed: mov edi,[ebp+0Ch]
0x60f7f0: jmp short 0060F7C0h
0x60f7f2: mov eax,[ebp+8]
0x60f7f5: mov [eax],edi
0x60f7f7: pop edi
0x60f7f8: pop esi
0x60f7f9: mov [eax+4],ebx
0x60f7fc: pop ebx
0x60f7fd: mov esp,ebp
0x60f7ff: pop ebp
0x60f800: ret 14h
````

`sub_60f730` is called by sub_60f240. It delegates to sub_573610, sub_60f5c0, sub_60fe40 (3 callees).

### sub_60f810 at 0x60f810 (152 instructions)

````text
0x60f810: push ebp
0x60f811: mov ebp,esp
0x60f813: and esp,0FFFFFFF8h
0x60f816: push 0FFFFFFFFh
0x60f818: push 73EDF9h
0x60f81d: mov eax,fs:[0]
0x60f823: push eax
0x60f824: sub esp,50h
0x60f827: push ebx
0x60f828: push esi
0x60f829: push edi
0x60f82a: mov eax,ds:[858220h]
0x60f82f: xor eax,esp
0x60f831: push eax
0x60f832: lea eax,[esp+60h]
0x60f836: mov fs:[0],eax
0x60f83c: mov edi,ecx
0x60f83e: cmp dword ptr [edi+8],7FFFFFEh
0x60f845: jb short 0060F883h
0x60f847: push 7C5AD8h
0x60f84c: lea ecx,[esp+1Ch]
0x60f850: call dword ptr ds:[77CD7Ch]
0x60f856: lea eax,[esp+18h]
0x60f85a: push eax
0x60f85b: lea ecx,[esp+38h]
0x60f85f: mov dword ptr [esp+6Ch],0
0x60f867: call 00401230h
0x60f86c: push 80A274h
0x60f871: lea ecx,[esp+38h]
0x60f875: push ecx
0x60f876: mov dword ptr [esp+3Ch],78FFECh
0x60f87e: call 00652AC4h
0x60f883: mov edx,[ebp+14h]
0x60f886: mov eax,[edi+4]
0x60f889: mov esi,[ebp+10h]
0x60f88c: push 0
0x60f88e: push edx
0x60f88f: push eax
0x60f890: push esi
0x60f891: push eax
0x60f892: call 00610210h
0x60f897: mov ecx,eax
0x60f899: mov eax,[edi+4]
0x60f89c: mov ebx,1
0x60f8a1: add [edi+8],ebx
0x60f8a4: cmp esi,eax
0x60f8a6: mov [esp+14h],ecx
0x60f8aa: jne short 0060F8BCh
0x60f8ac: mov [eax+4],ecx
0x60f8af: mov eax,[edi+4]
0x60f8b2: mov [eax],ecx
0x60f8b4: mov edx,[edi+4]
0x60f8b7: mov [edx+8],ecx
0x60f8ba: jmp short 0060F8DDh
0x60f8bc: cmp byte ptr [ebp+0Ch],0
0x60f8c0: je short 0060F8CFh
0x60f8c2: mov [esi],ecx
0x60f8c4: mov eax,[edi+4]
0x60f8c7: cmp esi,[eax]
0x60f8c9: jne short 0060F8DDh
0x60f8cb: mov [eax],ecx
0x60f8cd: jmp short 0060F8DDh
0x60f8cf: mov [esi+8],ecx
0x60f8d2: mov eax,[edi+4]
0x60f8d5: cmp esi,[eax+8]
0x60f8d8: jne short 0060F8DDh
0x60f8da: mov [eax+8],ecx
0x60f8dd: mov edx,[ecx+4]
0x60f8e0: cmp byte ptr [edx+2Ch],0
0x60f8e4: lea eax,[ecx+4]
0x60f8e7: mov esi,ecx
0x60f8e9: jne near ptr 0060F9A5h
0x60f8ef: nop
0x60f8f0: mov ecx,[eax]
0x60f8f2: mov edx,[ecx+4]
0x60f8f5: cmp ecx,[edx]
0x60f8f7: jne short 0060F947h
0x60f8f9: mov edx,[edx+8]
0x60f8fc: cmp byte ptr [edx+2Ch],0
0x60f900: jne short 0060F918h
0x60f902: mov [ecx+2Ch],bl
0x60f905: mov [edx+2Ch],bl
0x60f908: mov edx,[eax]
0x60f90a: mov ecx,[edx+4]
0x60f90d: mov byte ptr [ecx+2Ch],0
0x60f911: mov edx,[eax]
0x60f913: mov esi,[edx+4]
0x60f916: jmp short 0060F991h
0x60f918: cmp esi,[ecx+8]
0x60f91b: jne short 0060F927h
0x60f91d: mov esi,ecx
0x60f91f: push esi
0x60f920: mov ecx,edi
0x60f922: call 00610120h
0x60f927: mov eax,[esi+4]
0x60f92a: mov [eax+2Ch],bl
0x60f92d: mov ecx,[esi+4]
0x60f930: mov edx,[ecx+4]
0x60f933: mov byte ptr [edx+2Ch],0
0x60f937: mov eax,[esi+4]
0x60f93a: mov ecx,[eax+4]
0x60f93d: push ecx
0x60f93e: mov ecx,edi
0x60f940: call 00610170h
0x60f945: jmp short 0060F991h
0x60f947: mov edx,[edx]
0x60f949: cmp byte ptr [edx+2Ch],0
0x60f94d: jne short 0060F965h
0x60f94f: mov [ecx+2Ch],bl
0x60f952: mov [edx+2Ch],bl
0x60f955: mov edx,[eax]
0x60f957: mov ecx,[edx+4]
0x60f95a: mov byte ptr [ecx+2Ch],0
0x60f95e: mov edx,[eax]
0x60f960: mov esi,[edx+4]
0x60f963: jmp short 0060F991h
0x60f965: cmp esi,[ecx]
0x60f967: jne short 0060F973h
0x60f969: mov esi,ecx
0x60f96b: push esi
0x60f96c: mov ecx,edi
0x60f96e: call 00610170h
0x60f973: mov eax,[esi+4]
0x60f976: mov [eax+2Ch],bl
0x60f979: mov ecx,[esi+4]
0x60f97c: mov edx,[ecx+4]
0x60f97f: mov byte ptr [edx+2Ch],0
0x60f983: mov eax,[esi+4]
0x60f986: mov ecx,[eax+4]
0x60f989: push ecx
0x60f98a: mov ecx,edi
0x60f98c: call 00610120h
0x60f991: mov edx,[esi+4]
0x60f994: cmp byte ptr [edx+2Ch],0
0x60f998: lea eax,[esi+4]
0x60f99b: je near ptr 0060F8F0h
0x60f9a1: mov ecx,[esp+14h]
0x60f9a5: mov eax,[edi+4]
0x60f9a8: mov edx,[eax+4]
0x60f9ab: mov eax,[ebp+8]
0x60f9ae: mov [edx+2Ch],bl
0x60f9b1: mov [eax+4],ecx
0x60f9b4: mov [eax],edi
0x60f9b6: mov ecx,[esp+60h]
0x60f9ba: mov fs:[0],ecx
0x60f9c1: pop ecx
0x60f9c2: pop edi
0x60f9c3: pop esi
0x60f9c4: pop ebx
0x60f9c5: mov esp,ebp
0x60f9c7: pop ebp
0x60f9c8: ret 10h
````

`sub_60f810` is called by sub_60f020, sub_60f630. It delegates to sub_401230, sub_610120, sub_610170 (5 callees).

### sub_60f9d0 at 0x60f9d0 (31 instructions)

````text
0x60f9d0: mov eax,[ecx+4]
0x60f9d3: push esi
0x60f9d4: mov esi,[eax+4]
0x60f9d7: cmp byte ptr [esi+2Dh],0
0x60f9db: push edi
0x60f9dc: mov edi,eax
0x60f9de: jne short 0060FA11h
0x60f9e0: push ebx
0x60f9e1: mov ebx,[esp+10h]
0x60f9e5: push ebp
0x60f9e6: mov ebp,ds:[77CDA0h]
0x60f9ec: lea esp,[esp]
0x60f9f0: lea eax,[esi+0Ch]
0x60f9f3: push ebx
0x60f9f4: push eax
0x60f9f5: call ebp
0x60f9f7: add esp,8
0x60f9fa: test al,al
0x60f9fc: je short 0060FA03h
0x60f9fe: mov esi,[esi+8]
0x60fa01: jmp short 0060FA07h
0x60fa03: mov edi,esi
0x60fa05: mov esi,[esi]
0x60fa07: cmp byte ptr [esi+2Dh],0
0x60fa0b: je short 0060F9F0h
0x60fa0d: pop ebp
0x60fa0e: mov eax,edi
0x60fa10: pop ebx
0x60fa11: pop edi
0x60fa12: pop esi
0x60fa13: ret 4
````

`sub_60f9d0` is called by sub_60ec50. It calls nothing else.

### sub_60fa20 at 0x60fa20 (10 instructions)

````text
0x60fa20: mov eax,[esp+4]
0x60fa24: mov ecx,[eax]
0x60fa26: cmp byte ptr [ecx+2Dh],0
0x60fa2a: jne short 0060FA3Ah
0x60fa2c: lea esp,[esp]
0x60fa30: mov eax,ecx
0x60fa32: mov ecx,[eax]
0x60fa34: cmp byte ptr [ecx+2Dh],0
0x60fa38: je short 0060FA30h
0x60fa3a: ret
````

`sub_60fa20` is called by sub_60fe40. It calls nothing else.

### sub_60fa40 at 0x60fa40 (95 instructions)

````text
0x60fa40: sub esp,10h
0x60fa43: push ebp
0x60fa44: mov ebp,[esp+18h]
0x60fa48: push esi
0x60fa49: push edi
0x60fa4a: mov edi,[ebx+4]
0x60fa4d: mov esi,[edi+4]
0x60fa50: cmp byte ptr [esi+45h],0
0x60fa54: mov al,1
0x60fa56: mov [esp+20h],al
0x60fa5a: jne short 0060FA89h
0x60fa5c: lea esp,[esp]
0x60fa60: mov ecx,[esp+24h]
0x60fa64: lea eax,[esi+0Ch]
0x60fa67: push eax
0x60fa68: push ecx
0x60fa69: mov edi,esi
0x60fa6b: call dword ptr ds:[77CDA0h]
0x60fa71: add esp,8
0x60fa74: test al,al
0x60fa76: mov [esp+20h],al
0x60fa7a: je short 0060FA80h
0x60fa7c: mov esi,[esi]
0x60fa7e: jmp short 0060FA83h
0x60fa80: mov esi,[esi+8]
0x60fa83: cmp byte ptr [esi+45h],0
0x60fa87: je short 0060FA60h
0x60fa89: test al,al
0x60fa8b: mov esi,edi
0x60fa8d: mov [esp+14h],esi
0x60fa91: mov [esp+10h],ebx
0x60fa95: je short 0060FADAh
0x60fa97: mov edx,[ebx+4]
0x60fa9a: cmp edi,[edx]
0x60fa9c: jne short 0060FACDh
0x60fa9e: mov eax,[esp+24h]
0x60faa2: push eax
0x60faa3: push 1
0x60faa5: lea ecx,[esp+18h]
0x60faa9: push ecx
0x60faaa: mov ecx,edi
0x60faac: mov edi,ebx
0x60faae: call 0060FC20h
0x60fab3: mov edx,[eax]
0x60fab5: mov eax,[eax+4]
0x60fab8: mov [ebp+4],eax
0x60fabb: mov [ebp],edx
0x60fabe: mov byte ptr [ebp+8],1
0x60fac2: mov eax,ebp
0x60fac4: pop edi
0x60fac5: pop esi
0x60fac6: pop ebp
0x60fac7: add esp,10h
0x60faca: ret 8
0x60facd: lea esi,[esp+10h]
0x60fad1: call 00610800h
0x60fad6: mov esi,[esp+14h]
0x60fada: mov ecx,[esp+24h]
0x60fade: push ecx
0x60fadf: lea edx,[esi+0Ch]
0x60fae2: push edx
0x60fae3: call dword ptr ds:[77CDA0h]
0x60fae9: add esp,8
0x60faec: test al,al
0x60faee: je short 0060FB22h
0x60faf0: mov eax,[esp+24h]
0x60faf4: mov ecx,[esp+20h]
0x60faf8: push eax
0x60faf9: push ecx
0x60fafa: lea edx,[esp+18h]
0x60fafe: mov ecx,edi
0x60fb00: push edx
0x60fb01: mov edi,ebx
0x60fb03: call 0060FC20h
0x60fb08: mov ecx,[eax]
0x60fb0a: mov edx,[eax+4]
0x60fb0d: mov [ebp],ecx
0x60fb10: mov [ebp+4],edx
0x60fb13: mov byte ptr [ebp+8],1
0x60fb17: mov eax,ebp
0x60fb19: pop edi
0x60fb1a: pop esi
0x60fb1b: pop ebp
0x60fb1c: add esp,10h
0x60fb1f: ret 8
0x60fb22: mov eax,[esp+10h]
0x60fb26: pop edi
0x60fb27: mov [ebp+4],esi
0x60fb2a: mov [ebp],eax
0x60fb2d: pop esi
0x60fb2e: mov byte ptr [ebp+8],0
0x60fb32: mov eax,ebp
0x60fb34: pop ebp
0x60fb35: add esp,10h
0x60fb38: ret 8
````

`sub_60fa40` is called by sub_60f280. It delegates to sub_60fc20, sub_610800 (2 callees).

### sub_60fb40 at 0x60fb40 (81 instructions)

````text
0x60fb40: push ebp
0x60fb41: mov ebp,esp
0x60fb43: and esp,0FFFFFFF8h
0x60fb46: sub esp,0Ch
0x60fb49: push ebx
0x60fb4a: push esi
0x60fb4b: mov esi,ecx
0x60fb4d: mov eax,[esi+4]
0x60fb50: mov ecx,[eax]
0x60fb52: push edi
0x60fb53: mov edi,[ebp+0Ch]
0x60fb56: test edi,edi
0x60fb58: mov [esp+14h],ecx
0x60fb5c: je short 0060FB62h
0x60fb5e: cmp edi,esi
0x60fb60: je short 0060FB68h
0x60fb62: call dword ptr ds:[77D0E4h]
0x60fb68: mov ebx,[ebp+10h]
0x60fb6b: cmp ebx,[esp+14h]
0x60fb6f: jne short 0060FBD0h
0x60fb71: mov eax,[ebp+14h]
0x60fb74: test eax,eax
0x60fb76: mov edx,[esi+4]
0x60fb79: mov [esp+14h],edx
0x60fb7d: je short 0060FB83h
0x60fb7f: cmp eax,esi
0x60fb81: je short 0060FB89h
0x60fb83: call dword ptr ds:[77D0E4h]
0x60fb89: mov eax,[ebp+18h]
0x60fb8c: cmp eax,[esp+14h]
0x60fb90: jne short 0060FBD0h
0x60fb92: mov ecx,[esi+4]
0x60fb95: mov edx,[ecx+4]
0x60fb98: push edx
0x60fb99: mov ecx,esi
0x60fb9b: call 00610750h
0x60fba0: mov eax,[esi+4]
0x60fba3: mov [eax+4],eax
0x60fba6: mov eax,[esi+4]
0x60fba9: mov dword ptr [esi+8],0
0x60fbb0: mov [eax],eax
0x60fbb2: mov eax,[esi+4]
0x60fbb5: mov [eax+8],eax
0x60fbb8: mov eax,[esi+4]
0x60fbbb: mov ecx,[eax]
0x60fbbd: mov eax,[ebp+8]
0x60fbc0: mov [eax+4],ecx
0x60fbc3: mov [eax],esi
0x60fbc5: pop edi
0x60fbc6: pop esi
0x60fbc7: pop ebx
0x60fbc8: mov esp,ebp
0x60fbca: pop ebp
0x60fbcb: ret 14h
0x60fbd0: test edi,edi
0x60fbd2: je short 0060FBD9h
0x60fbd4: cmp edi,[ebp+14h]
0x60fbd7: je short 0060FBDFh
0x60fbd9: call dword ptr ds:[77D0E4h]
0x60fbdf: cmp ebx,[ebp+18h]
0x60fbe2: je short 0060FC02h
0x60fbe4: lea ecx,[ebp+0Ch]
0x60fbe7: call 0060F550h
0x60fbec: push ebx
0x60fbed: push edi
0x60fbee: lea edx,[esp+18h]
0x60fbf2: push edx
0x60fbf3: mov ecx,esi
0x60fbf5: call 006102C0h
0x60fbfa: mov ebx,[ebp+10h]
0x60fbfd: mov edi,[ebp+0Ch]
0x60fc00: jmp short 0060FBD0h
0x60fc02: mov eax,[ebp+8]
0x60fc05: mov [eax],edi
0x60fc07: pop edi
0x60fc08: pop esi
0x60fc09: mov [eax+4],ebx
0x60fc0c: pop ebx
0x60fc0d: mov esp,ebp
0x60fc0f: pop ebp
0x60fc10: ret 14h
````

`sub_60fb40` is called by sub_60f470. It delegates to sub_60f550, sub_6102c0, sub_610750 (3 callees).

### sub_60fc20 at 0x60fc20 (143 instructions)

````text
0x60fc20: push 0FFFFFFFFh
0x60fc22: push 740349h
0x60fc27: mov eax,fs:[0]
0x60fc2d: push eax
0x60fc2e: sub esp,4Ch
0x60fc31: push ebx
0x60fc32: push ebp
0x60fc33: push esi
0x60fc34: mov eax,ds:[858220h]
0x60fc39: xor eax,esp
0x60fc3b: push eax
0x60fc3c: lea eax,[esp+5Ch]
0x60fc40: mov fs:[0],eax
0x60fc46: mov esi,ecx
0x60fc48: cmp dword ptr [edi+8],4924923h
0x60fc4f: jb short 0060FC8Dh
0x60fc51: push 7C5AD8h
0x60fc56: lea ecx,[esp+18h]
0x60fc5a: call dword ptr ds:[77CD7Ch]
0x60fc60: lea eax,[esp+14h]
0x60fc64: push eax
0x60fc65: lea ecx,[esp+34h]
0x60fc69: mov dword ptr [esp+68h],0
0x60fc71: call 00401230h
0x60fc76: push 80A274h
0x60fc7b: lea ecx,[esp+34h]
0x60fc7f: push ecx
0x60fc80: mov dword ptr [esp+38h],78FFECh
0x60fc88: call 00652AC4h
0x60fc8d: mov edx,[esp+74h]
0x60fc91: mov eax,[edi+4]
0x60fc94: push edx
0x60fc95: push eax
0x60fc96: push esi
0x60fc97: push eax
0x60fc98: call 00610690h
0x60fc9d: mov ebp,eax
0x60fc9f: mov eax,[edi+4]
0x60fca2: mov ebx,1
0x60fca7: add [edi+8],ebx
0x60fcaa: cmp esi,eax
0x60fcac: jne short 0060FCBEh
0x60fcae: mov [eax+4],ebp
0x60fcb1: mov eax,[edi+4]
0x60fcb4: mov [eax],ebp
0x60fcb6: mov ecx,[edi+4]
0x60fcb9: mov [ecx+8],ebp
0x60fcbc: jmp short 0060FCE0h
0x60fcbe: cmp byte ptr [esp+70h],0
0x60fcc3: je short 0060FCD2h
0x60fcc5: mov [esi],ebp
0x60fcc7: mov eax,[edi+4]
0x60fcca: cmp esi,[eax]
0x60fccc: jne short 0060FCE0h
0x60fcce: mov [eax],ebp
0x60fcd0: jmp short 0060FCE0h
0x60fcd2: mov [esi+8],ebp
0x60fcd5: mov eax,[edi+4]
0x60fcd8: cmp esi,[eax+8]
0x60fcdb: jne short 0060FCE0h
0x60fcdd: mov [eax+8],ebp
0x60fce0: mov edx,[ebp+4]
0x60fce3: cmp byte ptr [edx+44h],0
0x60fce7: lea eax,[ebp+4]
0x60fcea: mov esi,ebp
0x60fcec: jne near ptr 0060FDA3h
0x60fcf2: mov ecx,[eax]
0x60fcf4: mov edx,[ecx+4]
0x60fcf7: cmp ecx,[edx]
0x60fcf9: jne short 0060FD49h
0x60fcfb: mov edx,[edx+8]
0x60fcfe: cmp byte ptr [edx+44h],0
0x60fd02: jne short 0060FD1Ah
0x60fd04: mov [ecx+44h],bl
0x60fd07: mov [edx+44h],bl
0x60fd0a: mov edx,[eax]
0x60fd0c: mov ecx,[edx+4]
0x60fd0f: mov byte ptr [ecx+44h],0
0x60fd13: mov edx,[eax]
0x60fd15: mov esi,[edx+4]
0x60fd18: jmp short 0060FD93h
0x60fd1a: cmp esi,[ecx+8]
0x60fd1d: jne short 0060FD29h
0x60fd1f: mov esi,ecx
0x60fd21: push esi
0x60fd22: mov ecx,edi
0x60fd24: call 006105A0h
0x60fd29: mov eax,[esi+4]
0x60fd2c: mov [eax+44h],bl
0x60fd2f: mov ecx,[esi+4]
0x60fd32: mov edx,[ecx+4]
0x60fd35: mov byte ptr [edx+44h],0
0x60fd39: mov eax,[esi+4]
0x60fd3c: mov ecx,[eax+4]
0x60fd3f: push ecx
0x60fd40: mov ecx,edi
0x60fd42: call 006105F0h
0x60fd47: jmp short 0060FD93h
0x60fd49: mov edx,[edx]
0x60fd4b: cmp byte ptr [edx+44h],0
0x60fd4f: jne short 0060FD67h
0x60fd51: mov [ecx+44h],bl
0x60fd54: mov [edx+44h],bl
0x60fd57: mov edx,[eax]
0x60fd59: mov ecx,[edx+4]
0x60fd5c: mov byte ptr [ecx+44h],0
0x60fd60: mov edx,[eax]
0x60fd62: mov esi,[edx+4]
0x60fd65: jmp short 0060FD93h
0x60fd67: cmp esi,[ecx]
0x60fd69: jne short 0060FD75h
0x60fd6b: mov esi,ecx
0x60fd6d: push esi
0x60fd6e: mov ecx,edi
0x60fd70: call 006105F0h
0x60fd75: mov eax,[esi+4]
0x60fd78: mov [eax+44h],bl
0x60fd7b: mov ecx,[esi+4]
0x60fd7e: mov edx,[ecx+4]
0x60fd81: mov byte ptr [edx+44h],0
0x60fd85: mov eax,[esi+4]
0x60fd88: mov ecx,[eax+4]
0x60fd8b: push ecx
0x60fd8c: mov ecx,edi
0x60fd8e: call 006105A0h
0x60fd93: mov edx,[esi+4]
0x60fd96: cmp byte ptr [edx+44h],0
0x60fd9a: lea eax,[esi+4]
0x60fd9d: je near ptr 0060FCF2h
0x60fda3: mov eax,[edi+4]
0x60fda6: mov ecx,[eax+4]
0x60fda9: mov eax,[esp+6Ch]
0x60fdad: mov [ecx+44h],bl
0x60fdb0: mov [eax+4],ebp
0x60fdb3: mov [eax],edi
0x60fdb5: mov ecx,[esp+5Ch]
0x60fdb9: mov fs:[0],ecx
0x60fdc0: pop ecx
0x60fdc1: pop esi
0x60fdc2: pop ebp
0x60fdc3: pop ebx
0x60fdc4: add esp,58h
0x60fdc7: ret 0Ch
````

`sub_60fc20` is called by sub_60f280, sub_60fa40. It delegates to sub_401230, sub_6105a0, sub_6105f0 (5 callees).

### sub_60fdd0 at 0x60fdd0 (31 instructions)

````text
0x60fdd0: mov eax,[ecx+4]
0x60fdd3: push esi
0x60fdd4: mov esi,[eax+4]
0x60fdd7: cmp byte ptr [esi+45h],0
0x60fddb: push edi
0x60fddc: mov edi,eax
0x60fdde: jne short 0060FE11h
0x60fde0: push ebx
0x60fde1: mov ebx,[esp+10h]
0x60fde5: push ebp
0x60fde6: mov ebp,ds:[77CDA0h]
0x60fdec: lea esp,[esp]
0x60fdf0: lea eax,[esi+0Ch]
0x60fdf3: push ebx
0x60fdf4: push eax
0x60fdf5: call ebp
0x60fdf7: add esp,8
0x60fdfa: test al,al
0x60fdfc: je short 0060FE03h
0x60fdfe: mov esi,[esi+8]
0x60fe01: jmp short 0060FE07h
0x60fe03: mov edi,esi
0x60fe05: mov esi,[esi]
0x60fe07: cmp byte ptr [esi+45h],0
0x60fe0b: je short 0060FDF0h
0x60fe0d: pop ebp
0x60fe0e: mov eax,edi
0x60fe10: pop ebx
0x60fe11: pop edi
0x60fe12: pop esi
0x60fe13: ret 4
````

`sub_60fdd0` is called by sub_60ed90. It calls nothing else.

### sub_60fe20 at 0x60fe20 (10 instructions)

````text
0x60fe20: mov eax,[esp+4]
0x60fe24: mov ecx,[eax]
0x60fe26: cmp byte ptr [ecx+45h],0
0x60fe2a: jne short 0060FE3Ah
0x60fe2c: lea esp,[esp]
0x60fe30: mov eax,ecx
0x60fe32: mov ecx,[eax]
0x60fe34: cmp byte ptr [ecx+45h],0
0x60fe38: je short 0060FE30h
0x60fe3a: ret
````

`sub_60fe20` is called by sub_6102c0. It calls nothing else.

### sub_60fe40 at 0x60fe40 (244 instructions)

````text
0x60fe40: push ebp
0x60fe41: mov ebp,esp
0x60fe43: and esp,0FFFFFFF8h
0x60fe46: push 0FFFFFFFFh
0x60fe48: push 7437B9h
0x60fe4d: mov eax,fs:[0]
0x60fe53: push eax
0x60fe54: sub esp,58h
0x60fe57: push ebx
0x60fe58: push esi
0x60fe59: push edi
0x60fe5a: mov eax,ds:[858220h]
0x60fe5f: xor eax,esp
0x60fe61: push eax
0x60fe62: lea eax,[esp+68h]
0x60fe66: mov fs:[0],eax
0x60fe6c: mov [esp+14h],ecx
0x60fe70: mov eax,[ebp+10h]
0x60fe73: cmp byte ptr [eax+2Dh],0
0x60fe77: je short 0060FEB5h
0x60fe79: push 7C5AECh
0x60fe7e: lea ecx,[esp+24h]
0x60fe82: call dword ptr ds:[77CD7Ch]
0x60fe88: lea eax,[esp+20h]
0x60fe8c: push eax
0x60fe8d: lea ecx,[esp+40h]
0x60fe91: mov dword ptr [esp+74h],0
0x60fe99: call 00401230h
0x60fe9e: push 80A4F8h
0x60fea3: lea ecx,[esp+40h]
0x60fea7: push ecx
0x60fea8: mov dword ptr [esp+44h],790F90h
0x60feb0: call 00652AC4h
0x60feb5: mov ebx,eax
0x60feb7: lea ecx,[ebp+0Ch]
0x60feba: mov [esp+18h],ebx
0x60febe: call 0060F5C0h
0x60fec3: mov eax,[ebx]
0x60fec5: cmp byte ptr [eax+2Dh],0
0x60fec9: je short 0060FED0h
0x60fecb: mov edi,[ebx+8]
0x60fece: jmp short 0060FEE7h
0x60fed0: mov edx,[ebx+8]
0x60fed3: cmp byte ptr [edx+2Dh],0
0x60fed7: je short 0060FEDDh
0x60fed9: mov edi,eax
0x60fedb: jmp short 0060FEE7h
0x60fedd: mov ecx,[ebp+10h]
0x60fee0: cmp ecx,ebx
0x60fee2: mov edi,[ecx+8]
0x60fee5: jne short 0060FF5Dh
0x60fee7: cmp byte ptr [edi+2Dh],0
0x60feeb: mov esi,[ebx+4]
0x60feee: jne short 0060FEF3h
0x60fef0: mov [edi+4],esi
0x60fef3: mov ecx,[esp+14h]
0x60fef7: mov eax,[ecx+4]
0x60fefa: cmp [eax+4],ebx
0x60fefd: jne short 0060FF04h
0x60feff: mov [eax+4],edi
0x60ff02: jmp short 0060FF0Fh
0x60ff04: cmp [esi],ebx
0x60ff06: jne short 0060FF0Ch
0x60ff08: mov [esi],edi
0x60ff0a: jmp short 0060FF0Fh
0x60ff0c: mov [esi+8],edi
0x60ff0f: mov eax,[ecx+4]
0x60ff12: cmp [eax],ebx
0x60ff14: jne short 0060FF32h
0x60ff16: cmp byte ptr [edi+2Dh],0
0x60ff1a: je short 0060FF20h
0x60ff1c: mov eax,esi
0x60ff1e: jmp short 0060FF2Dh
0x60ff20: push edi
0x60ff21: call 0060FA20h
0x60ff26: mov ecx,[esp+18h]
0x60ff2a: add esp,4
0x60ff2d: mov edx,[ecx+4]
0x60ff30: mov [edx],eax
0x60ff32: mov ecx,[ecx+4]
0x60ff35: cmp [ecx+8],ebx
0x60ff38: mov [esp+1Ch],ecx
0x60ff3c: jne short 0060FFB8h
0x60ff3e: cmp byte ptr [edi+2Dh],0
0x60ff42: je short 0060FF4Bh
0x60ff44: mov eax,esi
0x60ff46: mov [ecx+8],eax
0x60ff49: jmp short 0060FFB8h
0x60ff4b: push edi
0x60ff4c: call 00610730h
0x60ff51: mov ecx,[esp+20h]
0x60ff55: add esp,4
0x60ff58: mov [ecx+8],eax
0x60ff5b: jmp short 0060FFB8h
0x60ff5d: mov [eax+4],ecx
0x60ff60: mov eax,[ebx]
0x60ff62: mov [ecx],eax
0x60ff64: cmp ecx,[ebx+8]
0x60ff67: jne short 0060FF6Dh
0x60ff69: mov esi,ecx
0x60ff6b: jmp short 0060FF87h
0x60ff6d: cmp byte ptr [edi+2Dh],0
0x60ff71: mov esi,[ecx+4]
0x60ff74: jne short 0060FF79h
0x60ff76: mov [edi+4],esi
0x60ff79: mov [esi],edi
0x60ff7b: mov edx,[ebx+8]
0x60ff7e: mov [ecx+8],edx
0x60ff81: mov eax,[ebx+8]
0x60ff84: mov [eax+4],ecx
0x60ff87: mov edx,[esp+14h]
0x60ff8b: mov eax,[edx+4]
0x60ff8e: cmp [eax+4],ebx
0x60ff91: jne short 0060FF98h
0x60ff93: mov [eax+4],ecx
0x60ff96: jmp short 0060FFA6h
0x60ff98: mov eax,[ebx+4]
0x60ff9b: cmp [eax],ebx
0x60ff9d: jne short 0060FFA3h
0x60ff9f: mov [eax],ecx
0x60ffa1: jmp short 0060FFA6h
0x60ffa3: mov [eax+8],ecx
0x60ffa6: mov eax,[ebx+4]
0x60ffa9: mov [ecx+4],eax
0x60ffac: mov dl,[ebx+2Ch]
0x60ffaf: mov al,[ecx+2Ch]
0x60ffb2: mov [ecx+2Ch],dl
0x60ffb5: mov [ebx+2Ch],al
0x60ffb8: mov eax,[esp+18h]
0x60ffbc: mov bl,1
0x60ffbe: cmp [eax+2Ch],bl
0x60ffc1: jne near ptr 006100C6h
0x60ffc7: mov ecx,[esp+14h]
0x60ffcb: mov edx,[ecx+4]
0x60ffce: cmp edi,[edx+4]
0x60ffd1: je near ptr 006100C3h
0x60ffd7: cmp [edi+2Ch],bl
0x60ffda: jne near ptr 006100C3h
0x60ffe0: mov eax,[esi]
0x60ffe2: cmp edi,eax
0x60ffe4: jne short 0061004Dh
0x60ffe6: mov eax,[esi+8]
0x60ffe9: cmp byte ptr [eax+2Ch],0
0x60ffed: jne short 00610003h
0x60ffef: mov [eax+2Ch],bl
0x60fff2: push esi
0x60fff3: mov byte ptr [esi+2Ch],0
0x60fff7: call 00610120h
0x60fffc: mov eax,[esi+8]
0x60ffff: mov ecx,[esp+14h]
0x610003: cmp byte ptr [eax+2Dh],0
0x610007: jne short 0061007Fh
0x610009: mov edx,[eax]
0x61000b: cmp [edx+2Ch],bl
0x61000e: jne short 00610018h
0x610010: mov edx,[eax+8]
0x610013: cmp [edx+2Ch],bl
0x610016: je short 0061007Bh
0x610018: mov edx,[eax+8]
0x61001b: cmp [edx+2Ch],bl
0x61001e: jne short 00610036h
0x610020: mov edx,[eax]
0x610022: mov [edx+2Ch],bl
0x610025: push eax
0x610026: mov byte ptr [eax+2Ch],0
0x61002a: call 00610170h
0x61002f: mov eax,[esi+8]
0x610032: mov ecx,[esp+14h]
0x610036: mov dl,[esi+2Ch]
0x610039: mov [eax+2Ch],dl
0x61003c: mov [esi+2Ch],bl
0x61003f: mov eax,[eax+8]
0x610042: push esi
0x610043: mov [eax+2Ch],bl
0x610046: call 00610120h
0x61004b: jmp short 006100C3h
0x61004d: cmp byte ptr [eax+2Ch],0
0x610051: jne short 00610066h
0x610053: mov [eax+2Ch],bl
0x610056: push esi
0x610057: mov byte ptr [esi+2Ch],0
0x61005b: call 00610170h
0x610060: mov eax,[esi]
0x610062: mov ecx,[esp+14h]
0x610066: cmp byte ptr [eax+2Dh],0
0x61006a: jne short 0061007Fh
0x61006c: mov edx,[eax+8]
0x61006f: cmp [edx+2Ch],bl
0x610072: jne short 00610092h
0x610074: mov edx,[eax]
0x610076: cmp [edx+2Ch],bl
0x610079: jne short 00610092h
0x61007b: mov byte ptr [eax+2Ch],0
0x61007f: mov eax,[ecx+4]
0x610082: mov edi,esi
0x610084: cmp edi,[eax+4]
0x610087: mov esi,[esi+4]
0x61008a: jne near ptr 0060FFD7h
0x610090: jmp short 006100C3h
0x610092: mov edx,[eax]
0x610094: cmp [edx+2Ch],bl
0x610097: jne short 006100AFh
0x610099: mov edx,[eax+8]
0x61009c: mov [edx+2Ch],bl
0x61009f: push eax
0x6100a0: mov byte ptr [eax+2Ch],0
0x6100a4: call 00610120h
0x6100a9: mov eax,[esi]
0x6100ab: mov ecx,[esp+14h]
0x6100af: mov dl,[esi+2Ch]
0x6100b2: mov [eax+2Ch],dl
0x6100b5: mov [esi+2Ch],bl
0x6100b8: mov eax,[eax]
0x6100ba: push esi
0x6100bb: mov [eax+2Ch],bl
0x6100be: call 00610170h
0x6100c3: mov [edi+2Ch],bl
0x6100c6: mov ecx,[esp+18h]
0x6100ca: add ecx,0Ch
0x6100cd: call dword ptr ds:[77CD74h]
0x6100d3: mov ecx,[esp+18h]
0x6100d7: push ecx
0x6100d8: call 006516BAh
0x6100dd: mov ecx,[esp+18h]
0x6100e1: mov eax,[ecx+8]
0x6100e4: add esp,4
0x6100e7: test eax,eax
0x6100e9: jbe short 006100F1h
0x6100eb: add eax,0FFFFFFFFh
0x6100ee: mov [ecx+8],eax
0x6100f1: mov eax,[ebp+8]
0x6100f4: mov edx,[ebp+0Ch]
0x6100f7: mov ecx,[ebp+10h]
0x6100fa: mov [eax],edx
0x6100fc: mov [eax+4],ecx
0x6100ff: mov ecx,[esp+68h]
0x610103: mov fs:[0],ecx
0x61010a: pop ecx
0x61010b: pop edi
0x61010c: pop esi
0x61010d: pop ebx
0x61010e: mov esp,ebp
0x610110: pop ebp
0x610111: ret 0Ch
````

`sub_60fe40` is called by sub_60f730. It delegates to sub_401230, sub_60f5c0, sub_60fa20 (8 callees).

### sub_610120 at 0x610120 (30 instructions)

````text
0x610120: mov edx,[esp+4]
0x610124: mov eax,[edx+8]
0x610127: push esi
0x610128: mov esi,[eax]
0x61012a: mov [edx+8],esi
0x61012d: mov esi,[eax]
0x61012f: cmp byte ptr [esi+2Dh],0
0x610133: jne short 00610138h
0x610135: mov [esi+4],edx
0x610138: mov esi,[edx+4]
0x61013b: mov [eax+4],esi
0x61013e: mov ecx,[ecx+4]
0x610141: cmp edx,[ecx+4]
0x610144: pop esi
0x610145: jne short 00610152h
0x610147: mov [ecx+4],eax
0x61014a: mov [eax],edx
0x61014c: mov [edx+4],eax
0x61014f: ret 4
0x610152: mov ecx,[edx+4]
0x610155: cmp edx,[ecx]
0x610157: jne short 00610163h
0x610159: mov [ecx],eax
0x61015b: mov [eax],edx
0x61015d: mov [edx+4],eax
0x610160: ret 4
0x610163: mov [ecx+8],eax
0x610166: mov [eax],edx
0x610168: mov [edx+4],eax
0x61016b: ret 4
````

`sub_610120` is called by sub_60f810, sub_60fe40. It calls nothing else.

### sub_610170 at 0x610170 (30 instructions)

````text
0x610170: mov edx,[esp+4]
0x610174: mov eax,[edx]
0x610176: push esi
0x610177: mov esi,[eax+8]
0x61017a: mov [edx],esi
0x61017c: mov esi,[eax+8]
0x61017f: cmp byte ptr [esi+2Dh],0
0x610183: jne short 00610188h
0x610185: mov [esi+4],edx
0x610188: mov esi,[edx+4]
0x61018b: mov [eax+4],esi
0x61018e: mov ecx,[ecx+4]
0x610191: cmp edx,[ecx+4]
0x610194: pop esi
0x610195: jne short 006101A3h
0x610197: mov [ecx+4],eax
0x61019a: mov [eax+8],edx
0x61019d: mov [edx+4],eax
0x6101a0: ret 4
0x6101a3: mov ecx,[edx+4]
0x6101a6: cmp edx,[ecx+8]
0x6101a9: jne short 006101B7h
0x6101ab: mov [ecx+8],eax
0x6101ae: mov [eax+8],edx
0x6101b1: mov [edx+4],eax
0x6101b4: ret 4
0x6101b7: mov [ecx],eax
0x6101b9: mov [eax+8],edx
0x6101bc: mov [edx+4],eax
0x6101bf: ret 4
````

`sub_610170` is called by sub_60f810, sub_60fe40. It calls nothing else.

### sub_6101d0 at 0x6101d0 (17 instructions)

````text
0x6101d0: push 30h
0x6101d2: call 006516C0h
0x6101d7: add esp,4
0x6101da: test eax,eax
0x6101dc: je short 006101E4h
0x6101de: mov dword ptr [eax],0
0x6101e4: lea ecx,[eax+4]
0x6101e7: test ecx,ecx
0x6101e9: je short 006101F1h
0x6101eb: mov dword ptr [ecx],0
0x6101f1: lea ecx,[eax+8]
0x6101f4: test ecx,ecx
0x6101f6: je short 006101FEh
0x6101f8: mov dword ptr [ecx],0
0x6101fe: mov byte ptr [eax+2Ch],1
0x610202: mov byte ptr [eax+2Dh],0
0x610206: ret
````

`sub_6101d0` is called by sub_60b550. It delegates to j_ORDINAL 762 (1 callees).

### sub_610210 at 0x610210 (52 instructions)

````text
0x610210: push ebp
0x610211: mov ebp,esp
0x610213: push 0FFFFFFFFh
0x610215: push 73AA81h
0x61021a: mov eax,fs:[0]
0x610220: push eax
0x610221: sub esp,0Ch
0x610224: push ebx
0x610225: push esi
0x610226: push edi
0x610227: mov eax,ds:[858220h]
0x61022c: xor eax,ebp
0x61022e: push eax
0x61022f: lea eax,[ebp-0Ch]
0x610232: mov fs:[0],eax
0x610238: mov [ebp-10h],esp
0x61023b: push 30h
0x61023d: call 006516C0h
0x610242: mov esi,eax
0x610244: mov dword ptr [ebp-4],0
0x61024b: add esp,4
0x61024e: mov [ebp-14h],esi
0x610251: mov [ebp-18h],esi
0x610254: test esi,esi
0x610256: mov byte ptr [ebp-4],1
0x61025a: je short 0061028Ch
0x61025c: mov ecx,[ebp+0Ch]
0x61025f: mov eax,[ebp+8]
0x610262: mov edx,[ebp+10h]
0x610265: mov ebx,[ebp+14h]
0x610268: mov [esi+4],ecx
0x61026b: lea edi,[esi+0Ch]
0x61026e: push ebx
0x61026f: mov ecx,edi
0x610271: mov [esi],eax
0x610273: mov [esi+8],edx
0x610276: call dword ptr ds:[77CD78h]
0x61027c: mov eax,[ebx+1Ch]
0x61027f: mov cl,[ebp+18h]
0x610282: mov [edi+1Ch],eax
0x610285: mov [esi+2Ch],cl
0x610288: mov byte ptr [esi+2Dh],0
0x61028c: mov eax,esi
0x61028e: mov ecx,[ebp-0Ch]
0x610291: mov fs:[0],ecx
0x610298: pop ecx
0x610299: pop edi
0x61029a: pop esi
0x61029b: pop ebx
0x61029c: mov esp,ebp
0x61029e: pop ebp
0x61029f: ret 14h
````

`sub_610210` is called by sub_60f810. It delegates to j_ORDINAL 762 (1 callees).

### sub_6102c0 at 0x6102c0 (244 instructions)

````text
0x6102c0: push ebp
0x6102c1: mov ebp,esp
0x6102c3: and esp,0FFFFFFF8h
0x6102c6: push 0FFFFFFFFh
0x6102c8: push 7437B9h
0x6102cd: mov eax,fs:[0]
0x6102d3: push eax
0x6102d4: sub esp,58h
0x6102d7: push ebx
0x6102d8: push esi
0x6102d9: push edi
0x6102da: mov eax,ds:[858220h]
0x6102df: xor eax,esp
0x6102e1: push eax
0x6102e2: lea eax,[esp+68h]
0x6102e6: mov fs:[0],eax
0x6102ec: mov [esp+14h],ecx
0x6102f0: mov eax,[ebp+10h]
0x6102f3: cmp byte ptr [eax+45h],0
0x6102f7: je short 00610335h
0x6102f9: push 7C5AECh
0x6102fe: lea ecx,[esp+24h]
0x610302: call dword ptr ds:[77CD7Ch]
0x610308: lea eax,[esp+20h]
0x61030c: push eax
0x61030d: lea ecx,[esp+40h]
0x610311: mov dword ptr [esp+74h],0
0x610319: call 00401230h
0x61031e: push 80A4F8h
0x610323: lea ecx,[esp+40h]
0x610327: push ecx
0x610328: mov dword ptr [esp+44h],790F90h
0x610330: call 00652AC4h
0x610335: mov ebx,eax
0x610337: lea ecx,[ebp+0Ch]
0x61033a: mov [esp+18h],ebx
0x61033e: call 0060F550h
0x610343: mov eax,[ebx]
0x610345: cmp byte ptr [eax+45h],0
0x610349: je short 00610350h
0x61034b: mov edi,[ebx+8]
0x61034e: jmp short 00610367h
0x610350: mov edx,[ebx+8]
0x610353: cmp byte ptr [edx+45h],0
0x610357: je short 0061035Dh
0x610359: mov edi,eax
0x61035b: jmp short 00610367h
0x61035d: mov ecx,[ebp+10h]
0x610360: cmp ecx,ebx
0x610362: mov edi,[ecx+8]
0x610365: jne short 006103DDh
0x610367: cmp byte ptr [edi+45h],0
0x61036b: mov esi,[ebx+4]
0x61036e: jne short 00610373h
0x610370: mov [edi+4],esi
0x610373: mov ecx,[esp+14h]
0x610377: mov eax,[ecx+4]
0x61037a: cmp [eax+4],ebx
0x61037d: jne short 00610384h
0x61037f: mov [eax+4],edi
0x610382: jmp short 0061038Fh
0x610384: cmp [esi],ebx
0x610386: jne short 0061038Ch
0x610388: mov [esi],edi
0x61038a: jmp short 0061038Fh
0x61038c: mov [esi+8],edi
0x61038f: mov eax,[ecx+4]
0x610392: cmp [eax],ebx
0x610394: jne short 006103B2h
0x610396: cmp byte ptr [edi+45h],0
0x61039a: je short 006103A0h
0x61039c: mov eax,esi
0x61039e: jmp short 006103ADh
0x6103a0: push edi
0x6103a1: call 0060FE20h
0x6103a6: mov ecx,[esp+18h]
0x6103aa: add esp,4
0x6103ad: mov edx,[ecx+4]
0x6103b0: mov [edx],eax
0x6103b2: mov ecx,[ecx+4]
0x6103b5: cmp [ecx+8],ebx
0x6103b8: mov [esp+1Ch],ecx
0x6103bc: jne short 00610438h
0x6103be: cmp byte ptr [edi+45h],0
0x6103c2: je short 006103CBh
0x6103c4: mov eax,esi
0x6103c6: mov [ecx+8],eax
0x6103c9: jmp short 00610438h
0x6103cb: push edi
0x6103cc: call 006107E0h
0x6103d1: mov ecx,[esp+20h]
0x6103d5: add esp,4
0x6103d8: mov [ecx+8],eax
0x6103db: jmp short 00610438h
0x6103dd: mov [eax+4],ecx
0x6103e0: mov eax,[ebx]
0x6103e2: mov [ecx],eax
0x6103e4: cmp ecx,[ebx+8]
0x6103e7: jne short 006103EDh
0x6103e9: mov esi,ecx
0x6103eb: jmp short 00610407h
0x6103ed: cmp byte ptr [edi+45h],0
0x6103f1: mov esi,[ecx+4]
0x6103f4: jne short 006103F9h
0x6103f6: mov [edi+4],esi
0x6103f9: mov [esi],edi
0x6103fb: mov edx,[ebx+8]
0x6103fe: mov [ecx+8],edx
0x610401: mov eax,[ebx+8]
0x610404: mov [eax+4],ecx
0x610407: mov edx,[esp+14h]
0x61040b: mov eax,[edx+4]
0x61040e: cmp [eax+4],ebx
0x610411: jne short 00610418h
0x610413: mov [eax+4],ecx
0x610416: jmp short 00610426h
0x610418: mov eax,[ebx+4]
0x61041b: cmp [eax],ebx
0x61041d: jne short 00610423h
0x61041f: mov [eax],ecx
0x610421: jmp short 00610426h
0x610423: mov [eax+8],ecx
0x610426: mov eax,[ebx+4]
0x610429: mov [ecx+4],eax
0x61042c: mov dl,[ebx+44h]
0x61042f: mov al,[ecx+44h]
0x610432: mov [ecx+44h],dl
0x610435: mov [ebx+44h],al
0x610438: mov eax,[esp+18h]
0x61043c: mov bl,1
0x61043e: cmp [eax+44h],bl
0x610441: jne near ptr 00610546h
0x610447: mov ecx,[esp+14h]
0x61044b: mov edx,[ecx+4]
0x61044e: cmp edi,[edx+4]
0x610451: je near ptr 00610543h
0x610457: cmp [edi+44h],bl
0x61045a: jne near ptr 00610543h
0x610460: mov eax,[esi]
0x610462: cmp edi,eax
0x610464: jne short 006104CDh
0x610466: mov eax,[esi+8]
0x610469: cmp byte ptr [eax+44h],0
0x61046d: jne short 00610483h
0x61046f: mov [eax+44h],bl
0x610472: push esi
0x610473: mov byte ptr [esi+44h],0
0x610477: call 006105A0h
0x61047c: mov eax,[esi+8]
0x61047f: mov ecx,[esp+14h]
0x610483: cmp byte ptr [eax+45h],0
0x610487: jne short 006104FFh
0x610489: mov edx,[eax]
0x61048b: cmp [edx+44h],bl
0x61048e: jne short 00610498h
0x610490: mov edx,[eax+8]
0x610493: cmp [edx+44h],bl
0x610496: je short 006104FBh
0x610498: mov edx,[eax+8]
0x61049b: cmp [edx+44h],bl
0x61049e: jne short 006104B6h
0x6104a0: mov edx,[eax]
0x6104a2: mov [edx+44h],bl
0x6104a5: push eax
0x6104a6: mov byte ptr [eax+44h],0
0x6104aa: call 006105F0h
0x6104af: mov eax,[esi+8]
0x6104b2: mov ecx,[esp+14h]
0x6104b6: mov dl,[esi+44h]
0x6104b9: mov [eax+44h],dl
0x6104bc: mov [esi+44h],bl
0x6104bf: mov eax,[eax+8]
0x6104c2: push esi
0x6104c3: mov [eax+44h],bl
0x6104c6: call 006105A0h
0x6104cb: jmp short 00610543h
0x6104cd: cmp byte ptr [eax+44h],0
0x6104d1: jne short 006104E6h
0x6104d3: mov [eax+44h],bl
0x6104d6: push esi
0x6104d7: mov byte ptr [esi+44h],0
0x6104db: call 006105F0h
0x6104e0: mov eax,[esi]
0x6104e2: mov ecx,[esp+14h]
0x6104e6: cmp byte ptr [eax+45h],0
0x6104ea: jne short 006104FFh
0x6104ec: mov edx,[eax+8]
0x6104ef: cmp [edx+44h],bl
0x6104f2: jne short 00610512h
0x6104f4: mov edx,[eax]
0x6104f6: cmp [edx+44h],bl
0x6104f9: jne short 00610512h
0x6104fb: mov byte ptr [eax+44h],0
0x6104ff: mov eax,[ecx+4]
0x610502: mov edi,esi
0x610504: cmp edi,[eax+4]
0x610507: mov esi,[esi+4]
0x61050a: jne near ptr 00610457h
0x610510: jmp short 00610543h
0x610512: mov edx,[eax]
0x610514: cmp [edx+44h],bl
0x610517: jne short 0061052Fh
0x610519: mov edx,[eax+8]
0x61051c: mov [edx+44h],bl
0x61051f: push eax
0x610520: mov byte ptr [eax+44h],0
0x610524: call 006105A0h
0x610529: mov eax,[esi]
0x61052b: mov ecx,[esp+14h]
0x61052f: mov dl,[esi+44h]
0x610532: mov [eax+44h],dl
0x610535: mov [esi+44h],bl
0x610538: mov eax,[eax]
0x61053a: push esi
0x61053b: mov [eax+44h],bl
0x61053e: call 006105F0h
0x610543: mov [edi+44h],bl
0x610546: mov ecx,[esp+18h]
0x61054a: add ecx,0Ch
0x61054d: call 0060EF00h
0x610552: mov ecx,[esp+18h]
0x610556: push ecx
0x610557: call 006516BAh
0x61055c: mov ecx,[esp+18h]
0x610560: mov eax,[ecx+8]
0x610563: add esp,4
0x610566: test eax,eax
0x610568: jbe short 00610570h
0x61056a: add eax,0FFFFFFFFh
0x61056d: mov [ecx+8],eax
0x610570: mov eax,[ebp+8]
0x610573: mov edx,[ebp+0Ch]
0x610576: mov ecx,[ebp+10h]
0x610579: mov [eax],edx
0x61057b: mov [eax+4],ecx
0x61057e: mov ecx,[esp+68h]
0x610582: mov fs:[0],ecx
0x610589: pop ecx
0x61058a: pop edi
0x61058b: pop esi
0x61058c: pop ebx
0x61058d: mov esp,ebp
0x61058f: pop ebp
0x610590: ret 0Ch
````

`sub_6102c0` is called by sub_60fb40. It delegates to sub_401230, sub_60ef00, sub_60f550 (9 callees).

### sub_6105a0 at 0x6105a0 (30 instructions)

````text
0x6105a0: mov edx,[esp+4]
0x6105a4: mov eax,[edx+8]
0x6105a7: push esi
0x6105a8: mov esi,[eax]
0x6105aa: mov [edx+8],esi
0x6105ad: mov esi,[eax]
0x6105af: cmp byte ptr [esi+45h],0
0x6105b3: jne short 006105B8h
0x6105b5: mov [esi+4],edx
0x6105b8: mov esi,[edx+4]
0x6105bb: mov [eax+4],esi
0x6105be: mov ecx,[ecx+4]
0x6105c1: cmp edx,[ecx+4]
0x6105c4: pop esi
0x6105c5: jne short 006105D2h
0x6105c7: mov [ecx+4],eax
0x6105ca: mov [eax],edx
0x6105cc: mov [edx+4],eax
0x6105cf: ret 4
0x6105d2: mov ecx,[edx+4]
0x6105d5: cmp edx,[ecx]
0x6105d7: jne short 006105E3h
0x6105d9: mov [ecx],eax
0x6105db: mov [eax],edx
0x6105dd: mov [edx+4],eax
0x6105e0: ret 4
0x6105e3: mov [ecx+8],eax
0x6105e6: mov [eax],edx
0x6105e8: mov [edx+4],eax
0x6105eb: ret 4
````

`sub_6105a0` is called by sub_60fc20, sub_6102c0. It calls nothing else.

### sub_6105f0 at 0x6105f0 (30 instructions)

````text
0x6105f0: mov edx,[esp+4]
0x6105f4: mov eax,[edx]
0x6105f6: push esi
0x6105f7: mov esi,[eax+8]
0x6105fa: mov [edx],esi
0x6105fc: mov esi,[eax+8]
0x6105ff: cmp byte ptr [esi+45h],0
0x610603: jne short 00610608h
0x610605: mov [esi+4],edx
0x610608: mov esi,[edx+4]
0x61060b: mov [eax+4],esi
0x61060e: mov ecx,[ecx+4]
0x610611: cmp edx,[ecx+4]
0x610614: pop esi
0x610615: jne short 00610623h
0x610617: mov [ecx+4],eax
0x61061a: mov [eax+8],edx
0x61061d: mov [edx+4],eax
0x610620: ret 4
0x610623: mov ecx,[edx+4]
0x610626: cmp edx,[ecx+8]
0x610629: jne short 00610637h
0x61062b: mov [ecx+8],eax
0x61062e: mov [eax+8],edx
0x610631: mov [edx+4],eax
0x610634: ret 4
0x610637: mov [ecx],eax
0x610639: mov [eax+8],edx
0x61063c: mov [edx+4],eax
0x61063f: ret 4
````

`sub_6105f0` is called by sub_60fc20, sub_6102c0. It calls nothing else.

### sub_610650 at 0x610650 (17 instructions)

````text
0x610650: push 48h
0x610652: call 006516C0h
0x610657: add esp,4
0x61065a: test eax,eax
0x61065c: je short 00610664h
0x61065e: mov dword ptr [eax],0
0x610664: lea ecx,[eax+4]
0x610667: test ecx,ecx
0x610669: je short 00610671h
0x61066b: mov dword ptr [ecx],0
0x610671: lea ecx,[eax+8]
0x610674: test ecx,ecx
0x610676: je short 0061067Eh
0x610678: mov dword ptr [ecx],0
0x61067e: mov byte ptr [eax+44h],1
0x610682: mov byte ptr [eax+45h],0
0x610686: ret
````

`sub_610650` is called by sub_60b550, sub_610980. It delegates to j_ORDINAL 762 (1 callees).

### sub_610690 at 0x610690 (49 instructions)

````text
0x610690: push ebp
0x610691: mov ebp,esp
0x610693: push 0FFFFFFFFh
0x610695: push 73AA51h
0x61069a: mov eax,fs:[0]
0x6106a0: push eax
0x6106a1: sub esp,0Ch
0x6106a4: push ebx
0x6106a5: push esi
0x6106a6: push edi
0x6106a7: mov eax,ds:[858220h]
0x6106ac: xor eax,ebp
0x6106ae: push eax
0x6106af: lea eax,[ebp-0Ch]
0x6106b2: mov fs:[0],eax
0x6106b8: mov [ebp-10h],esp
0x6106bb: push 48h
0x6106bd: call 006516C0h
0x6106c2: mov esi,eax
0x6106c4: xor ebx,ebx
0x6106c6: mov [ebp-4],ebx
0x6106c9: add esp,4
0x6106cc: mov [ebp-14h],esi
0x6106cf: mov [ebp-18h],esi
0x6106d2: cmp esi,ebx
0x6106d4: mov byte ptr [ebp-4],1
0x6106d8: je short 006106FDh
0x6106da: mov eax,[ebp+8]
0x6106dd: mov ecx,[ebp+0Ch]
0x6106e0: mov edx,[ebp+10h]
0x6106e3: mov [esi],eax
0x6106e5: lea eax,[esi+0Ch]
0x6106e8: mov [esi+4],ecx
0x6106eb: mov ecx,[ebp+14h]
0x6106ee: push eax
0x6106ef: mov [esi+8],edx
0x6106f2: call 00610920h
0x6106f7: mov [esi+44h],bl
0x6106fa: mov [esi+45h],bl
0x6106fd: mov eax,esi
0x6106ff: mov ecx,[ebp-0Ch]
0x610702: mov fs:[0],ecx
0x610709: pop ecx
0x61070a: pop edi
0x61070b: pop esi
0x61070c: pop ebx
0x61070d: mov esp,ebp
0x61070f: pop ebp
0x610710: ret 10h
````

`sub_610690` is called by sub_60fc20. It delegates to sub_610920, j_ORDINAL 762 (2 callees).

### sub_610730 at 0x610730 (10 instructions)

````text
0x610730: mov eax,[esp+4]
0x610734: mov ecx,[eax+8]
0x610737: cmp byte ptr [ecx+2Dh],0
0x61073b: jne short 0061074Bh
0x61073d: lea ecx,[ecx]
0x610740: mov eax,ecx
0x610742: mov ecx,[eax+8]
0x610745: cmp byte ptr [ecx+2Dh],0
0x610749: je short 00610740h
0x61074b: ret
````

`sub_610730` is called by sub_60fe40. It calls nothing else.

### sub_610750 at 0x610750 (46 instructions)

````text
0x610750: push 0FFFFFFFFh
0x610752: push 73E709h
0x610757: mov eax,fs:[0]
0x61075d: push eax
0x61075e: push ebx
0x61075f: push ebp
0x610760: push esi
0x610761: push edi
0x610762: mov eax,ds:[858220h]
0x610767: xor eax,esp
0x610769: push eax
0x61076a: lea eax,[esp+14h]
0x61076e: mov fs:[0],eax
0x610774: mov ebx,ecx
0x610776: mov edi,[esp+24h]
0x61077a: cmp byte ptr [edi+45h],0
0x61077e: mov esi,edi
0x610780: jne short 006107C8h
0x610782: mov eax,[esi+8]
0x610785: push eax
0x610786: mov ecx,ebx
0x610788: call 00610750h
0x61078d: mov esi,[esi]
0x61078f: lea ebp,[edi+0Ch]
0x610792: mov [esp+24h],ebp
0x610796: lea ecx,[ebp+1Ch]
0x610799: mov dword ptr [esp+1Ch],0
0x6107a1: call dword ptr ds:[77CD74h]
0x6107a7: mov ecx,ebp
0x6107a9: mov dword ptr [esp+1Ch],0FFFFFFFFh
0x6107b1: call dword ptr ds:[77CD74h]
0x6107b7: push edi
0x6107b8: call 006516BAh
0x6107bd: add esp,4
0x6107c0: cmp byte ptr [esi+45h],0
0x6107c4: mov edi,esi
0x6107c6: je short 00610782h
0x6107c8: mov ecx,[esp+14h]
0x6107cc: mov fs:[0],ecx
0x6107d3: pop ecx
0x6107d4: pop edi
0x6107d5: pop esi
0x6107d6: pop ebp
0x6107d7: pop ebx
0x6107d8: add esp,0Ch
0x6107db: ret 4
````

`sub_610750` is called by sub_60fb40, sub_610750. It delegates to sub_610750, j_ORDINAL 764 (2 callees).

### sub_6107e0 at 0x6107e0 (10 instructions)

````text
0x6107e0: mov eax,[esp+4]
0x6107e4: mov ecx,[eax+8]
0x6107e7: cmp byte ptr [ecx+45h],0
0x6107eb: jne short 006107FBh
0x6107ed: lea ecx,[ecx]
0x6107f0: mov eax,ecx
0x6107f2: mov ecx,[eax+8]
0x6107f5: cmp byte ptr [ecx+45h],0
0x6107f9: je short 006107F0h
0x6107fb: ret
````

`sub_6107e0` is called by sub_6102c0. It calls nothing else.

### sub_610800 at 0x610800 (47 instructions)

````text
0x610800: cmp dword ptr [esi],0
0x610803: push edi
0x610804: mov edi,ds:[77D0E4h]
0x61080a: jne short 0061080Eh
0x61080c: call edi
0x61080e: mov eax,[esi+4]
0x610811: cmp byte ptr [eax+45h],0
0x610815: je short 00610827h
0x610817: mov eax,[eax+8]
0x61081a: mov [esi+4],eax
0x61081d: cmp byte ptr [eax+45h],0
0x610821: je short 00610881h
0x610823: call edi
0x610825: pop edi
0x610826: ret
0x610827: mov ecx,[eax]
0x610829: cmp byte ptr [ecx+45h],0
0x61082d: jne short 00610850h
0x61082f: mov eax,[ecx+8]
0x610832: cmp byte ptr [eax+45h],0
0x610836: jne short 0061084Bh
0x610838: jmp short 00610840h
0x610840: mov ecx,eax
0x610842: mov eax,[ecx+8]
0x610845: cmp byte ptr [eax+45h],0
0x610849: je short 00610840h
0x61084b: mov [esi+4],ecx
0x61084e: pop edi
0x61084f: ret
0x610850: mov eax,[eax+4]
0x610853: cmp byte ptr [eax+45h],0
0x610857: jne short 00610875h
0x610859: lea esp,[esp]
0x610860: mov ecx,[esi+4]
0x610863: cmp ecx,[eax]
0x610865: jne short 00610875h
0x610867: mov [esi+4],eax
0x61086a: mov edx,eax
0x61086c: mov eax,[edx+4]
0x61086f: cmp byte ptr [eax+45h],0
0x610873: je short 00610860h
0x610875: mov ecx,[esi+4]
0x610878: cmp byte ptr [ecx+45h],0
0x61087c: jne short 00610823h
0x61087e: mov [esi+4],eax
0x610881: pop edi
0x610882: ret
````

`sub_610800` is called by sub_60f280, sub_60fa40. It calls nothing else.

### sub_610890 at 0x610890 (52 instructions)

````text
0x610890: push esi
0x610891: mov esi,ecx
0x610893: cmp dword ptr [esi],0
0x610896: push edi
0x610897: mov edi,ds:[77D0E4h]
0x61089d: jne short 006108A1h
0x61089f: call edi
0x6108a1: mov eax,[esi+4]
0x6108a4: cmp byte ptr [eax+2Dh],0
0x6108a8: je short 006108BBh
0x6108aa: mov eax,[eax+8]
0x6108ad: mov [esi+4],eax
0x6108b0: cmp byte ptr [eax+2Dh],0
0x6108b4: je short 00610911h
0x6108b6: call edi
0x6108b8: pop edi
0x6108b9: pop esi
0x6108ba: ret
0x6108bb: mov ecx,[eax]
0x6108bd: cmp byte ptr [ecx+2Dh],0
0x6108c1: jne short 006108E1h
0x6108c3: mov eax,[ecx+8]
0x6108c6: cmp byte ptr [eax+2Dh],0
0x6108ca: jne short 006108DBh
0x6108cc: lea esp,[esp]
0x6108d0: mov ecx,eax
0x6108d2: mov eax,[ecx+8]
0x6108d5: cmp byte ptr [eax+2Dh],0
0x6108d9: je short 006108D0h
0x6108db: pop edi
0x6108dc: mov [esi+4],ecx
0x6108df: pop esi
0x6108e0: ret
0x6108e1: mov eax,[eax+4]
0x6108e4: cmp byte ptr [eax+2Dh],0
0x6108e8: jne short 00610905h
0x6108ea: lea ebx,[ebx]
0x6108f0: mov ecx,[esi+4]
0x6108f3: cmp ecx,[eax]
0x6108f5: jne short 00610905h
0x6108f7: mov [esi+4],eax
0x6108fa: mov edx,eax
0x6108fc: mov eax,[edx+4]
0x6108ff: cmp byte ptr [eax+2Dh],0
0x610903: je short 006108F0h
0x610905: mov ecx,[esi+4]
0x610908: cmp byte ptr [ecx+2Dh],0
0x61090c: jne short 006108B6h
0x61090e: mov [esi+4],eax
0x610911: pop edi
0x610912: pop esi
0x610913: ret
````

`sub_610890` is called by sub_60f020, sub_60f630. It calls nothing else.

### sub_610920 at 0x610920 (29 instructions)

````text
0x610920: push 0FFFFFFFFh
0x610922: push 73E769h
0x610927: mov eax,fs:[0]
0x61092d: push eax
0x61092e: push esi
0x61092f: push edi
0x610930: mov eax,ds:[858220h]
0x610935: xor eax,esp
0x610937: push eax
0x610938: lea eax,[esp+0Ch]
0x61093c: mov fs:[0],eax
0x610942: mov edi,ecx
0x610944: mov esi,[esp+1Ch]
0x610948: push edi
0x610949: mov ecx,esi
0x61094b: call dword ptr ds:[77CD78h]
0x610951: add edi,1Ch
0x610954: push edi
0x610955: lea ecx,[esi+1Ch]
0x610958: mov dword ptr [esp+18h],0
0x610960: call dword ptr ds:[77CD78h]
0x610966: mov eax,esi
0x610968: mov ecx,[esp+0Ch]
0x61096c: mov fs:[0],ecx
0x610973: pop ecx
0x610974: pop edi
0x610975: pop esi
0x610976: add esp,0Ch
0x610979: ret 4
````

`sub_610920` is called by sub_610690. It calls nothing else.

### sub_610980 at 0x610980 (142 instructions)

````text
0x610980: push 0FFFFFFFFh
0x610982: push 74F476h
0x610987: mov eax,fs:[0]
0x61098d: push eax
0x61098e: sub esp,10h
0x610991: push ebx
0x610992: mov eax,ds:[858220h]
0x610997: xor eax,esp
0x610999: push eax
0x61099a: lea eax,[esp+18h]
0x61099e: mov fs:[0],eax
0x6109a4: mov dword ptr [esp+14h],874E80h
0x6109ac: call 0062BB40h
0x6109b1: xor ebx,ebx
0x6109b3: push 874F88h
0x6109b8: mov [esp+24h],ebx
0x6109bc: call 00619E20h
0x6109c1: push 874FCCh
0x6109c6: mov byte ptr [esp+24h],1
0x6109cb: call 00620460h
0x6109d0: push 8750D8h
0x6109d5: mov byte ptr [esp+24h],2
0x6109da: call 0061D830h
0x6109df: push 8753C8h
0x6109e4: mov byte ptr [esp+24h],3
0x6109e9: call 00636C20h
0x6109ee: push 6358C0h
0x6109f3: push 6358B0h
0x6109f8: push 4
0x6109fa: push 10h
0x6109fc: push 875418h
0x610a01: mov byte ptr [esp+34h],4
0x610a06: call 00652929h
0x610a0b: mov ds:[87545Ch],bl
0x610a11: mov ds:[875458h],ebx
0x610a17: push 875460h
0x610a1c: mov byte ptr [esp+24h],5
0x610a21: call 00624350h
0x610a26: push 875520h
0x610a2b: mov byte ptr [esp+24h],6
0x610a30: call 00609E80h
0x610a35: mov ds:[87553Ch],ebx
0x610a3b: mov ds:[875540h],ebx
0x610a41: mov ds:[875544h],ebx
0x610a47: push 875548h
0x610a4c: mov byte ptr [esp+24h],8
0x610a51: call 00638D10h
0x610a56: push 875554h
0x610a5b: mov byte ptr [esp+24h],9
0x610a60: call 00631060h
0x610a65: push 875580h
0x610a6a: mov byte ptr [esp+24h],0Ah
0x610a6f: call 00614EF0h
0x610a74: mov ecx,875730h
0x610a79: mov byte ptr [esp+20h],0Bh
0x610a7e: call 00610650h
0x610a83: mov ds:[875734h],eax
0x610a88: mov byte ptr [eax+45h],1
0x610a8c: mov eax,ds:[875734h]
0x610a91: mov [eax+4],eax
0x610a94: mov eax,ds:[875734h]
0x610a99: mov [eax],eax
0x610a9b: mov eax,ds:[875734h]
0x610aa0: mov [eax+8],eax
0x610aa3: mov ds:[875738h],ebx
0x610aa9: push 87573Ch
0x610aae: mov byte ptr [esp+24h],0Ch
0x610ab3: call 006300D0h
0x610ab8: mov byte ptr [esp+20h],0Dh
0x610abd: mov ecx,87577Ch
0x610ac2: mov dword ptr ds:[875774h],1
0x610acc: mov ds:[875778h],ebx
0x610ad2: call dword ptr ds:[77CD80h]
0x610ad8: push 875798h
0x610add: mov byte ptr [esp+24h],0Eh
0x610ae2: call 0063A5B0h
0x610ae7: mov ds:[8757D4h],ebx
0x610aed: mov ds:[8757D8h],ebx
0x610af3: mov ds:[8757DCh],ebx
0x610af9: mov ds:[8757E4h],ebx
0x610aff: mov ds:[8757E8h],ebx
0x610b05: mov ds:[8757ECh],ebx
0x610b0b: mov ds:[8757F4h],ebx
0x610b11: mov ds:[8757F8h],ebx
0x610b17: mov ds:[8757FCh],ebx
0x610b1d: push 875800h
0x610b22: mov byte ptr [esp+24h],12h
0x610b27: call 00628750h
0x610b2c: mov ds:[87582Ch],ebx
0x610b32: mov ds:[875830h],ebx
0x610b38: mov ds:[875838h],ebx
0x610b3e: mov ds:[87583Ch],ebx
0x610b44: mov ds:[875840h],ebx
0x610b4a: mov ds:[875848h],ebx
0x610b50: mov ds:[87584Ch],ebx
0x610b56: mov ds:[875850h],ebx
0x610b5c: mov ecx,875854h
0x610b61: mov byte ptr [esp+20h],15h
0x610b66: call 00610650h
0x610b6b: mov ds:[875858h],eax
0x610b70: mov byte ptr [eax+45h],1
0x610b74: mov eax,ds:[875858h]
0x610b79: mov [eax+4],eax
0x610b7c: mov eax,ds:[875858h]
0x610b81: mov [eax],eax
0x610b83: mov eax,ds:[875858h]
0x610b88: mov [eax+8],eax
0x610b8b: mov ds:[87585Ch],ebx
0x610b91: push 875860h
0x610b96: mov byte ptr [esp+24h],16h
0x610b9b: call 0040D150h
0x610ba0: push 875880h
0x610ba5: mov byte ptr [esp+24h],17h
0x610baa: call 0040D150h
0x610baf: push 8758A0h
0x610bb4: mov byte ptr [esp+24h],18h
0x610bb9: call 0040D150h
0x610bbe: push 8758C0h
0x610bc3: mov byte ptr [esp+24h],19h
0x610bc8: call 0040D150h
0x610bcd: push 8758E0h
0x610bd2: mov byte ptr [esp+24h],1Ah
0x610bd7: call 0040D150h
0x610bdc: push 875900h
0x610be1: mov byte ptr [esp+24h],1Bh
0x610be6: call 0040D150h
0x610beb: push 875920h
0x610bf0: mov byte ptr [esp+24h],1Ch
0x610bf5: call 0040D150h
0x610bfa: push 875940h
0x610bff: mov byte ptr [esp+24h],1Dh
0x610c04: call 0040D150h
0x610c09: push 875960h
0x610c0e: mov byte ptr [esp+24h],1Eh
0x610c13: call 0040D150h
0x610c18: mov eax,874E80h
0x610c1d: mov ecx,[esp+18h]
0x610c21: mov fs:[0],ecx
0x610c28: pop ecx
0x610c29: pop ebx
0x610c2a: add esp,1Ch
0x610c2d: ret
````

`sub_610980` is called by ?get_instance@?$singleton@VCConfig@@@serialization@boost@@CAAAVCConfig@@XZ. It delegates to sub_40d150, sub_609e80, sub_610650 (16 callees).

### sub_610c30 at 0x610c30 (110 instructions)

````text
0x610c30: push 0FFFFFFFFh
0x610c32: push 74F2A6h
0x610c37: mov eax,fs:[0]
0x610c3d: push eax
0x610c3e: sub esp,8
0x610c41: push ebx
0x610c42: mov eax,ds:[858220h]
0x610c47: xor eax,esp
0x610c49: push eax
0x610c4a: lea eax,[esp+10h]
0x610c4e: mov fs:[0],eax
0x610c54: mov dword ptr [esp+0Ch],874E80h
0x610c5c: mov ecx,875960h
0x610c61: mov dword ptr [esp+18h],1Ch
0x610c69: call 0040D1F0h
0x610c6e: mov ecx,875940h
0x610c73: mov byte ptr [esp+18h],1Bh
0x610c78: call 0040D1F0h
0x610c7d: mov ecx,875920h
0x610c82: mov byte ptr [esp+18h],1Ah
0x610c87: call 0040D1F0h
0x610c8c: mov ecx,875900h
0x610c91: mov byte ptr [esp+18h],19h
0x610c96: call 0040D1F0h
0x610c9b: mov ecx,8758E0h
0x610ca0: mov byte ptr [esp+18h],18h
0x610ca5: call 0040D1F0h
0x610caa: mov ecx,8758C0h
0x610caf: mov byte ptr [esp+18h],17h
0x610cb4: call 0040D1F0h
0x610cb9: mov ecx,8758A0h
0x610cbe: mov byte ptr [esp+18h],16h
0x610cc3: call 0040D1F0h
0x610cc8: mov ecx,875880h
0x610ccd: mov byte ptr [esp+18h],15h
0x610cd2: call 0040D1F0h
0x610cd7: mov ecx,875860h
0x610cdc: mov byte ptr [esp+18h],14h
0x610ce1: call 0040D1F0h
0x610ce6: mov ecx,875854h
0x610ceb: mov byte ptr [esp+18h],13h
0x610cf0: call 0060F470h
0x610cf5: push 875834h
0x610cfa: mov byte ptr [esp+1Ch],12h
0x610cff: call 00611D90h
0x610d04: push 875800h
0x610d09: mov byte ptr [esp+1Ch],11h
0x610d0e: call 006287E0h
0x610d13: push 8757E0h
0x610d18: mov byte ptr [esp+1Ch],10h
0x610d1d: call 00612890h
0x610d22: mov ebx,8757D0h
0x610d27: mov byte ptr [esp+18h],0Fh
0x610d2c: call 00575110h
0x610d31: push 875798h
0x610d36: mov byte ptr [esp+1Ch],0Eh
0x610d3b: call 004DEE70h
0x610d40: mov ecx,87577Ch
0x610d45: mov byte ptr [esp+18h],0Dh
0x610d4a: call dword ptr ds:[77CD74h]
0x610d50: mov ecx,875758h
0x610d55: mov byte ptr [esp+18h],0Ch
0x610d5a: call dword ptr ds:[77CD74h]
0x610d60: mov ecx,875730h
0x610d65: mov byte ptr [esp+18h],0Bh
0x610d6a: call 0060F470h
0x610d6f: push 875580h
0x610d74: mov byte ptr [esp+1Ch],0Ah
0x610d79: call 00615070h
0x610d7e: push 875554h
0x610d83: mov byte ptr [esp+1Ch],9
0x610d88: call 00631110h
0x610d8d: mov eax,875548h
0x610d92: mov byte ptr [esp+18h],8
0x610d97: call 00639E00h
0x610d9c: mov ebx,875538h
0x610da1: mov byte ptr [esp+18h],7
0x610da6: call 00445D90h
0x610dab: push 875520h
0x610db0: mov byte ptr [esp+1Ch],6
0x610db5: call 00609F20h
0x610dba: mov ecx,875460h
0x610dbf: mov byte ptr [esp+18h],5
0x610dc4: call 006245B0h
0x610dc9: push 6358C0h
0x610dce: push 4
0x610dd0: push 10h
0x610dd2: push 875418h
0x610dd7: mov byte ptr [esp+28h],4
0x610ddc: call 006528C6h
0x610de1: push 8753C8h
0x610de6: mov byte ptr [esp+1Ch],3
0x610deb: call 00636C90h
0x610df0: push 8750D8h
0x610df5: mov byte ptr [esp+1Ch],2
0x610dfa: call 0061DA40h
0x610dff: push 874FCCh
0x610e04: mov byte ptr [esp+1Ch],1
0x610e09: call 006205F0h
0x610e0e: push 874F88h
0x610e13: mov byte ptr [esp+1Ch],0
0x610e18: call 00619EE0h
0x610e1d: mov dword ptr [esp+18h],0FFFFFFFFh
0x610e25: call 0062BC80h
0x610e2a: mov ecx,[esp+10h]
0x610e2e: mov fs:[0],ecx
0x610e35: pop ecx
0x610e36: pop ebx
0x610e37: add esp,14h
0x610e3a: ret
````

`sub_610c30` is called by sub_77b4e0. It delegates to sub_40d1f0, sub_445d90, sub_4dee70 (19 callees).

### ?get_mutable_instance@?$singleton@VCConfig@@@serialization@boost@@SAAAVCConfig@@XZ at 0x611bb0 (4 instructions)

````text
0x611bb0: push ecx
0x611bb1: call 00611BC0h
0x611bb6: pop ecx
0x611bb7: ret
````

`?get_mutable_instance@?$singleton@VCConfig@@@serialization@boost@@SAAAVCConfig@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VCConfig@@@serialization@boost@@CAAAVCConfig@@XZ (1 callees).

### ?get_instance@?$singleton@VCConfig@@@serialization@boost@@CAAAVCConfig@@XZ at 0x611bc0 (25 instructions)

````text
0x611bc0: push 0FFFFFFFFh
0x611bc2: push 75454Eh
0x611bc7: mov eax,fs:[0]
0x611bcd: push eax
0x611bce: mov eax,ds:[858220h]
0x611bd3: push ecx
0x611bd4: xor eax,esp
0x611bd6: push eax
0x611bd7: lea eax,[esp+8]
0x611bdb: mov fs:[0],eax
0x611be1: mov eax,1
0x611be6: test ds:[875EB4h],al
0x611bec: jne short 00611C0Eh
0x611bee: or ds:[875EB4h],eax
0x611bf4: mov dword ptr [esp+10h],0
0x611bfc: call 00610980h
0x611c01: push 77B4E0h
0x611c06: call 006527EDh
0x611c0b: add esp,4
0x611c0e: mov eax,874E80h
0x611c13: mov ecx,[esp+8]
0x611c17: mov fs:[0],ecx
0x611c1e: pop ecx
0x611c1f: add esp,10h
0x611c22: ret
````

`?get_instance@?$singleton@VCConfig@@@serialization@boost@@CAAAVCConfig@@XZ` is called by ?get_mutable_instance@?$singleton@VCConfig@@@serialization@boost@@SAAAVCConfig@@XZ. It delegates to sub_610980, sub_6527ed (2 callees).

### sub_611d90 at 0x611d90 (54 instructions)

````text
0x611d90: push 0FFFFFFFFh
0x611d92: push 73AA18h
0x611d97: mov eax,fs:[0]
0x611d9d: push eax
0x611d9e: push ebx
0x611d9f: push esi
0x611da0: push edi
0x611da1: mov eax,ds:[858220h]
0x611da6: xor eax,esp
0x611da8: push eax
0x611da9: lea eax,[esp+10h]
0x611dad: mov fs:[0],eax
0x611db3: mov esi,[esp+20h]
0x611db7: xor ebx,ebx
0x611db9: mov [esp+18h],ebx
0x611dbd: mov eax,[esi+14h]
0x611dc0: cmp eax,ebx
0x611dc2: je short 00611DDEh
0x611dc4: mov ecx,[esp+20h]
0x611dc8: mov edi,[esi+18h]
0x611dcb: push ecx
0x611dcc: push eax
0x611dcd: call 006127E0h
0x611dd2: mov eax,[esi+14h]
0x611dd5: push eax
0x611dd6: call 006516BAh
0x611ddb: add esp,0Ch
0x611dde: mov [esi+14h],ebx
0x611de1: mov [esi+18h],ebx
0x611de4: mov [esi+1Ch],ebx
0x611de7: mov dword ptr [esp+18h],0FFFFFFFFh
0x611def: mov eax,[esi+4]
0x611df2: cmp eax,ebx
0x611df4: je short 00611E10h
0x611df6: mov edx,[esp+20h]
0x611dfa: mov edi,[esi+8]
0x611dfd: push edx
0x611dfe: push eax
0x611dff: call 006127E0h
0x611e04: mov eax,[esi+4]
0x611e07: push eax
0x611e08: call 006516BAh
0x611e0d: add esp,0Ch
0x611e10: mov [esi+4],ebx
0x611e13: mov [esi+8],ebx
0x611e16: mov [esi+0Ch],ebx
0x611e19: mov ecx,[esp+10h]
0x611e1d: mov fs:[0],ecx
0x611e24: pop ecx
0x611e25: pop edi
0x611e26: pop esi
0x611e27: pop ebx
0x611e28: add esp,0Ch
0x611e2b: ret 4
````

`sub_611d90` is called by sub_610c30. It delegates to sub_6127e0, j_ORDINAL 764 (2 callees).

### sub_6127e0 at 0x6127e0 (30 instructions)

````text
0x6127e0: push 0FFFFFFFFh
0x6127e2: push 73931Ch
0x6127e7: mov eax,fs:[0]
0x6127ed: push eax
0x6127ee: push esi
0x6127ef: mov eax,ds:[858220h]
0x6127f4: xor eax,esp
0x6127f6: push eax
0x6127f7: lea eax,[esp+8]
0x6127fb: mov fs:[0],eax
0x612801: mov esi,[esp+18h]
0x612805: cmp esi,edi
0x612807: je short 0061283Dh
0x612809: lea esp,[esp]
0x612810: lea ecx,[esi+20h]
0x612813: mov dword ptr [esp+10h],0
0x61281b: call dword ptr ds:[77CD74h]
0x612821: lea ecx,[esi+4]
0x612824: mov dword ptr [esp+10h],0FFFFFFFFh
0x61282c: call dword ptr ds:[77CD74h]
0x612832: add esi,3Ch
0x612835: cmp esi,edi
0x612837: mov [esp+18h],esi
0x61283b: jne short 00612810h
0x61283d: mov ecx,[esp+8]
0x612841: mov fs:[0],ecx
0x612848: pop ecx
0x612849: pop esi
0x61284a: add esp,0Ch
0x61284d: ret
````

`sub_6127e0` is called by sub_611d90, sub_612890, sub_62bc80. It calls nothing else.

### sub_612890 at 0x612890 (43 instructions)

````text
0x612890: push 0FFFFFFFFh
0x612892: push 743788h
0x612897: mov eax,fs:[0]
0x61289d: push eax
0x61289e: push ebx
0x61289f: push ebp
0x6128a0: push esi
0x6128a1: push edi
0x6128a2: mov eax,ds:[858220h]
0x6128a7: xor eax,esp
0x6128a9: push eax
0x6128aa: lea eax,[esp+14h]
0x6128ae: mov fs:[0],eax
0x6128b4: mov esi,[esp+24h]
0x6128b8: xor ebp,ebp
0x6128ba: lea ebx,[esi+10h]
0x6128bd: mov [esp+1Ch],ebp
0x6128c1: call 00497E50h
0x6128c6: mov dword ptr [esp+1Ch],0FFFFFFFFh
0x6128ce: mov eax,[esi+4]
0x6128d1: cmp eax,ebp
0x6128d3: je short 006128EFh
0x6128d5: mov ecx,[esp+24h]
0x6128d9: mov edi,[esi+8]
0x6128dc: push ecx
0x6128dd: push eax
0x6128de: call 006127E0h
0x6128e3: mov edx,[esi+4]
0x6128e6: push edx
0x6128e7: call 006516BAh
0x6128ec: add esp,0Ch
0x6128ef: mov [esi+4],ebp
0x6128f2: mov [esi+8],ebp
0x6128f5: mov [esi+0Ch],ebp
0x6128f8: mov ecx,[esp+14h]
0x6128fc: mov fs:[0],ecx
0x612903: pop ecx
0x612904: pop edi
0x612905: pop esi
0x612906: pop ebp
0x612907: pop ebx
0x612908: add esp,0Ch
0x61290b: ret 4
````

`sub_612890` is called by sub_610c30. It delegates to sub_497e50, sub_6127e0, j_ORDINAL 764 (3 callees).

### sub_614ef0 at 0x614ef0 (79 instructions)

````text
0x614ef0: push 0FFFFFFFFh
0x614ef2: push 74A634h
0x614ef7: mov eax,fs:[0]
0x614efd: push eax
0x614efe: push ebx
0x614eff: push esi
0x614f00: mov eax,ds:[858220h]
0x614f05: xor eax,esp
0x614f07: push eax
0x614f08: lea eax,[esp+0Ch]
0x614f0c: mov fs:[0],eax
0x614f12: mov esi,[esp+1Ch]
0x614f16: push 7F6000h
0x614f1b: mov ecx,esi
0x614f1d: call dword ptr ds:[77CD7Ch]
0x614f23: xor ebx,ebx
0x614f25: mov [esp+14h],ebx
0x614f29: lea ecx,[esi+30h]
0x614f2c: mov [esi+1Ch],ebx
0x614f2f: mov dword ptr [esi+20h],1
0x614f36: mov [esi+24h],ebx
0x614f39: mov [esi+28h],ebx
0x614f3c: mov [esi+2Ch],ebx
0x614f3f: call dword ptr ds:[77CD80h]
0x614f45: mov byte ptr [esp+14h],1
0x614f4a: lea ecx,[esi+84h]
0x614f50: mov byte ptr [esi+4Ch],1
0x614f54: mov [esi+4Dh],bl
0x614f57: mov [esi+50h],ebx
0x614f5a: mov [esi+54h],ebx
0x614f5d: mov [esi+58h],ebx
0x614f60: call dword ptr ds:[77CD80h]
0x614f66: lea ecx,[esi+0A4h]
0x614f6c: mov byte ptr [esp+14h],2
0x614f71: call dword ptr ds:[77CD80h]
0x614f77: mov [esi+0F0h],ebx
0x614f7d: mov [esi+0F4h],ebx
0x614f83: mov [esi+0F8h],ebx
0x614f89: mov [esi+100h],ebx
0x614f8f: mov [esi+104h],ebx
0x614f95: mov [esi+108h],ebx
0x614f9b: lea ecx,[esi+10Ch]
0x614fa1: mov byte ptr [esp+14h],5
0x614fa6: call dword ptr ds:[77CD80h]
0x614fac: mov [esi+12Ch],ebx
0x614fb2: mov [esi+130h],ebx
0x614fb8: mov dword ptr [esi+134h],1
0x614fc2: mov [esi+13Ch],ebx
0x614fc8: mov [esi+140h],ebx
0x614fce: mov [esi+144h],ebx
0x614fd4: mov [esi+14Ch],ebx
0x614fda: mov [esi+150h],ebx
0x614fe0: mov [esi+154h],ebx
0x614fe6: mov [esi+15Ch],ebx
0x614fec: mov [esi+160h],ebx
0x614ff2: mov [esi+164h],ebx
0x614ff8: mov eax,2
0x614ffd: mov [esi+168h],eax
0x615003: mov [esi+170h],ebx
0x615009: mov [esi+174h],ebx
0x61500f: mov [esi+178h],ebx
0x615015: mov [esi+17Ch],eax
0x61501b: mov dword ptr [esi+180h],1
0x615025: mov [esi+188h],ebx
0x61502b: mov [esi+18Ch],ebx
0x615031: mov [esi+190h],ebx
0x615037: mov [esi+198h],ebx
0x61503d: mov [esi+19Ch],ebx
0x615043: mov [esi+1A0h],ebx
0x615049: mov [esi+1A4h],ebx
0x61504f: mov [esi+1A8h],ebx
0x615055: mov eax,esi
0x615057: mov ecx,[esp+0Ch]
0x61505b: mov fs:[0],ecx
0x615062: pop ecx
0x615063: pop esi
0x615064: pop ebx
0x615065: add esp,0Ch
0x615068: ret 4
````

`sub_614ef0` is called by sub_610980. It calls nothing else.

### sub_615070 at 0x615070 (86 instructions)

````text
0x615070: push 0FFFFFFFFh
0x615072: push 743714h
0x615077: mov eax,fs:[0]
0x61507d: push eax
0x61507e: push ebx
0x61507f: push esi
0x615080: push edi
0x615081: mov eax,ds:[858220h]
0x615086: xor eax,esp
0x615088: push eax
0x615089: lea eax,[esp+10h]
0x61508d: mov fs:[0],eax
0x615093: mov esi,[esp+20h]
0x615097: lea ebx,[esi+194h]
0x61509d: mov dword ptr [esp+18h],0Bh
0x6150a5: call 00433080h
0x6150aa: mov eax,[esi+188h]
0x6150b0: xor edi,edi
0x6150b2: cmp eax,edi
0x6150b4: je short 006150BFh
0x6150b6: push eax
0x6150b7: call 006516BAh
0x6150bc: add esp,4
0x6150bf: lea ebx,[esi+16Ch]
0x6150c5: mov [esi+188h],edi
0x6150cb: mov [esi+18Ch],edi
0x6150d1: mov [esi+190h],edi
0x6150d7: mov byte ptr [esp+18h],9
0x6150dc: call 00433080h
0x6150e1: mov eax,[esi+15Ch]
0x6150e7: xor edi,edi
0x6150e9: cmp eax,edi
0x6150eb: je short 006150F6h
0x6150ed: push eax
0x6150ee: call 006516BAh
0x6150f3: add esp,4
0x6150f6: mov [esi+15Ch],edi
0x6150fc: mov [esi+160h],edi
0x615102: mov [esi+164h],edi
0x615108: mov eax,[esi+14Ch]
0x61510e: cmp eax,edi
0x615110: je short 0061511Bh
0x615112: push eax
0x615113: call 006516BAh
0x615118: add esp,4
0x61511b: mov [esi+14Ch],edi
0x615121: mov [esi+150h],edi
0x615127: mov [esi+154h],edi
0x61512d: mov eax,[esi+13Ch]
0x615133: cmp eax,edi
0x615135: je short 00615140h
0x615137: push eax
0x615138: call 006516BAh
0x61513d: add esp,4
0x615140: lea ecx,[esi+10Ch]
0x615146: mov [esi+13Ch],edi
0x61514c: mov [esi+140h],edi
0x615152: mov [esi+144h],edi
0x615158: mov byte ptr [esp+18h],5
0x61515d: call dword ptr ds:[77CD74h]
0x615163: lea ebx,[esi+0FCh]
0x615169: mov byte ptr [esp+18h],4
0x61516e: call 00575110h
0x615173: lea ebx,[esi+0ECh]
0x615179: mov byte ptr [esp+18h],3
0x61517e: call 00433080h
0x615183: lea ecx,[esi+0A4h]
0x615189: mov byte ptr [esp+18h],2
0x61518e: call dword ptr ds:[77CD74h]
0x615194: lea ecx,[esi+84h]
0x61519a: mov byte ptr [esp+18h],1
0x61519f: call dword ptr ds:[77CD74h]
0x6151a5: lea ecx,[esi+30h]
0x6151a8: mov byte ptr [esp+18h],0
0x6151ad: call dword ptr ds:[77CD74h]
0x6151b3: mov ecx,esi
0x6151b5: mov dword ptr [esp+18h],0FFFFFFFFh
0x6151bd: call dword ptr ds:[77CD74h]
0x6151c3: mov ecx,[esp+10h]
0x6151c7: mov fs:[0],ecx
0x6151ce: pop ecx
0x6151cf: pop edi
0x6151d0: pop esi
0x6151d1: pop ebx
0x6151d2: add esp,0Ch
0x6151d5: ret 4
````

`sub_615070` is called by sub_610c30. It delegates to sub_433080, sub_575110, j_ORDINAL 764 (3 callees).

### sub_619e20 at 0x619e20 (60 instructions)

````text
0x619e20: push 0FFFFFFFFh
0x619e22: push 74A569h
0x619e27: mov eax,fs:[0]
0x619e2d: push eax
0x619e2e: push esi
0x619e2f: push edi
0x619e30: mov eax,ds:[858220h]
0x619e35: xor eax,esp
0x619e37: push eax
0x619e38: lea eax,[esp+0Ch]
0x619e3c: mov fs:[0],eax
0x619e42: mov esi,[esp+1Ch]
0x619e46: call 00585350h
0x619e4b: mov [esi+4],eax
0x619e4e: mov byte ptr [eax+19h],1
0x619e52: mov eax,[esi+4]
0x619e55: mov [eax+4],eax
0x619e58: mov eax,[esi+4]
0x619e5b: mov [eax],eax
0x619e5d: mov eax,[esi+4]
0x619e60: xor edi,edi
0x619e62: mov [eax+8],eax
0x619e65: mov [esi+8],edi
0x619e68: mov [esp+14h],edi
0x619e6c: mov [esi+10h],edi
0x619e6f: mov [esi+14h],edi
0x619e72: mov [esi+18h],edi
0x619e75: mov [esi+20h],edi
0x619e78: mov [esi+24h],edi
0x619e7b: mov [esi+28h],edi
0x619e7e: mov byte ptr [esp+14h],2
0x619e83: call 00585350h
0x619e88: mov [esi+30h],eax
0x619e8b: mov byte ptr [eax+19h],1
0x619e8f: mov eax,[esi+30h]
0x619e92: mov [eax+4],eax
0x619e95: mov eax,[esi+30h]
0x619e98: mov [eax],eax
0x619e9a: mov eax,[esi+30h]
0x619e9d: mov [eax+8],eax
0x619ea0: mov [esi+34h],edi
0x619ea3: mov byte ptr [esp+14h],3
0x619ea8: call 00633900h
0x619ead: mov [esi+3Ch],eax
0x619eb0: mov byte ptr [eax+39h],1
0x619eb4: mov eax,[esi+3Ch]
0x619eb7: mov [eax+4],eax
0x619eba: mov eax,[esi+3Ch]
0x619ebd: mov [eax],eax
0x619ebf: mov eax,[esi+3Ch]
0x619ec2: mov [eax+8],eax
0x619ec5: mov [esi+40h],edi
0x619ec8: mov eax,esi
0x619eca: mov ecx,[esp+0Ch]
0x619ece: mov fs:[0],ecx
0x619ed5: pop ecx
0x619ed6: pop edi
0x619ed7: pop esi
0x619ed8: add esp,0Ch
0x619edb: ret 4
````

`sub_619e20` is called by sub_610980. It delegates to sub_585350, sub_633900 (2 callees).

### sub_619ee0 at 0x619ee0 (63 instructions)

````text
0x619ee0: push 0FFFFFFFFh
0x619ee2: push 74A569h
0x619ee7: mov eax,fs:[0]
0x619eed: push eax
0x619eee: push ebx
0x619eef: push esi
0x619ef0: mov eax,ds:[858220h]
0x619ef5: xor eax,esp
0x619ef7: push eax
0x619ef8: lea eax,[esp+0Ch]
0x619efc: mov fs:[0],eax
0x619f02: mov esi,[esp+1Ch]
0x619f06: lea eax,[esi+38h]
0x619f09: mov dword ptr [esp+14h],3
0x619f11: call 00506590h
0x619f16: lea eax,[esi+2Ch]
0x619f19: mov byte ptr [esp+14h],2
0x619f1e: call 005064E0h
0x619f23: mov byte ptr [esp+14h],1
0x619f28: mov eax,[esi+20h]
0x619f2b: xor ecx,ecx
0x619f2d: cmp eax,ecx
0x619f2f: je short 00619F4Fh
0x619f31: mov ecx,[esp+1Ch]
0x619f35: mov ebx,[esi+24h]
0x619f38: push ecx
0x619f39: call 0044D400h
0x619f3e: mov eax,[esi+20h]
0x619f41: add esp,4
0x619f44: push eax
0x619f45: call 006516BAh
0x619f4a: add esp,4
0x619f4d: xor ecx,ecx
0x619f4f: mov [esi+20h],ecx
0x619f52: mov [esi+24h],ecx
0x619f55: mov [esi+28h],ecx
0x619f58: mov [esp+14h],cl
0x619f5c: mov eax,[esi+10h]
0x619f5f: cmp eax,ecx
0x619f61: je short 00619F81h
0x619f63: mov edx,[esp+1Ch]
0x619f67: mov ebx,[esi+14h]
0x619f6a: push edx
0x619f6b: call 0044D400h
0x619f70: mov eax,[esi+10h]
0x619f73: add esp,4
0x619f76: push eax
0x619f77: call 006516BAh
0x619f7c: add esp,4
0x619f7f: xor ecx,ecx
0x619f81: mov eax,esi
0x619f83: mov [esi+10h],ecx
0x619f86: mov [esi+14h],ecx
0x619f89: mov [esi+18h],ecx
0x619f8c: mov dword ptr [esp+14h],0FFFFFFFFh
0x619f94: call 005064E0h
0x619f99: mov ecx,[esp+0Ch]
0x619f9d: mov fs:[0],ecx
0x619fa4: pop ecx
0x619fa5: pop esi
0x619fa6: pop ebx
0x619fa7: add esp,0Ch
0x619faa: ret 4
````

`sub_619ee0` is called by sub_610c30. It delegates to sub_44d400, sub_5064e0, sub_506590 (4 callees).

### sub_61d830 at 0x61d830 (107 instructions)

````text
0x61d830: push 0FFFFFFFFh
0x61d832: push 73EC8Dh
0x61d837: mov eax,fs:[0]
0x61d83d: push eax
0x61d83e: push esi
0x61d83f: push edi
0x61d840: mov eax,ds:[858220h]
0x61d845: xor eax,esp
0x61d847: push eax
0x61d848: lea eax,[esp+0Ch]
0x61d84c: mov fs:[0],eax
0x61d852: mov esi,[esp+1Ch]
0x61d856: xor edi,edi
0x61d858: mov [esi+4],edi
0x61d85b: mov [esi+8],edi
0x61d85e: mov [esi+0Ch],edi
0x61d861: mov [esp+14h],edi
0x61d865: mov [esi+14h],edi
0x61d868: mov [esi+18h],edi
0x61d86b: mov [esi+1Ch],edi
0x61d86e: mov [esi+24h],edi
0x61d871: mov [esi+28h],edi
0x61d874: mov [esi+2Ch],edi
0x61d877: lea ecx,[esi+30h]
0x61d87a: mov byte ptr [esp+14h],2
0x61d87f: call dword ptr ds:[77CD80h]
0x61d885: lea ecx,[esi+4Ch]
0x61d888: mov byte ptr [esp+14h],3
0x61d88d: call dword ptr ds:[77CD80h]
0x61d893: lea ecx,[esi+68h]
0x61d896: mov byte ptr [esp+14h],4
0x61d89b: call dword ptr ds:[77CD80h]
0x61d8a1: lea ecx,[esi+84h]
0x61d8a7: mov byte ptr [esp+14h],5
0x61d8ac: call dword ptr ds:[77CD80h]
0x61d8b2: lea ecx,[esi+0A0h]
0x61d8b8: mov byte ptr [esp+14h],6
0x61d8bd: call dword ptr ds:[77CD80h]
0x61d8c3: lea ecx,[esi+0BCh]
0x61d8c9: mov byte ptr [esp+14h],7
0x61d8ce: call dword ptr ds:[77CD80h]
0x61d8d4: lea ecx,[esi+0D8h]
0x61d8da: mov byte ptr [esp+14h],8
0x61d8df: call dword ptr ds:[77CD80h]
0x61d8e5: lea ecx,[esi+0F4h]
0x61d8eb: mov byte ptr [esp+14h],9
0x61d8f0: call dword ptr ds:[77CD80h]
0x61d8f6: lea ecx,[esi+110h]
0x61d8fc: mov byte ptr [esp+14h],0Ah
0x61d901: call dword ptr ds:[77CD80h]
0x61d907: lea ecx,[esi+12Ch]
0x61d90d: mov byte ptr [esp+14h],0Bh
0x61d912: call dword ptr ds:[77CD80h]
0x61d918: lea ecx,[esi+148h]
0x61d91e: mov byte ptr [esp+14h],0Ch
0x61d923: call dword ptr ds:[77CD80h]
0x61d929: lea ecx,[esi+164h]
0x61d92f: mov byte ptr [esp+14h],0Dh
0x61d934: call dword ptr ds:[77CD80h]
0x61d93a: lea ecx,[esi+180h]
0x61d940: mov byte ptr [esp+14h],0Eh
0x61d945: call dword ptr ds:[77CD80h]
0x61d94b: lea ecx,[esi+19Ch]
0x61d951: mov byte ptr [esp+14h],0Fh
0x61d956: call dword ptr ds:[77CD80h]
0x61d95c: lea ecx,[esi+1B8h]
0x61d962: mov byte ptr [esp+14h],10h
0x61d967: call dword ptr ds:[77CD80h]
0x61d96d: lea ecx,[esi+1D4h]
0x61d973: mov byte ptr [esp+14h],11h
0x61d978: call dword ptr ds:[77CD80h]
0x61d97e: lea ecx,[esi+1F0h]
0x61d984: mov byte ptr [esp+14h],12h
0x61d989: call dword ptr ds:[77CD80h]
0x61d98f: lea ecx,[esi+20Ch]
0x61d995: mov byte ptr [esp+14h],13h
0x61d99a: call dword ptr ds:[77CD80h]
0x61d9a0: lea ecx,[esi+228h]
0x61d9a6: mov byte ptr [esp+14h],14h
0x61d9ab: call dword ptr ds:[77CD80h]
0x61d9b1: lea ecx,[esi+244h]
0x61d9b7: mov byte ptr [esp+14h],15h
0x61d9bc: call dword ptr ds:[77CD80h]
0x61d9c2: mov byte ptr [esp+14h],16h
0x61d9c7: lea ecx,[esi+264h]
0x61d9cd: mov [esi+260h],edi
0x61d9d3: call dword ptr ds:[77CD80h]
0x61d9d9: lea ecx,[esi+280h]
0x61d9df: mov byte ptr [esp+14h],17h
0x61d9e4: call dword ptr ds:[77CD80h]
0x61d9ea: lea ecx,[esi+29Ch]
0x61d9f0: mov byte ptr [esp+14h],18h
0x61d9f5: call dword ptr ds:[77CD80h]
0x61d9fb: lea ecx,[esi+2B8h]
0x61da01: mov byte ptr [esp+14h],19h
0x61da06: call dword ptr ds:[77CD80h]
0x61da0c: lea ecx,[esi+2D4h]
0x61da12: mov byte ptr [esp+14h],1Ah
0x61da17: call dword ptr ds:[77CD80h]
0x61da1d: mov eax,esi
0x61da1f: mov ecx,[esp+0Ch]
0x61da23: mov fs:[0],ecx
0x61da2a: pop ecx
0x61da2b: pop edi
0x61da2c: pop esi
0x61da2d: add esp,0Ch
0x61da30: ret 4
````

`sub_61d830` is called by sub_610980. It calls nothing else.

### sub_61da40 at 0x61da40 (110 instructions)

````text
0x61da40: push 0FFFFFFFFh
0x61da42: push 73EC8Dh
0x61da47: mov eax,fs:[0]
0x61da4d: push eax
0x61da4e: push ebx
0x61da4f: push esi
0x61da50: mov eax,ds:[858220h]
0x61da55: xor eax,esp
0x61da57: push eax
0x61da58: lea eax,[esp+0Ch]
0x61da5c: mov fs:[0],eax
0x61da62: mov esi,[esp+1Ch]
0x61da66: lea ecx,[esi+2D4h]
0x61da6c: mov dword ptr [esp+14h],1Ah
0x61da74: call dword ptr ds:[77CD74h]
0x61da7a: lea ecx,[esi+2B8h]
0x61da80: mov byte ptr [esp+14h],19h
0x61da85: call dword ptr ds:[77CD74h]
0x61da8b: lea ecx,[esi+29Ch]
0x61da91: mov byte ptr [esp+14h],18h
0x61da96: call dword ptr ds:[77CD74h]
0x61da9c: lea ecx,[esi+280h]
0x61daa2: mov byte ptr [esp+14h],17h
0x61daa7: call dword ptr ds:[77CD74h]
0x61daad: lea ecx,[esi+264h]
0x61dab3: mov byte ptr [esp+14h],16h
0x61dab8: call dword ptr ds:[77CD74h]
0x61dabe: lea ecx,[esi+244h]
0x61dac4: mov byte ptr [esp+14h],15h
0x61dac9: call dword ptr ds:[77CD74h]
0x61dacf: lea ecx,[esi+228h]
0x61dad5: mov byte ptr [esp+14h],14h
0x61dada: call dword ptr ds:[77CD74h]
0x61dae0: lea ecx,[esi+20Ch]
0x61dae6: mov byte ptr [esp+14h],13h
0x61daeb: call dword ptr ds:[77CD74h]
0x61daf1: lea ecx,[esi+1F0h]
0x61daf7: mov byte ptr [esp+14h],12h
0x61dafc: call dword ptr ds:[77CD74h]
0x61db02: lea ecx,[esi+1D4h]
0x61db08: mov byte ptr [esp+14h],11h
0x61db0d: call dword ptr ds:[77CD74h]
0x61db13: lea ecx,[esi+1B8h]
0x61db19: mov byte ptr [esp+14h],10h
0x61db1e: call dword ptr ds:[77CD74h]
0x61db24: lea ecx,[esi+19Ch]
0x61db2a: mov byte ptr [esp+14h],0Fh
0x61db2f: call dword ptr ds:[77CD74h]
0x61db35: lea ecx,[esi+180h]
0x61db3b: mov byte ptr [esp+14h],0Eh
0x61db40: call dword ptr ds:[77CD74h]
0x61db46: lea ecx,[esi+164h]
0x61db4c: mov byte ptr [esp+14h],0Dh
0x61db51: call dword ptr ds:[77CD74h]
0x61db57: lea ecx,[esi+148h]
0x61db5d: mov byte ptr [esp+14h],0Ch
0x61db62: call dword ptr ds:[77CD74h]
0x61db68: lea ecx,[esi+12Ch]
0x61db6e: mov byte ptr [esp+14h],0Bh
0x61db73: call dword ptr ds:[77CD74h]
0x61db79: lea ecx,[esi+110h]
0x61db7f: mov byte ptr [esp+14h],0Ah
0x61db84: call dword ptr ds:[77CD74h]
0x61db8a: lea ecx,[esi+0F4h]
0x61db90: mov byte ptr [esp+14h],9
0x61db95: call dword ptr ds:[77CD74h]
0x61db9b: lea ecx,[esi+0D8h]
0x61dba1: mov byte ptr [esp+14h],8
0x61dba6: call dword ptr ds:[77CD74h]
0x61dbac: lea ecx,[esi+0BCh]
0x61dbb2: mov byte ptr [esp+14h],7
0x61dbb7: call dword ptr ds:[77CD74h]
0x61dbbd: lea ecx,[esi+0A0h]
0x61dbc3: mov byte ptr [esp+14h],6
0x61dbc8: call dword ptr ds:[77CD74h]
0x61dbce: lea ecx,[esi+84h]
0x61dbd4: mov byte ptr [esp+14h],5
0x61dbd9: call dword ptr ds:[77CD74h]
0x61dbdf: lea ecx,[esi+68h]
0x61dbe2: mov byte ptr [esp+14h],4
0x61dbe7: call dword ptr ds:[77CD74h]
0x61dbed: lea ecx,[esi+4Ch]
0x61dbf0: mov byte ptr [esp+14h],3
0x61dbf5: call dword ptr ds:[77CD74h]
0x61dbfb: lea ecx,[esi+30h]
0x61dbfe: mov byte ptr [esp+14h],2
0x61dc03: call dword ptr ds:[77CD74h]
0x61dc09: mov eax,[esi+24h]
0x61dc0c: xor ebx,ebx
0x61dc0e: cmp eax,ebx
0x61dc10: je short 0061DC1Bh
0x61dc12: push eax
0x61dc13: call 006516BAh
0x61dc18: add esp,4
0x61dc1b: mov [esi+24h],ebx
0x61dc1e: mov [esi+28h],ebx
0x61dc21: mov [esi+2Ch],ebx
0x61dc24: mov [esp+14h],bl
0x61dc28: lea ebx,[esi+10h]
0x61dc2b: call 00433080h
0x61dc30: mov ebx,esi
0x61dc32: mov dword ptr [esp+14h],0FFFFFFFFh
0x61dc3a: call 00433080h
0x61dc3f: mov ecx,[esp+0Ch]
0x61dc43: mov fs:[0],ecx
0x61dc4a: pop ecx
0x61dc4b: pop esi
0x61dc4c: pop ebx
0x61dc4d: add esp,0Ch
0x61dc50: ret 4
````

`sub_61da40` is called by sub_610c30. It delegates to sub_433080, j_ORDINAL 764 (2 callees).

### sub_620460 at 0x620460 (44 instructions)

````text
0x620460: push 0FFFFFFFFh
0x620462: push 74A4F5h
0x620467: mov eax,fs:[0]
0x62046d: push eax
0x62046e: push ecx
0x62046f: push esi
0x620470: mov eax,ds:[858220h]
0x620475: xor eax,esp
0x620477: push eax
0x620478: lea eax,[esp+0Ch]
0x62047c: mov fs:[0],eax
0x620482: mov esi,[esp+1Ch]
0x620486: push esi
0x620487: call 00620510h
0x62048c: lea eax,[esi+40h]
0x62048f: push eax
0x620490: mov dword ptr [esp+18h],0
0x620498: call 00620510h
0x62049d: lea ecx,[esi+80h]
0x6204a3: push ecx
0x6204a4: mov byte ptr [esp+18h],1
0x6204a9: call 00620510h
0x6204ae: lea edx,[esi+0C0h]
0x6204b4: push edx
0x6204b5: mov byte ptr [esp+18h],2
0x6204ba: call 00620510h
0x6204bf: mov byte ptr [esp+14h],3
0x6204c4: call 00633900h
0x6204c9: mov [esi+104h],eax
0x6204cf: mov byte ptr [eax+39h],1
0x6204d3: mov eax,[esi+104h]
0x6204d9: mov [eax+4],eax
0x6204dc: mov eax,[esi+104h]
0x6204e2: mov [eax],eax
0x6204e4: mov eax,[esi+104h]
0x6204ea: mov [eax+8],eax
0x6204ed: mov dword ptr [esi+108h],0
0x6204f7: mov eax,esi
0x6204f9: mov ecx,[esp+0Ch]
0x6204fd: mov fs:[0],ecx
0x620504: pop ecx
0x620505: pop esi
0x620506: add esp,10h
0x620509: ret 4
````

`sub_620460` is called by sub_610980. It delegates to sub_620510, sub_633900 (2 callees).

### sub_620510 at 0x620510 (28 instructions)

````text
0x620510: push 0FFFFFFFFh
0x620512: push 74359Eh
0x620517: mov eax,fs:[0]
0x62051d: push eax
0x62051e: mov eax,ds:[858220h]
0x620523: xor eax,esp
0x620525: push eax
0x620526: lea eax,[esp+4]
0x62052a: mov fs:[0],eax
0x620530: mov eax,[esp+14h]
0x620534: xor ecx,ecx
0x620536: mov [eax+4],ecx
0x620539: mov [eax+8],ecx
0x62053c: mov [eax+0Ch],ecx
0x62053f: mov [eax+14h],ecx
0x620542: mov [eax+18h],ecx
0x620545: mov [eax+1Ch],ecx
0x620548: mov [eax+24h],ecx
0x62054b: mov [eax+28h],ecx
0x62054e: mov [eax+2Ch],ecx
0x620551: mov [eax+34h],ecx
0x620554: mov [eax+38h],ecx
0x620557: mov [eax+3Ch],ecx
0x62055a: mov ecx,[esp+4]
0x62055e: mov fs:[0],ecx
0x620565: pop ecx
0x620566: add esp,0Ch
0x620569: ret 4
````

`sub_620510` is called by sub_620460. It calls nothing else.

### sub_620570 at 0x620570 (31 instructions)

````text
0x620570: push 0FFFFFFFFh
0x620572: push 74355Eh
0x620577: mov eax,fs:[0]
0x62057d: push eax
0x62057e: push ebx
0x62057f: push esi
0x620580: mov eax,ds:[858220h]
0x620585: xor eax,esp
0x620587: push eax
0x620588: lea eax,[esp+0Ch]
0x62058c: mov fs:[0],eax
0x620592: mov esi,[esp+1Ch]
0x620596: lea ebx,[esi+30h]
0x620599: mov dword ptr [esp+14h],2
0x6205a1: call 00401F60h
0x6205a6: lea ebx,[esi+20h]
0x6205a9: mov byte ptr [esp+14h],1
0x6205ae: call 00401F60h
0x6205b3: lea ebx,[esi+10h]
0x6205b6: mov byte ptr [esp+14h],0
0x6205bb: call 00401F60h
0x6205c0: mov ebx,esi
0x6205c2: mov dword ptr [esp+14h],0FFFFFFFFh
0x6205ca: call 00401F60h
0x6205cf: mov ecx,[esp+0Ch]
0x6205d3: mov fs:[0],ecx
0x6205da: pop ecx
0x6205db: pop esi
0x6205dc: pop ebx
0x6205dd: add esp,0Ch
0x6205e0: ret 4
````

`sub_620570` is called by sub_6205f0. It delegates to sub_401f60 (1 callees).

### sub_6205f0 at 0x6205f0 (36 instructions)

````text
0x6205f0: push 0FFFFFFFFh
0x6205f2: push 74A4F5h
0x6205f7: mov eax,fs:[0]
0x6205fd: push eax
0x6205fe: push ecx
0x6205ff: push esi
0x620600: mov eax,ds:[858220h]
0x620605: xor eax,esp
0x620607: push eax
0x620608: lea eax,[esp+0Ch]
0x62060c: mov fs:[0],eax
0x620612: mov esi,[esp+1Ch]
0x620616: lea eax,[esi+100h]
0x62061c: mov dword ptr [esp+14h],3
0x620624: call 00622660h
0x620629: lea eax,[esi+0C0h]
0x62062f: push eax
0x620630: mov byte ptr [esp+18h],2
0x620635: call 00620570h
0x62063a: lea ecx,[esi+80h]
0x620640: push ecx
0x620641: mov byte ptr [esp+18h],1
0x620646: call 00620570h
0x62064b: lea edx,[esi+40h]
0x62064e: push edx
0x62064f: mov byte ptr [esp+18h],0
0x620654: call 00620570h
0x620659: push esi
0x62065a: mov dword ptr [esp+18h],0FFFFFFFFh
0x620662: call 00620570h
0x620667: mov ecx,[esp+0Ch]
0x62066b: mov fs:[0],ecx
0x620672: pop ecx
0x620673: pop esi
0x620674: add esp,10h
0x620677: ret 4
````

`sub_6205f0` is called by sub_610c30. It delegates to sub_620570, sub_622660 (2 callees).

### sub_622660 at 0x622660 (26 instructions)

````text
0x622660: push ebp
0x622661: mov ebp,esp
0x622663: and esp,0FFFFFFF8h
0x622666: sub esp,0Ch
0x622669: push edi
0x62266a: mov edi,eax
0x62266c: mov eax,[edi+4]
0x62266f: mov ecx,[eax]
0x622671: push eax
0x622672: push edi
0x622673: push ecx
0x622674: push edi
0x622675: lea eax,[esp+18h]
0x622679: push eax
0x62267a: call 00622780h
0x62267f: mov ecx,[edi+4]
0x622682: push ecx
0x622683: call 006516BAh
0x622688: add esp,4
0x62268b: xor eax,eax
0x62268d: mov [edi+4],eax
0x622690: mov [edi+8],eax
0x622693: pop edi
0x622694: mov esp,ebp
0x622696: pop ebp
0x622697: ret
````

`sub_622660` is called by sub_6205f0. It delegates to sub_622780, j_ORDINAL 764 (2 callees).

### sub_622780 at 0x622780 (72 instructions)

````text
0x622780: mov eax,[edi+4]
0x622783: sub esp,0Ch
0x622786: push ebx
0x622787: mov ebx,[esp+18h]
0x62278b: test ebx,ebx
0x62278d: push ebp
0x62278e: push esi
0x62278f: mov esi,[eax]
0x622791: je short 00622797h
0x622793: cmp ebx,edi
0x622795: je short 0062279Dh
0x622797: call dword ptr ds:[77D0E4h]
0x62279d: mov ebp,[esp+24h]
0x6227a1: cmp ebp,esi
0x6227a3: jne short 00622800h
0x6227a5: mov eax,[esp+28h]
0x6227a9: test eax,eax
0x6227ab: mov esi,[edi+4]
0x6227ae: je short 006227B4h
0x6227b0: cmp eax,edi
0x6227b2: je short 006227BAh
0x6227b4: call dword ptr ds:[77D0E4h]
0x6227ba: cmp [esp+2Ch],esi
0x6227be: jne short 00622800h
0x6227c0: mov ecx,[edi+4]
0x6227c3: mov edx,[ecx+4]
0x6227c6: push edx
0x6227c7: mov ecx,edi
0x6227c9: call 00622DA0h
0x6227ce: mov eax,[edi+4]
0x6227d1: mov [eax+4],eax
0x6227d4: mov eax,[edi+4]
0x6227d7: mov dword ptr [edi+8],0
0x6227de: mov [eax],eax
0x6227e0: mov eax,[edi+4]
0x6227e3: mov [eax+8],eax
0x6227e6: mov eax,[edi+4]
0x6227e9: mov ecx,[eax]
0x6227eb: mov eax,[esp+1Ch]
0x6227ef: mov [eax+4],ecx
0x6227f2: mov [eax],edi
0x6227f4: pop esi
0x6227f5: pop ebp
0x6227f6: pop ebx
0x6227f7: add esp,0Ch
0x6227fa: ret 14h
0x622800: test ebx,ebx
0x622802: je short 0062280Ah
0x622804: cmp ebx,[esp+28h]
0x622808: je short 00622810h
0x62280a: call dword ptr ds:[77D0E4h]
0x622810: cmp ebp,[esp+2Ch]
0x622814: je short 00622836h
0x622816: lea esi,[esp+20h]
0x62281a: call 00633EE0h
0x62281f: push ebp
0x622820: push ebx
0x622821: lea edx,[esp+18h]
0x622825: push edx
0x622826: push edi
0x622827: call 006229F0h
0x62282c: mov ebp,[esp+24h]
0x622830: mov ebx,[esp+20h]
0x622834: jmp short 00622800h
0x622836: mov eax,[esp+1Ch]
0x62283a: pop esi
0x62283b: mov [eax+4],ebp
0x62283e: pop ebp
0x62283f: mov [eax],ebx
0x622841: pop ebx
0x622842: add esp,0Ch
0x622845: ret 14h
````

`sub_622780` is called by sub_622660. It delegates to sub_6229f0, sub_622da0, sub_633ee0 (3 callees).

### sub_6229f0 at 0x6229f0 (246 instructions)

````text
0x6229f0: push 0FFFFFFFFh
0x6229f2: push 7410D9h
0x6229f7: mov eax,fs:[0]
0x6229fd: push eax
0x6229fe: sub esp,44h
0x622a01: push ebx
0x622a02: push ebp
0x622a03: push esi
0x622a04: push edi
0x622a05: mov eax,ds:[858220h]
0x622a0a: xor eax,esp
0x622a0c: push eax
0x622a0d: lea eax,[esp+58h]
0x622a11: mov fs:[0],eax
0x622a17: mov eax,[esp+74h]
0x622a1b: cmp byte ptr [eax+39h],0
0x622a1f: je short 00622A5Dh
0x622a21: push 7C5AECh
0x622a26: lea ecx,[esp+18h]
0x622a2a: call dword ptr ds:[77CD7Ch]
0x622a30: lea eax,[esp+14h]
0x622a34: push eax
0x622a35: lea ecx,[esp+34h]
0x622a39: mov dword ptr [esp+64h],0
0x622a41: call 00401230h
0x622a46: push 80A4F8h
0x622a4b: lea ecx,[esp+34h]
0x622a4f: push ecx
0x622a50: mov dword ptr [esp+38h],790F90h
0x622a58: call 00652AC4h
0x622a5d: lea esi,[esp+70h]
0x622a61: mov ebp,eax
0x622a63: call 00633EE0h
0x622a68: mov eax,[ebp]
0x622a6b: cmp byte ptr [eax+39h],0
0x622a6f: je short 00622A76h
0x622a71: mov edi,[ebp+8]
0x622a74: jmp short 00622A8Eh
0x622a76: mov edx,[ebp+8]
0x622a79: cmp byte ptr [edx+39h],0
0x622a7d: je short 00622A83h
0x622a7f: mov edi,eax
0x622a81: jmp short 00622A8Eh
0x622a83: mov ecx,[esp+74h]
0x622a87: cmp ecx,ebp
0x622a89: mov edi,[ecx+8]
0x622a8c: jne short 00622B02h
0x622a8e: cmp byte ptr [edi+39h],0
0x622a92: mov esi,[ebp+4]
0x622a95: jne short 00622A9Ah
0x622a97: mov [edi+4],esi
0x622a9a: mov ecx,[esp+68h]
0x622a9e: mov eax,[ecx+4]
0x622aa1: cmp [eax+4],ebp
0x622aa4: jne short 00622AABh
0x622aa6: mov [eax+4],edi
0x622aa9: jmp short 00622AB6h
0x622aab: cmp [esi],ebp
0x622aad: jne short 00622AB3h
0x622aaf: mov [esi],edi
0x622ab1: jmp short 00622AB6h
0x622ab3: mov [esi+8],edi
0x622ab6: mov edx,[ecx+4]
0x622ab9: cmp [edx],ebp
0x622abb: jne short 00622ADDh
0x622abd: cmp byte ptr [edi+39h],0
0x622ac1: je short 00622AC7h
0x622ac3: mov ecx,esi
0x622ac5: jmp short 00622ADBh
0x622ac7: mov eax,[edi]
0x622ac9: cmp byte ptr [eax+39h],0
0x622acd: mov ecx,edi
0x622acf: jne short 00622ADBh
0x622ad1: mov ecx,eax
0x622ad3: mov eax,[ecx]
0x622ad5: cmp byte ptr [eax+39h],0
0x622ad9: je short 00622AD1h
0x622adb: mov [edx],ecx
0x622add: mov eax,[esp+68h]
0x622ae1: mov ebx,[eax+4]
0x622ae4: cmp [ebx+8],ebp
0x622ae7: jne short 00622B5Eh
0x622ae9: cmp byte ptr [edi+39h],0
0x622aed: je short 00622AF6h
0x622aef: mov eax,esi
0x622af1: mov [ebx+8],eax
0x622af4: jmp short 00622B5Eh
0x622af6: mov eax,edi
0x622af8: call 00458540h
0x622afd: mov [ebx+8],eax
0x622b00: jmp short 00622B5Eh
0x622b02: mov [eax+4],ecx
0x622b05: mov edx,[ebp]
0x622b08: mov [ecx],edx
0x622b0a: cmp ecx,[ebp+8]
0x622b0d: jne short 00622B13h
0x622b0f: mov esi,ecx
0x622b11: jmp short 00622B2Dh
0x622b13: cmp byte ptr [edi+39h],0
0x622b17: mov esi,[ecx+4]
0x622b1a: jne short 00622B1Fh
0x622b1c: mov [edi+4],esi
0x622b1f: mov [esi],edi
0x622b21: mov eax,[ebp+8]
0x622b24: mov [ecx+8],eax
0x622b27: mov edx,[ebp+8]
0x622b2a: mov [edx+4],ecx
0x622b2d: mov eax,[esp+68h]
0x622b31: mov eax,[eax+4]
0x622b34: cmp [eax+4],ebp
0x622b37: jne short 00622B3Eh
0x622b39: mov [eax+4],ecx
0x622b3c: jmp short 00622B4Ch
0x622b3e: mov eax,[ebp+4]
0x622b41: cmp [eax],ebp
0x622b43: jne short 00622B49h
0x622b45: mov [eax],ecx
0x622b47: jmp short 00622B4Ch
0x622b49: mov [eax+8],ecx
0x622b4c: mov edx,[ebp+4]
0x622b4f: mov [ecx+4],edx
0x622b52: mov dl,[ebp+38h]
0x622b55: mov al,[ecx+38h]
0x622b58: mov [ecx+38h],dl
0x622b5b: mov [ebp+38h],al
0x622b5e: mov bl,1
0x622b60: cmp [ebp+38h],bl
0x622b63: jne near ptr 00622C8Ah
0x622b69: mov eax,[esp+68h]
0x622b6d: mov ecx,[eax+4]
0x622b70: cmp edi,[ecx+4]
0x622b73: je near ptr 00622C87h
0x622b79: lea esp,[esp]
0x622b80: cmp [edi+38h],bl
0x622b83: jne near ptr 00622C87h
0x622b89: mov ecx,[esi]
0x622b8b: cmp edi,ecx
0x622b8d: jne short 00622C05h
0x622b8f: mov ecx,[esi+8]
0x622b92: cmp byte ptr [ecx+38h],0
0x622b96: jne short 00622BAEh
0x622b98: mov edx,[esp+68h]
0x622b9c: mov [ecx+38h],bl
0x622b9f: push edx
0x622ba0: mov ecx,esi
0x622ba2: mov byte ptr [esi+38h],0
0x622ba6: call 005F9650h
0x622bab: mov ecx,[esi+8]
0x622bae: cmp byte ptr [ecx+39h],0
0x622bb2: jne near ptr 00622C39h
0x622bb8: mov eax,[ecx]
0x622bba: cmp [eax+38h],bl
0x622bbd: jne short 00622BC7h
0x622bbf: mov edx,[ecx+8]
0x622bc2: cmp [edx+38h],bl
0x622bc5: je short 00622C35h
0x622bc7: mov eax,[ecx+8]
0x622bca: cmp [eax+38h],bl
0x622bcd: jne short 00622BE5h
0x622bcf: mov edx,[ecx]
0x622bd1: mov eax,[esp+68h]
0x622bd5: mov [edx+38h],bl
0x622bd8: push eax
0x622bd9: mov byte ptr [ecx+38h],0
0x622bdd: call 004DD9C0h
0x622be2: mov ecx,[esi+8]
0x622be5: mov dl,[esi+38h]
0x622be8: mov [ecx+38h],dl
0x622beb: mov [esi+38h],bl
0x622bee: mov eax,[ecx+8]
0x622bf1: mov ecx,[esp+68h]
0x622bf5: push ecx
0x622bf6: mov ecx,esi
0x622bf8: mov [eax+38h],bl
0x622bfb: call 005F9650h
0x622c00: jmp near ptr 00622C87h
0x622c05: cmp byte ptr [ecx+38h],0
0x622c09: jne short 00622C20h
0x622c0b: mov eax,[esp+68h]
0x622c0f: mov [ecx+38h],bl
0x622c12: push eax
0x622c13: mov ecx,esi
0x622c15: mov byte ptr [esi+38h],0
0x622c19: call 004DD9C0h
0x622c1e: mov ecx,[esi]
0x622c20: cmp byte ptr [ecx+39h],0
0x622c24: jne short 00622C39h
0x622c26: mov edx,[ecx+8]
0x622c29: cmp [edx+38h],bl
0x622c2c: jne short 00622C50h
0x622c2e: mov eax,[ecx]
0x622c30: cmp [eax+38h],bl
0x622c33: jne short 00622C50h
0x622c35: mov byte ptr [ecx+38h],0
0x622c39: mov ecx,[esp+68h]
0x622c3d: mov edx,[ecx+4]
0x622c40: mov edi,esi
0x622c42: cmp edi,[edx+4]
0x622c45: mov esi,[esi+4]
0x622c48: jne near ptr 00622B80h
0x622c4e: jmp short 00622C87h
0x622c50: mov edx,[ecx]
0x622c52: cmp [edx+38h],bl
0x622c55: jne short 00622C6Dh
0x622c57: mov eax,[ecx+8]
0x622c5a: mov edx,[esp+68h]
0x622c5e: mov [eax+38h],bl
0x622c61: push edx
0x622c62: mov byte ptr [ecx+38h],0
0x622c66: call 005F9650h
0x622c6b: mov ecx,[esi]
0x622c6d: mov al,[esi+38h]
0x622c70: mov edx,[esp+68h]
0x622c74: mov [ecx+38h],al
0x622c77: mov [esi+38h],bl
0x622c7a: mov ecx,[ecx]
0x622c7c: mov [ecx+38h],bl
0x622c7f: push edx
0x622c80: mov ecx,esi
0x622c82: call 004DD9C0h
0x622c87: mov [edi+38h],bl
0x622c8a: lea ecx,[ebp+1Ch]
0x622c8d: call dword ptr ds:[77CD74h]
0x622c93: push ebp
0x622c94: call 006516BAh
0x622c99: mov ecx,[esp+6Ch]
0x622c9d: mov eax,[ecx+8]
0x622ca0: add esp,4
0x622ca3: test eax,eax
0x622ca5: jbe short 00622CADh
0x622ca7: add eax,0FFFFFFFFh
0x622caa: mov [ecx+8],eax
0x622cad: mov eax,[esp+6Ch]
0x622cb1: mov ecx,[esp+70h]
0x622cb5: mov edx,[esp+74h]
0x622cb9: mov [eax],ecx
0x622cbb: mov [eax+4],edx
0x622cbe: mov ecx,[esp+58h]
0x622cc2: mov fs:[0],ecx
0x622cc9: pop ecx
0x622cca: pop edi
0x622ccb: pop esi
0x622ccc: pop ebp
0x622ccd: pop ebx
0x622cce: add esp,50h
0x622cd1: ret 10h
````

`sub_6229f0` is called by sub_622780. It delegates to sub_401230, sub_458540, sub_4dd9c0 (7 callees).

### sub_622da0 at 0x622da0 (25 instructions)

````text
0x622da0: push ebx
0x622da1: push esi
0x622da2: push edi
0x622da3: mov edi,[esp+10h]
0x622da7: cmp byte ptr [edi+39h],0
0x622dab: mov ebx,ecx
0x622dad: mov esi,edi
0x622daf: jne short 00622DD8h
0x622db1: mov eax,[esi+8]
0x622db4: push eax
0x622db5: mov ecx,ebx
0x622db7: call 00622DA0h
0x622dbc: mov esi,[esi]
0x622dbe: lea ecx,[edi+1Ch]
0x622dc1: call dword ptr ds:[77CD74h]
0x622dc7: push edi
0x622dc8: call 006516BAh
0x622dcd: add esp,4
0x622dd0: cmp byte ptr [esi+39h],0
0x622dd4: mov edi,esi
0x622dd6: je short 00622DB1h
0x622dd8: pop edi
0x622dd9: pop esi
0x622dda: pop ebx
0x622ddb: ret 4
````

`sub_622da0` is called by sub_622780, sub_622da0. It delegates to sub_622da0, j_ORDINAL 764 (2 callees).

### sub_624350 at 0x624350 (150 instructions)

````text
0x624350: push 0FFFFFFFFh
0x624352: push 74A467h
0x624357: mov eax,fs:[0]
0x62435d: push eax
0x62435e: push ecx
0x62435f: push ebx
0x624360: push esi
0x624361: push edi
0x624362: mov eax,ds:[858220h]
0x624367: xor eax,esp
0x624369: push eax
0x62436a: lea eax,[esp+14h]
0x62436e: mov fs:[0],eax
0x624374: mov esi,[esp+24h]
0x624378: xor edi,edi
0x62437a: mov dword ptr [esi],7F66DCh
0x624380: mov [esi+8],edi
0x624383: mov [esi+0Ch],edi
0x624386: mov [esi+10h],edi
0x624389: mov [esp+1Ch],edi
0x62438d: mov [esi+18h],edi
0x624390: mov [esi+1Ch],edi
0x624393: mov [esi+20h],edi
0x624396: mov bl,1
0x624398: mov [esp+1Ch],bl
0x62439c: call 0050FCB0h
0x6243a1: mov [esi+28h],eax
0x6243a4: mov [eax+21h],bl
0x6243a7: mov eax,[esi+28h]
0x6243aa: mov [eax+4],eax
0x6243ad: mov eax,[esi+28h]
0x6243b0: mov [eax],eax
0x6243b2: mov eax,[esi+28h]
0x6243b5: mov [eax+8],eax
0x6243b8: mov [esi+2Ch],edi
0x6243bb: mov [esi+34h],edi
0x6243be: mov [esi+38h],edi
0x6243c1: mov [esi+3Ch],edi
0x6243c4: mov byte ptr [esp+1Ch],3
0x6243c9: call 0050FCB0h
0x6243ce: mov [esi+44h],eax
0x6243d1: mov [eax+21h],bl
0x6243d4: mov eax,[esi+44h]
0x6243d7: mov [eax+4],eax
0x6243da: mov eax,[esi+44h]
0x6243dd: mov [eax],eax
0x6243df: mov eax,[esi+44h]
0x6243e2: mov [eax+8],eax
0x6243e5: mov [esi+48h],edi
0x6243e8: mov [esi+50h],edi
0x6243eb: mov [esi+54h],edi
0x6243ee: mov [esi+58h],edi
0x6243f1: mov byte ptr [esp+1Ch],5
0x6243f6: call 005735D0h
0x6243fb: mov [esi+60h],eax
0x6243fe: mov [eax+2Dh],bl
0x624401: mov eax,[esi+60h]
0x624404: mov [eax+4],eax
0x624407: mov eax,[esi+60h]
0x62440a: mov [eax],eax
0x62440c: mov eax,[esi+60h]
0x62440f: mov [eax+8],eax
0x624412: mov [esi+64h],edi
0x624415: mov byte ptr [esp+1Ch],6
0x62441a: call 004B4FA0h
0x62441f: mov [esi+6Ch],eax
0x624422: mov [eax+0Fh],bl
0x624425: mov eax,[esi+6Ch]
0x624428: mov [eax+4],eax
0x62442b: mov eax,[esi+6Ch]
0x62442e: mov [eax],eax
0x624430: mov eax,[esi+6Ch]
0x624433: mov [eax+8],eax
0x624436: mov [esi+70h],edi
0x624439: mov byte ptr [esp+1Ch],7
0x62443e: call 004B53B0h
0x624443: mov [esi+78h],eax
0x624446: mov [eax+11h],bl
0x624449: mov eax,[esi+78h]
0x62444c: mov [eax+4],eax
0x62444f: mov eax,[esi+78h]
0x624452: mov [eax],eax
0x624454: mov eax,[esi+78h]
0x624457: mov [eax+8],eax
0x62445a: mov [esi+7Ch],edi
0x62445d: mov byte ptr [esp+1Ch],8
0x624462: call 005735D0h
0x624467: mov [esi+84h],eax
0x62446d: mov [eax+2Dh],bl
0x624470: mov eax,[esi+84h]
0x624476: mov [eax+4],eax
0x624479: mov eax,[esi+84h]
0x62447f: mov [eax],eax
0x624481: mov eax,[esi+84h]
0x624487: mov [eax+8],eax
0x62448a: mov [esi+88h],edi
0x624490: mov byte ptr [esp+1Ch],9
0x624495: call 005735D0h
0x62449a: mov [esi+90h],eax
0x6244a0: mov [eax+2Dh],bl
0x6244a3: mov eax,[esi+90h]
0x6244a9: mov [eax+4],eax
0x6244ac: mov eax,[esi+90h]
0x6244b2: mov [eax],eax
0x6244b4: mov eax,[esi+90h]
0x6244ba: mov [eax+8],eax
0x6244bd: mov [esi+94h],edi
0x6244c3: mov byte ptr [esp+1Ch],0Ah
0x6244c8: call 004B4FA0h
0x6244cd: mov [esi+9Ch],eax
0x6244d3: mov [eax+0Fh],bl
0x6244d6: mov eax,[esi+9Ch]
0x6244dc: mov [eax+4],eax
0x6244df: mov eax,[esi+9Ch]
0x6244e5: mov [eax],eax
0x6244e7: mov eax,[esi+9Ch]
0x6244ed: mov [eax+8],eax
0x6244f0: mov [esi+0A0h],edi
0x6244f6: mov byte ptr [esp+1Ch],0Bh
0x6244fb: call 004B53B0h
0x624500: mov [esi+0A8h],eax
0x624506: mov [eax+11h],bl
0x624509: mov eax,[esi+0A8h]
0x62450f: mov [eax+4],eax
0x624512: mov eax,[esi+0A8h]
0x624518: mov [eax],eax
0x62451a: mov eax,[esi+0A8h]
0x624520: mov [eax+8],eax
0x624523: mov [esi+0ACh],edi
0x624529: mov byte ptr [esp+1Ch],0Ch
0x62452e: call 005735D0h
0x624533: mov [esi+0B4h],eax
0x624539: mov [eax+2Dh],bl
0x62453c: mov eax,[esi+0B4h]
0x624542: mov [eax+4],eax
0x624545: mov eax,[esi+0B4h]
0x62454b: mov [eax],eax
0x62454d: mov eax,[esi+0B4h]
0x624553: mov [eax+8],eax
0x624556: mov [esi+0B8h],edi
0x62455c: mov [esi+0BCh],bl
0x624562: mov eax,esi
0x624564: mov ecx,[esp+14h]
0x624568: mov fs:[0],ecx
0x62456f: pop ecx
0x624570: pop edi
0x624571: pop esi
0x624572: pop ebx
0x624573: add esp,10h
0x624576: ret 4
````

`sub_624350` is called by sub_610980, ?get_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@CAAAVCSigNoConfig@@XZ. It delegates to sub_4b4fa0, sub_4b53b0, sub_50fcb0 (4 callees).

### sub_6245b0 at 0x6245b0 (105 instructions)

````text
0x6245b0: push 0FFFFFFFFh
0x6245b2: push 74F0E7h
0x6245b7: mov eax,fs:[0]
0x6245bd: push eax
0x6245be: sub esp,8
0x6245c1: push ebx
0x6245c2: push esi
0x6245c3: push edi
0x6245c4: mov eax,ds:[858220h]
0x6245c9: xor eax,esp
0x6245cb: push eax
0x6245cc: lea eax,[esp+18h]
0x6245d0: mov fs:[0],eax
0x6245d6: mov esi,ecx
0x6245d8: mov [esp+14h],esi
0x6245dc: mov dword ptr [esi],7F66DCh
0x6245e2: lea eax,[esi+0B0h]
0x6245e8: mov dword ptr [esp+20h],0Ch
0x6245f0: call 004B3BA0h
0x6245f5: lea eax,[esi+0A4h]
0x6245fb: mov byte ptr [esp+20h],0Bh
0x624600: call 004B4320h
0x624605: lea eax,[esi+98h]
0x62460b: mov byte ptr [esp+20h],0Ah
0x624610: call 004B3FF0h
0x624615: lea eax,[esi+8Ch]
0x62461b: mov byte ptr [esp+20h],9
0x624620: call 00465FB0h
0x624625: lea eax,[esi+80h]
0x62462b: mov byte ptr [esp+20h],8
0x624630: call 004B3BA0h
0x624635: lea eax,[esi+74h]
0x624638: mov byte ptr [esp+20h],7
0x62463d: call 004B4320h
0x624642: lea eax,[esi+68h]
0x624645: mov byte ptr [esp+20h],6
0x62464a: call 004B3FF0h
0x62464f: lea eax,[esi+5Ch]
0x624652: mov byte ptr [esp+20h],5
0x624657: call 00465FB0h
0x62465c: mov byte ptr [esp+20h],4
0x624661: mov eax,[esi+50h]
0x624664: xor ebx,ebx
0x624666: cmp eax,ebx
0x624668: je short 00624684h
0x62466a: mov ecx,[esp+14h]
0x62466e: mov edi,[esi+54h]
0x624671: push ecx
0x624672: push eax
0x624673: call 004AB3E0h
0x624678: mov eax,[esi+50h]
0x62467b: push eax
0x62467c: call 006516BAh
0x624681: add esp,0Ch
0x624684: lea eax,[esi+40h]
0x624687: mov [esi+50h],ebx
0x62468a: mov [esi+54h],ebx
0x62468d: mov [esi+58h],ebx
0x624690: mov byte ptr [esp+20h],3
0x624695: call 00627720h
0x62469a: mov byte ptr [esp+20h],2
0x62469f: mov eax,[esi+34h]
0x6246a2: cmp eax,ebx
0x6246a4: je short 006246C0h
0x6246a6: mov edx,[esp+14h]
0x6246aa: mov edi,[esi+38h]
0x6246ad: push edx
0x6246ae: push eax
0x6246af: call 004AB3E0h
0x6246b4: mov eax,[esi+34h]
0x6246b7: push eax
0x6246b8: call 006516BAh
0x6246bd: add esp,0Ch
0x6246c0: lea eax,[esi+24h]
0x6246c3: mov [esi+34h],ebx
0x6246c6: mov [esi+38h],ebx
0x6246c9: mov [esi+3Ch],ebx
0x6246cc: mov byte ptr [esp+20h],1
0x6246d1: call 00627720h
0x6246d6: mov eax,[esi+18h]
0x6246d9: cmp eax,ebx
0x6246db: je short 006246E6h
0x6246dd: push eax
0x6246de: call 006516BAh
0x6246e3: add esp,4
0x6246e6: mov [esi+18h],ebx
0x6246e9: mov [esi+1Ch],ebx
0x6246ec: mov [esi+20h],ebx
0x6246ef: mov eax,[esi+8]
0x6246f2: cmp eax,ebx
0x6246f4: je short 006246FFh
0x6246f6: push eax
0x6246f7: call 006516BAh
0x6246fc: add esp,4
0x6246ff: mov [esi+8],ebx
0x624702: mov [esi+0Ch],ebx
0x624705: mov [esi+10h],ebx
0x624708: mov ecx,[esp+18h]
0x62470c: mov fs:[0],ecx
0x624713: pop ecx
0x624714: pop edi
0x624715: pop esi
0x624716: pop ebx
0x624717: add esp,14h
0x62471a: ret
````

`sub_6245b0` is called by sub_610c30, sub_77b4f0. It delegates to sub_465fb0, sub_4ab3e0, sub_4b3ba0 (7 callees).

### ?get_mutable_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@SAAAVCSigNoConfig@@XZ at 0x6273a0 (4 instructions)

````text
0x6273a0: push ecx
0x6273a1: call 00627890h
0x6273a6: pop ecx
0x6273a7: ret
````

`?get_mutable_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@SAAAVCSigNoConfig@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to ?get_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@CAAAVCSigNoConfig@@XZ (1 callees).

### sub_6273d0 at 0x6273d0 (72 instructions)

````text
0x6273d0: mov eax,[edi+4]
0x6273d3: sub esp,0Ch
0x6273d6: push ebx
0x6273d7: mov ebx,[esp+18h]
0x6273db: test ebx,ebx
0x6273dd: push ebp
0x6273de: push esi
0x6273df: mov esi,[eax]
0x6273e1: je short 006273E7h
0x6273e3: cmp ebx,edi
0x6273e5: je short 006273EDh
0x6273e7: call dword ptr ds:[77D0E4h]
0x6273ed: mov ebp,[esp+24h]
0x6273f1: cmp ebp,esi
0x6273f3: jne short 00627450h
0x6273f5: mov eax,[esp+28h]
0x6273f9: test eax,eax
0x6273fb: mov esi,[edi+4]
0x6273fe: je short 00627404h
0x627400: cmp eax,edi
0x627402: je short 0062740Ah
0x627404: call dword ptr ds:[77D0E4h]
0x62740a: cmp [esp+2Ch],esi
0x62740e: jne short 00627450h
0x627410: mov ecx,[edi+4]
0x627413: mov edx,[ecx+4]
0x627416: push edx
0x627417: mov ecx,edi
0x627419: call 00627510h
0x62741e: mov eax,[edi+4]
0x627421: mov [eax+4],eax
0x627424: mov eax,[edi+4]
0x627427: mov dword ptr [edi+8],0
0x62742e: mov [eax],eax
0x627430: mov eax,[edi+4]
0x627433: mov [eax+8],eax
0x627436: mov eax,[edi+4]
0x627439: mov ecx,[eax]
0x62743b: mov eax,[esp+1Ch]
0x62743f: mov [eax+4],ecx
0x627442: mov [eax],edi
0x627444: pop esi
0x627445: pop ebp
0x627446: pop ebx
0x627447: add esp,0Ch
0x62744a: ret 14h
0x627450: test ebx,ebx
0x627452: je short 0062745Ah
0x627454: cmp ebx,[esp+28h]
0x627458: je short 00627460h
0x62745a: call dword ptr ds:[77D0E4h]
0x627460: cmp ebp,[esp+2Ch]
0x627464: je short 00627486h
0x627466: lea esi,[esp+20h]
0x62746a: call 00415E60h
0x62746f: push ebp
0x627470: push ebx
0x627471: lea edx,[esp+18h]
0x627475: push edx
0x627476: push edi
0x627477: call 00627940h
0x62747c: mov ebp,[esp+24h]
0x627480: mov ebx,[esp+20h]
0x627484: jmp short 00627450h
0x627486: mov eax,[esp+1Ch]
0x62748a: pop esi
0x62748b: mov [eax+4],ebp
0x62748e: pop ebp
0x62748f: mov [eax],ebx
0x627491: pop ebx
0x627492: add esp,0Ch
0x627495: ret 14h
````

`sub_6273d0` is called by sub_627720. It delegates to sub_415e60, sub_627510, sub_627940 (3 callees).

### sub_627510 at 0x627510 (42 instructions)

````text
0x627510: push ebx
0x627511: push ebp
0x627512: push esi
0x627513: mov esi,[esp+10h]
0x627517: cmp byte ptr [esi+21h],0
0x62751b: mov ebx,ecx
0x62751d: mov ebp,esi
0x62751f: jne short 00627570h
0x627521: push edi
0x627522: mov eax,[ebp+8]
0x627525: push eax
0x627526: mov ecx,ebx
0x627528: call 00627510h
0x62752d: mov eax,[esi+14h]
0x627530: mov ebp,[ebp]
0x627533: xor ecx,ecx
0x627535: cmp eax,ecx
0x627537: je short 00627555h
0x627539: mov ecx,[esp+14h]
0x62753d: mov edi,[esi+18h]
0x627540: push ecx
0x627541: push eax
0x627542: call 004AB3E0h
0x627547: mov edx,[esi+14h]
0x62754a: push edx
0x62754b: call 006516BAh
0x627550: add esp,0Ch
0x627553: xor ecx,ecx
0x627555: push esi
0x627556: mov [esi+14h],ecx
0x627559: mov [esi+18h],ecx
0x62755c: mov [esi+1Ch],ecx
0x62755f: call 006516BAh
0x627564: add esp,4
0x627567: cmp byte ptr [ebp+21h],0
0x62756b: mov esi,ebp
0x62756d: je short 00627522h
0x62756f: pop edi
0x627570: pop esi
0x627571: pop ebp
0x627572: pop ebx
0x627573: ret 4
````

`sub_627510` is called by sub_6273d0, sub_627510. It delegates to sub_4ab3e0, sub_627510, j_ORDINAL 764 (3 callees).

### sub_627720 at 0x627720 (26 instructions)

````text
0x627720: push ebp
0x627721: mov ebp,esp
0x627723: and esp,0FFFFFFF8h
0x627726: sub esp,0Ch
0x627729: push edi
0x62772a: mov edi,eax
0x62772c: mov eax,[edi+4]
0x62772f: mov ecx,[eax]
0x627731: push eax
0x627732: push edi
0x627733: push ecx
0x627734: push edi
0x627735: lea eax,[esp+18h]
0x627739: push eax
0x62773a: call 006273D0h
0x62773f: mov ecx,[edi+4]
0x627742: push ecx
0x627743: call 006516BAh
0x627748: add esp,4
0x62774b: xor eax,eax
0x62774d: mov [edi+4],eax
0x627750: mov [edi+8],eax
0x627753: pop edi
0x627754: mov esp,ebp
0x627756: pop ebp
0x627757: ret
````

`sub_627720` is called by sub_6245b0. It delegates to sub_6273d0, j_ORDINAL 764 (2 callees).

### ?get_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@CAAAVCSigNoConfig@@XZ at 0x627890 (27 instructions)

````text
0x627890: push 0FFFFFFFFh
0x627892: push 75451Eh
0x627897: mov eax,fs:[0]
0x62789d: push eax
0x62789e: mov eax,ds:[858220h]
0x6278a3: push ecx
0x6278a4: xor eax,esp
0x6278a6: push eax
0x6278a7: lea eax,[esp+8]
0x6278ab: mov fs:[0],eax
0x6278b1: mov eax,1
0x6278b6: test ds:[875EB0h],al
0x6278bc: jne short 006278EDh
0x6278be: or ds:[875EB0h],eax
0x6278c4: push 875DF0h
0x6278c9: mov dword ptr [esp+14h],0
0x6278d1: call 00624350h
0x6278d6: push 77B4F0h
0x6278db: mov dword ptr ds:[875DF0h],7F66E4h
0x6278e5: call 006527EDh
0x6278ea: add esp,4
0x6278ed: mov eax,875DF0h
0x6278f2: mov ecx,[esp+8]
0x6278f6: mov fs:[0],ecx
0x6278fd: pop ecx
0x6278fe: add esp,10h
0x627901: ret
````

`?get_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@CAAAVCSigNoConfig@@XZ` is called by ?get_mutable_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@SAAAVCSigNoConfig@@XZ. It delegates to sub_624350, sub_6527ed (2 callees).

### sub_627940 at 0x627940 (251 instructions)

````text
0x627940: push 0FFFFFFFFh
0x627942: push 7410D9h
0x627947: mov eax,fs:[0]
0x62794d: push eax
0x62794e: sub esp,44h
0x627951: push ebx
0x627952: push ebp
0x627953: push esi
0x627954: push edi
0x627955: mov eax,ds:[858220h]
0x62795a: xor eax,esp
0x62795c: push eax
0x62795d: lea eax,[esp+58h]
0x627961: mov fs:[0],eax
0x627967: mov eax,[esp+74h]
0x62796b: cmp byte ptr [eax+21h],0
0x62796f: je short 006279ADh
0x627971: push 7C5AECh
0x627976: lea ecx,[esp+18h]
0x62797a: call dword ptr ds:[77CD7Ch]
0x627980: lea eax,[esp+14h]
0x627984: push eax
0x627985: lea ecx,[esp+34h]
0x627989: mov dword ptr [esp+64h],0
0x627991: call 00401230h
0x627996: push 80A4F8h
0x62799b: lea ecx,[esp+34h]
0x62799f: push ecx
0x6279a0: mov dword ptr [esp+38h],790F90h
0x6279a8: call 00652AC4h
0x6279ad: lea esi,[esp+70h]
0x6279b1: mov ebp,eax
0x6279b3: call 00415E60h
0x6279b8: mov eax,[ebp]
0x6279bb: cmp byte ptr [eax+21h],0
0x6279bf: je short 006279C6h
0x6279c1: mov edi,[ebp+8]
0x6279c4: jmp short 006279DEh
0x6279c6: mov edx,[ebp+8]
0x6279c9: cmp byte ptr [edx+21h],0
0x6279cd: je short 006279D3h
0x6279cf: mov edi,eax
0x6279d1: jmp short 006279DEh
0x6279d3: mov ecx,[esp+74h]
0x6279d7: cmp ecx,ebp
0x6279d9: mov edi,[ecx+8]
0x6279dc: jne short 00627A49h
0x6279de: cmp byte ptr [edi+21h],0
0x6279e2: mov esi,[ebp+4]
0x6279e5: jne short 006279EAh
0x6279e7: mov [edi+4],esi
0x6279ea: mov edx,[esp+68h]
0x6279ee: mov eax,[edx+4]
0x6279f1: cmp [eax+4],ebp
0x6279f4: jne short 006279FBh
0x6279f6: mov [eax+4],edi
0x6279f9: jmp short 00627A06h
0x6279fb: cmp [esi],ebp
0x6279fd: jne short 00627A03h
0x6279ff: mov [esi],edi
0x627a01: jmp short 00627A06h
0x627a03: mov [esi+8],edi
0x627a06: mov ebx,[edx+4]
0x627a09: cmp [ebx],ebp
0x627a0b: jne short 00627A24h
0x627a0d: cmp byte ptr [edi+21h],0
0x627a11: je short 00627A17h
0x627a13: mov eax,esi
0x627a15: jmp short 00627A22h
0x627a17: mov eax,edi
0x627a19: call 00627CE0h
0x627a1e: mov edx,[esp+68h]
0x627a22: mov [ebx],eax
0x627a24: mov ebx,[edx+4]
0x627a27: cmp [ebx+8],ebp
0x627a2a: jne short 00627AA9h
0x627a2c: cmp byte ptr [edi+21h],0
0x627a30: je short 00627A39h
0x627a32: mov eax,esi
0x627a34: mov [ebx+8],eax
0x627a37: jmp short 00627AA9h
0x627a39: mov eax,edi
0x627a3b: call 005B0480h
0x627a40: mov edx,[esp+68h]
0x627a44: mov [ebx+8],eax
0x627a47: jmp short 00627AA9h
0x627a49: mov [eax+4],ecx
0x627a4c: mov eax,[ebp]
0x627a4f: mov [ecx],eax
0x627a51: cmp ecx,[ebp+8]
0x627a54: jne short 00627A5Ah
0x627a56: mov esi,ecx
0x627a58: jmp short 00627A74h
0x627a5a: cmp byte ptr [edi+21h],0
0x627a5e: mov esi,[ecx+4]
0x627a61: jne short 00627A66h
0x627a63: mov [edi+4],esi
0x627a66: mov [esi],edi
0x627a68: mov edx,[ebp+8]
0x627a6b: mov [ecx+8],edx
0x627a6e: mov eax,[ebp+8]
0x627a71: mov [eax+4],ecx
0x627a74: mov edx,[esp+68h]
0x627a78: mov eax,[edx+4]
0x627a7b: cmp [eax+4],ebp
0x627a7e: jne short 00627A85h
0x627a80: mov [eax+4],ecx
0x627a83: jmp short 00627A93h
0x627a85: mov eax,[ebp+4]
0x627a88: cmp [eax],ebp
0x627a8a: jne short 00627A90h
0x627a8c: mov [eax],ecx
0x627a8e: jmp short 00627A93h
0x627a90: mov [eax+8],ecx
0x627a93: mov eax,[ebp+4]
0x627a96: mov [ecx+4],eax
0x627a99: mov dl,[ebp+20h]
0x627a9c: mov al,[ecx+20h]
0x627a9f: mov [ecx+20h],dl
0x627aa2: mov edx,[esp+68h]
0x627aa6: mov [ebp+20h],al
0x627aa9: mov bl,1
0x627aab: cmp [ebp+20h],bl
0x627aae: jne near ptr 00627BB7h
0x627ab4: mov eax,[edx+4]
0x627ab7: cmp edi,[eax+4]
0x627aba: je near ptr 00627BB4h
0x627ac0: cmp [edi+20h],bl
0x627ac3: jne near ptr 00627BB4h
0x627ac9: mov ecx,[esi]
0x627acb: cmp edi,ecx
0x627acd: jne short 00627B3Ah
0x627acf: mov ecx,[esi+8]
0x627ad2: cmp byte ptr [ecx+20h],0
0x627ad6: jne short 00627AEEh
0x627ad8: mov [ecx+20h],bl
0x627adb: push edx
0x627adc: mov ecx,esi
0x627ade: mov byte ptr [esi+20h],0
0x627ae2: call 005484D0h
0x627ae7: mov ecx,[esi+8]
0x627aea: mov edx,[esp+68h]
0x627aee: cmp byte ptr [ecx+21h],0
0x627af2: jne short 00627B6Eh
0x627af4: mov eax,[ecx]
0x627af6: cmp [eax+20h],bl
0x627af9: jne short 00627B03h
0x627afb: mov eax,[ecx+8]
0x627afe: cmp [eax+20h],bl
0x627b01: je short 00627B6Ah
0x627b03: mov eax,[ecx+8]
0x627b06: cmp [eax+20h],bl
0x627b09: jne short 00627B21h
0x627b0b: mov eax,[ecx]
0x627b0d: mov [eax+20h],bl
0x627b10: push edx
0x627b11: mov byte ptr [ecx+20h],0
0x627b15: call 0050F8B0h
0x627b1a: mov ecx,[esi+8]
0x627b1d: mov edx,[esp+68h]
0x627b21: mov al,[esi+20h]
0x627b24: mov [ecx+20h],al
0x627b27: mov [esi+20h],bl
0x627b2a: mov ecx,[ecx+8]
0x627b2d: mov [ecx+20h],bl
0x627b30: push edx
0x627b31: mov ecx,esi
0x627b33: call 005484D0h
0x627b38: jmp short 00627BB4h
0x627b3a: cmp byte ptr [ecx+20h],0
0x627b3e: jne short 00627B55h
0x627b40: mov [ecx+20h],bl
0x627b43: push edx
0x627b44: mov ecx,esi
0x627b46: mov byte ptr [esi+20h],0
0x627b4a: call 0050F8B0h
0x627b4f: mov ecx,[esi]
0x627b51: mov edx,[esp+68h]
0x627b55: cmp byte ptr [ecx+21h],0
0x627b59: jne short 00627B6Eh
0x627b5b: mov eax,[ecx+8]
0x627b5e: cmp [eax+20h],bl
0x627b61: jne short 00627B81h
0x627b63: mov eax,[ecx]
0x627b65: cmp [eax+20h],bl
0x627b68: jne short 00627B81h
0x627b6a: mov byte ptr [ecx+20h],0
0x627b6e: mov ecx,[edx+4]
0x627b71: mov edi,esi
0x627b73: cmp edi,[ecx+4]
0x627b76: mov esi,[esi+4]
0x627b79: jne near ptr 00627AC0h
0x627b7f: jmp short 00627BB4h
0x627b81: mov eax,[ecx]
0x627b83: cmp [eax+20h],bl
0x627b86: jne short 00627B9Eh
0x627b88: mov eax,[ecx+8]
0x627b8b: mov [eax+20h],bl
0x627b8e: push edx
0x627b8f: mov byte ptr [ecx+20h],0
0x627b93: call 005484D0h
0x627b98: mov ecx,[esi]
0x627b9a: mov edx,[esp+68h]
0x627b9e: mov al,[esi+20h]
0x627ba1: mov [ecx+20h],al
0x627ba4: mov [esi+20h],bl
0x627ba7: mov ecx,[ecx]
0x627ba9: mov [ecx+20h],bl
0x627bac: push edx
0x627bad: mov ecx,esi
0x627baf: call 0050F8B0h
0x627bb4: mov [edi+20h],bl
0x627bb7: mov eax,[ebp+14h]
0x627bba: xor esi,esi
0x627bbc: cmp eax,esi
0x627bbe: je short 00627BDAh
0x627bc0: mov edx,[esp+68h]
0x627bc4: mov edi,[ebp+18h]
0x627bc7: push edx
0x627bc8: push eax
0x627bc9: call 004AB3E0h
0x627bce: mov eax,[ebp+14h]
0x627bd1: push eax
0x627bd2: call 006516BAh
0x627bd7: add esp,0Ch
0x627bda: push ebp
0x627bdb: mov [ebp+14h],esi
0x627bde: mov [ebp+18h],esi
0x627be1: mov [ebp+1Ch],esi
0x627be4: call 006516BAh
0x627be9: mov ecx,[esp+6Ch]
0x627bed: mov eax,[ecx+8]
0x627bf0: add esp,4
0x627bf3: cmp eax,esi
0x627bf5: jbe short 00627BFDh
0x627bf7: add eax,0FFFFFFFFh
0x627bfa: mov [ecx+8],eax
0x627bfd: mov eax,[esp+6Ch]
0x627c01: mov ecx,[esp+70h]
0x627c05: mov edx,[esp+74h]
0x627c09: mov [eax],ecx
0x627c0b: mov [eax+4],edx
0x627c0e: mov ecx,[esp+58h]
0x627c12: mov fs:[0],ecx
0x627c19: pop ecx
0x627c1a: pop edi
0x627c1b: pop esi
0x627c1c: pop ebp
0x627c1d: pop ebx
0x627c1e: add esp,50h
0x627c21: ret 10h
````

`sub_627940` is called by sub_6273d0. It delegates to sub_401230, sub_415e60, sub_4ab3e0 (9 callees).

### sub_627ce0 at 0x627ce0 (8 instructions)

````text
0x627ce0: mov ecx,[eax]
0x627ce2: cmp byte ptr [ecx+21h],0
0x627ce6: jne short 00627CF2h
0x627ce8: mov eax,ecx
0x627cea: mov ecx,[eax]
0x627cec: cmp byte ptr [ecx+21h],0
0x627cf0: je short 00627CE8h
0x627cf2: ret
````

`sub_627ce0` is called by sub_627940. It calls nothing else.

### sub_628750 at 0x628750 (36 instructions)

````text
0x628750: push 0FFFFFFFFh
0x628752: push 74F003h
0x628757: mov eax,fs:[0]
0x62875d: push eax
0x62875e: push ecx
0x62875f: push esi
0x628760: mov eax,ds:[858220h]
0x628765: xor eax,esp
0x628767: push eax
0x628768: lea eax,[esp+0Ch]
0x62876c: mov fs:[0],eax
0x628772: mov esi,[esp+1Ch]
0x628776: call 0062B5F0h
0x62877b: mov [esi+4],eax
0x62877e: mov byte ptr [eax+89h],1
0x628785: mov eax,[esi+4]
0x628788: mov [eax+4],eax
0x62878b: mov eax,[esi+4]
0x62878e: mov [eax],eax
0x628790: mov eax,[esi+4]
0x628793: mov [eax+8],eax
0x628796: xor eax,eax
0x628798: mov [esi+8],eax
0x62879b: mov [esi+10h],eax
0x62879e: mov [esi+14h],eax
0x6287a1: mov [esi+18h],eax
0x6287a4: mov [esi+20h],eax
0x6287a7: mov [esi+24h],eax
0x6287aa: mov [esi+28h],eax
0x6287ad: mov eax,esi
0x6287af: mov ecx,[esp+0Ch]
0x6287b3: mov fs:[0],ecx
0x6287ba: pop ecx
0x6287bb: pop esi
0x6287bc: add esp,10h
0x6287bf: ret 4
````

`sub_628750` is called by sub_610980. It delegates to sub_62b5f0 (1 callees).

### sub_6287e0 at 0x6287e0 (28 instructions)

````text
0x6287e0: push 0FFFFFFFFh
0x6287e2: push 74F003h
0x6287e7: mov eax,fs:[0]
0x6287ed: push eax
0x6287ee: push ebx
0x6287ef: push esi
0x6287f0: mov eax,ds:[858220h]
0x6287f5: xor eax,esp
0x6287f7: push eax
0x6287f8: lea eax,[esp+0Ch]
0x6287fc: mov fs:[0],eax
0x628802: mov esi,[esp+1Ch]
0x628806: lea ebx,[esi+1Ch]
0x628809: mov dword ptr [esp+14h],1
0x628811: call 004EF1A0h
0x628816: lea ebx,[esi+0Ch]
0x628819: mov byte ptr [esp+14h],0
0x62881e: call 004EF1A0h
0x628823: mov eax,esi
0x628825: mov dword ptr [esp+14h],0FFFFFFFFh
0x62882d: call 0062AAF0h
0x628832: mov ecx,[esp+0Ch]
0x628836: mov fs:[0],ecx
0x62883d: pop ecx
0x62883e: pop esi
0x62883f: pop ebx
0x628840: add esp,0Ch
0x628843: ret 4
````

`sub_6287e0` is called by sub_610c30. It delegates to sub_4ef1a0, sub_62aaf0 (2 callees).

### sub_62a0c0 at 0x62a0c0 (239 instructions)

````text
0x62a0c0: push 0FFFFFFFFh
0x62a0c2: push 7410D9h
0x62a0c7: mov eax,fs:[0]
0x62a0cd: push eax
0x62a0ce: sub esp,44h
0x62a0d1: push ebx
0x62a0d2: push ebp
0x62a0d3: push esi
0x62a0d4: push edi
0x62a0d5: mov eax,ds:[858220h]
0x62a0da: xor eax,esp
0x62a0dc: push eax
0x62a0dd: lea eax,[esp+58h]
0x62a0e1: mov fs:[0],eax
0x62a0e7: mov eax,[esp+74h]
0x62a0eb: cmp byte ptr [eax+89h],0
0x62a0f2: je short 0062A130h
0x62a0f4: push 7C5AECh
0x62a0f9: lea ecx,[esp+18h]
0x62a0fd: call dword ptr ds:[77CD7Ch]
0x62a103: lea eax,[esp+14h]
0x62a107: push eax
0x62a108: lea ecx,[esp+34h]
0x62a10c: mov dword ptr [esp+64h],0
0x62a114: call 00401230h
0x62a119: push 80A4F8h
0x62a11e: lea ecx,[esp+34h]
0x62a122: push ecx
0x62a123: mov dword ptr [esp+38h],790F90h
0x62a12b: call 00652AC4h
0x62a130: lea esi,[esp+70h]
0x62a134: mov ebp,eax
0x62a136: call 0062B040h
0x62a13b: mov eax,[ebp]
0x62a13e: cmp byte ptr [eax+89h],0
0x62a145: je short 0062A14Ch
0x62a147: mov edi,[ebp+8]
0x62a14a: jmp short 0062A167h
0x62a14c: mov edx,[ebp+8]
0x62a14f: cmp byte ptr [edx+89h],0
0x62a156: je short 0062A15Ch
0x62a158: mov edi,eax
0x62a15a: jmp short 0062A167h
0x62a15c: mov ecx,[esp+74h]
0x62a160: cmp ecx,ebp
0x62a162: mov edi,[ecx+8]
0x62a165: jne short 0062A1DFh
0x62a167: cmp byte ptr [edi+89h],0
0x62a16e: mov esi,[ebp+4]
0x62a171: jne short 0062A176h
0x62a173: mov [edi+4],esi
0x62a176: mov edx,[esp+68h]
0x62a17a: mov eax,[edx+4]
0x62a17d: cmp [eax+4],ebp
0x62a180: jne short 0062A187h
0x62a182: mov [eax+4],edi
0x62a185: jmp short 0062A192h
0x62a187: cmp [esi],ebp
0x62a189: jne short 0062A18Fh
0x62a18b: mov [esi],edi
0x62a18d: jmp short 0062A192h
0x62a18f: mov [esi+8],edi
0x62a192: mov ebx,[edx+4]
0x62a195: cmp [ebx],ebp
0x62a197: jne short 0062A1B3h
0x62a199: cmp byte ptr [edi+89h],0
0x62a1a0: je short 0062A1A6h
0x62a1a2: mov eax,esi
0x62a1a4: jmp short 0062A1B1h
0x62a1a6: mov eax,edi
0x62a1a8: call 0062AA70h
0x62a1ad: mov edx,[esp+68h]
0x62a1b1: mov [ebx],eax
0x62a1b3: mov ebx,[edx+4]
0x62a1b6: cmp [ebx+8],ebp
0x62a1b9: jne near ptr 0062A24Eh
0x62a1bf: cmp byte ptr [edi+89h],0
0x62a1c6: je short 0062A1CFh
0x62a1c8: mov eax,esi
0x62a1ca: mov [ebx+8],eax
0x62a1cd: jmp short 0062A24Eh
0x62a1cf: mov eax,edi
0x62a1d1: call 0062AA50h
0x62a1d6: mov edx,[esp+68h]
0x62a1da: mov [ebx+8],eax
0x62a1dd: jmp short 0062A24Eh
0x62a1df: mov [eax+4],ecx
0x62a1e2: mov eax,[ebp]
0x62a1e5: mov [ecx],eax
0x62a1e7: cmp ecx,[ebp+8]
0x62a1ea: jne short 0062A1F0h
0x62a1ec: mov esi,ecx
0x62a1ee: jmp short 0062A20Dh
0x62a1f0: cmp byte ptr [edi+89h],0
0x62a1f7: mov esi,[ecx+4]
0x62a1fa: jne short 0062A1FFh
0x62a1fc: mov [edi+4],esi
0x62a1ff: mov [esi],edi
0x62a201: mov edx,[ebp+8]
0x62a204: mov [ecx+8],edx
0x62a207: mov eax,[ebp+8]
0x62a20a: mov [eax+4],ecx
0x62a20d: mov edx,[esp+68h]
0x62a211: mov eax,[edx+4]
0x62a214: cmp [eax+4],ebp
0x62a217: jne short 0062A21Eh
0x62a219: mov [eax+4],ecx
0x62a21c: jmp short 0062A22Ch
0x62a21e: mov eax,[ebp+4]
0x62a221: cmp [eax],ebp
0x62a223: jne short 0062A229h
0x62a225: mov [eax],ecx
0x62a227: jmp short 0062A22Ch
0x62a229: mov [eax+8],ecx
0x62a22c: mov eax,[ebp+4]
0x62a22f: mov [ecx+4],eax
0x62a232: mov dl,[ebp+88h]
0x62a238: mov al,[ecx+88h]
0x62a23e: mov [ecx+88h],dl
0x62a244: mov edx,[esp+68h]
0x62a248: mov [ebp+88h],al
0x62a24e: mov bl,1
0x62a250: cmp [ebp+88h],bl
0x62a256: jne near ptr 0062A3CDh
0x62a25c: mov eax,[edx+4]
0x62a25f: cmp edi,[eax+4]
0x62a262: je near ptr 0062A3C7h
0x62a268: jmp short 0062A270h
0x62a270: cmp [edi+88h],bl
0x62a276: jne near ptr 0062A3C7h
0x62a27c: mov ecx,[esi]
0x62a27e: cmp edi,ecx
0x62a280: jne near ptr 0062A323h
0x62a286: mov ecx,[esi+8]
0x62a289: cmp byte ptr [ecx+88h],0
0x62a290: jne short 0062A2AEh
0x62a292: mov [ecx+88h],bl
0x62a298: push edx
0x62a299: mov ecx,esi
0x62a29b: mov byte ptr [esi+88h],0
0x62a2a2: call 0062AA00h
0x62a2a7: mov ecx,[esi+8]
0x62a2aa: mov edx,[esp+68h]
0x62a2ae: cmp byte ptr [ecx+89h],0
0x62a2b5: jne near ptr 0062A36Ch
0x62a2bb: mov eax,[ecx]
0x62a2bd: cmp [eax+88h],bl
0x62a2c3: jne short 0062A2D4h
0x62a2c5: mov eax,[ecx+8]
0x62a2c8: cmp [eax+88h],bl
0x62a2ce: je near ptr 0062A365h
0x62a2d4: mov eax,[ecx+8]
0x62a2d7: cmp [eax+88h],bl
0x62a2dd: jne short 0062A2FBh
0x62a2df: mov eax,[ecx]
0x62a2e1: mov [eax+88h],bl
0x62a2e7: push edx
0x62a2e8: mov byte ptr [ecx+88h],0
0x62a2ef: call 0062AA90h
0x62a2f4: mov ecx,[esi+8]
0x62a2f7: mov edx,[esp+68h]
0x62a2fb: mov al,[esi+88h]
0x62a301: mov [ecx+88h],al
0x62a307: mov [esi+88h],bl
0x62a30d: mov ecx,[ecx+8]
0x62a310: mov [ecx+88h],bl
0x62a316: push edx
0x62a317: mov ecx,esi
0x62a319: call 0062AA00h
0x62a31e: jmp near ptr 0062A3C7h
0x62a323: cmp byte ptr [ecx+88h],0
0x62a32a: jne short 0062A347h
0x62a32c: mov [ecx+88h],bl
0x62a332: push edx
0x62a333: mov ecx,esi
0x62a335: mov byte ptr [esi+88h],0
0x62a33c: call 0062AA90h
0x62a341: mov ecx,[esi]
0x62a343: mov edx,[esp+68h]
0x62a347: cmp byte ptr [ecx+89h],0
0x62a34e: jne short 0062A36Ch
0x62a350: mov eax,[ecx+8]
0x62a353: cmp [eax+88h],bl
0x62a359: jne short 0062A37Fh
0x62a35b: mov eax,[ecx]
0x62a35d: cmp [eax+88h],bl
0x62a363: jne short 0062A37Fh
0x62a365: mov byte ptr [ecx+88h],0
0x62a36c: mov ecx,[edx+4]
0x62a36f: mov edi,esi
0x62a371: cmp edi,[ecx+4]
0x62a374: mov esi,[esi+4]
0x62a377: jne near ptr 0062A270h
0x62a37d: jmp short 0062A3C7h
0x62a37f: mov eax,[ecx]
0x62a381: cmp [eax+88h],bl
0x62a387: jne short 0062A3A5h
0x62a389: mov eax,[ecx+8]
0x62a38c: mov [eax+88h],bl
0x62a392: push edx
0x62a393: mov byte ptr [ecx+88h],0
0x62a39a: call 0062AA00h
0x62a39f: mov ecx,[esi]
0x62a3a1: mov edx,[esp+68h]
0x62a3a5: mov al,[esi+88h]
0x62a3ab: mov [ecx+88h],al
0x62a3b1: mov [esi+88h],bl
0x62a3b7: mov ecx,[ecx]
0x62a3b9: mov [ecx+88h],bl
0x62a3bf: push edx
0x62a3c0: mov ecx,esi
0x62a3c2: call 0062AA90h
0x62a3c7: mov [edi+88h],bl
0x62a3cd: lea edx,[ebp+0Ch]
0x62a3d0: push edx
0x62a3d1: call 0062A6E0h
0x62a3d6: push ebp
0x62a3d7: call 006516BAh
0x62a3dc: mov ecx,[esp+6Ch]
0x62a3e0: mov eax,[ecx+8]
0x62a3e3: add esp,4
0x62a3e6: test eax,eax
0x62a3e8: jbe short 0062A3F0h
0x62a3ea: add eax,0FFFFFFFFh
0x62a3ed: mov [ecx+8],eax
0x62a3f0: mov eax,[esp+6Ch]
0x62a3f4: mov ecx,[esp+70h]
0x62a3f8: mov edx,[esp+74h]
0x62a3fc: mov [eax],ecx
0x62a3fe: mov [eax+4],edx
0x62a401: mov ecx,[esp+58h]
0x62a405: mov fs:[0],ecx
0x62a40c: pop ecx
0x62a40d: pop edi
0x62a40e: pop esi
0x62a40f: pop ebp
0x62a410: pop ebx
0x62a411: add esp,50h
0x62a414: ret 10h
````

`sub_62a0c0` is called by sub_62b310. It delegates to sub_401230, sub_62a6e0, sub_62aa00 (9 callees).

### sub_62a6e0 at 0x62a6e0 (24 instructions)

````text
0x62a6e0: push 0FFFFFFFFh
0x62a6e2: push 73DB58h
0x62a6e7: mov eax,fs:[0]
0x62a6ed: push eax
0x62a6ee: push esi
0x62a6ef: mov eax,ds:[858220h]
0x62a6f4: xor eax,esp
0x62a6f6: push eax
0x62a6f7: lea eax,[esp+8]
0x62a6fb: mov fs:[0],eax
0x62a701: mov esi,[esp+18h]
0x62a705: lea eax,[esi+20h]
0x62a708: push eax
0x62a709: mov dword ptr [esp+14h],0
0x62a711: call 0044C770h
0x62a716: lea ecx,[esi+4]
0x62a719: mov dword ptr [esp+10h],0FFFFFFFFh
0x62a721: call dword ptr ds:[77CD74h]
0x62a727: mov ecx,[esp+8]
0x62a72b: mov fs:[0],ecx
0x62a732: pop ecx
0x62a733: pop esi
0x62a734: add esp,0Ch
0x62a737: ret 4
````

`sub_62a6e0` is called by sub_62a0c0. It delegates to sub_44c770 (1 callees).

### sub_62a960 at 0x62a960 (47 instructions)

````text
0x62a960: push 0FFFFFFFFh
0x62a962: push 75D658h
0x62a967: mov eax,fs:[0]
0x62a96d: push eax
0x62a96e: push ebx
0x62a96f: push ebp
0x62a970: push esi
0x62a971: push edi
0x62a972: mov eax,ds:[858220h]
0x62a977: xor eax,esp
0x62a979: push eax
0x62a97a: lea eax,[esp+14h]
0x62a97e: mov fs:[0],eax
0x62a984: mov ebx,ecx
0x62a986: mov edi,[esp+24h]
0x62a98a: cmp byte ptr [edi+89h],0
0x62a991: mov esi,edi
0x62a993: jne short 0062A9DFh
0x62a995: mov eax,[esi+8]
0x62a998: push eax
0x62a999: mov ecx,ebx
0x62a99b: call 0062A960h
0x62a9a0: mov esi,[esi]
0x62a9a2: lea ebp,[edi+0Ch]
0x62a9a5: mov [esp+24h],ebp
0x62a9a9: lea ecx,[ebp+20h]
0x62a9ac: push ecx
0x62a9ad: mov dword ptr [esp+20h],0
0x62a9b5: call 0044C770h
0x62a9ba: lea ecx,[ebp+4]
0x62a9bd: mov dword ptr [esp+1Ch],0FFFFFFFFh
0x62a9c5: call dword ptr ds:[77CD74h]
0x62a9cb: push edi
0x62a9cc: call 006516BAh
0x62a9d1: add esp,4
0x62a9d4: cmp byte ptr [esi+89h],0
0x62a9db: mov edi,esi
0x62a9dd: je short 0062A995h
0x62a9df: mov ecx,[esp+14h]
0x62a9e3: mov fs:[0],ecx
0x62a9ea: pop ecx
0x62a9eb: pop edi
0x62a9ec: pop esi
0x62a9ed: pop ebp
0x62a9ee: pop ebx
0x62a9ef: add esp,0Ch
0x62a9f2: ret 4
````

`sub_62a960` is called by sub_62a960, sub_62b310. It delegates to sub_44c770, sub_62a960, j_ORDINAL 764 (3 callees).

### sub_62aa00 at 0x62aa00 (28 instructions)

````text
0x62aa00: mov eax,[ecx+8]
0x62aa03: mov edx,[eax]
0x62aa05: mov [ecx+8],edx
0x62aa08: mov edx,[eax]
0x62aa0a: cmp byte ptr [edx+89h],0
0x62aa11: jne short 0062AA16h
0x62aa13: mov [edx+4],ecx
0x62aa16: mov edx,[ecx+4]
0x62aa19: mov [eax+4],edx
0x62aa1c: mov edx,[esp+4]
0x62aa20: mov edx,[edx+4]
0x62aa23: cmp ecx,[edx+4]
0x62aa26: jne short 0062AA33h
0x62aa28: mov [edx+4],eax
0x62aa2b: mov [eax],ecx
0x62aa2d: mov [ecx+4],eax
0x62aa30: ret 4
0x62aa33: mov edx,[ecx+4]
0x62aa36: cmp ecx,[edx]
0x62aa38: jne short 0062AA44h
0x62aa3a: mov [edx],eax
0x62aa3c: mov [eax],ecx
0x62aa3e: mov [ecx+4],eax
0x62aa41: ret 4
0x62aa44: mov [edx+8],eax
0x62aa47: mov [eax],ecx
0x62aa49: mov [ecx+4],eax
0x62aa4c: ret 4
````

`sub_62aa00` is called by sub_62a0c0. It calls nothing else.

### sub_62aa50 at 0x62aa50 (9 instructions)

````text
0x62aa50: mov ecx,[eax+8]
0x62aa53: cmp byte ptr [ecx+89h],0
0x62aa5a: jne short 0062AA6Eh
0x62aa5c: lea esp,[esp]
0x62aa60: mov eax,ecx
0x62aa62: mov ecx,[eax+8]
0x62aa65: cmp byte ptr [ecx+89h],0
0x62aa6c: je short 0062AA60h
0x62aa6e: ret
````

`sub_62aa50` is called by sub_62a0c0. It calls nothing else.

### sub_62aa70 at 0x62aa70 (9 instructions)

````text
0x62aa70: mov ecx,[eax]
0x62aa72: cmp byte ptr [ecx+89h],0
0x62aa79: jne short 0062AA8Dh
0x62aa7b: jmp short 0062AA80h
0x62aa80: mov eax,ecx
0x62aa82: mov ecx,[eax]
0x62aa84: cmp byte ptr [ecx+89h],0
0x62aa8b: je short 0062AA80h
0x62aa8d: ret
````

`sub_62aa70` is called by sub_62a0c0. It calls nothing else.

### sub_62aa90 at 0x62aa90 (28 instructions)

````text
0x62aa90: mov eax,[ecx]
0x62aa92: mov edx,[eax+8]
0x62aa95: mov [ecx],edx
0x62aa97: mov edx,[eax+8]
0x62aa9a: cmp byte ptr [edx+89h],0
0x62aaa1: jne short 0062AAA6h
0x62aaa3: mov [edx+4],ecx
0x62aaa6: mov edx,[ecx+4]
0x62aaa9: mov [eax+4],edx
0x62aaac: mov edx,[esp+4]
0x62aab0: mov edx,[edx+4]
0x62aab3: cmp ecx,[edx+4]
0x62aab6: jne short 0062AAC4h
0x62aab8: mov [edx+4],eax
0x62aabb: mov [eax+8],ecx
0x62aabe: mov [ecx+4],eax
0x62aac1: ret 4
0x62aac4: mov edx,[ecx+4]
0x62aac7: cmp ecx,[edx+8]
0x62aaca: jne short 0062AAD8h
0x62aacc: mov [edx+8],eax
0x62aacf: mov [eax+8],ecx
0x62aad2: mov [ecx+4],eax
0x62aad5: ret 4
0x62aad8: mov [edx],eax
0x62aada: mov [eax+8],ecx
0x62aadd: mov [ecx+4],eax
0x62aae0: ret 4
````

`sub_62aa90` is called by sub_62a0c0. It calls nothing else.

### sub_62aaf0 at 0x62aaf0 (26 instructions)

````text
0x62aaf0: push ebp
0x62aaf1: mov ebp,esp
0x62aaf3: and esp,0FFFFFFF8h
0x62aaf6: sub esp,0Ch
0x62aaf9: push edi
0x62aafa: mov edi,eax
0x62aafc: mov eax,[edi+4]
0x62aaff: mov ecx,[eax]
0x62ab01: push eax
0x62ab02: push edi
0x62ab03: push ecx
0x62ab04: push edi
0x62ab05: lea eax,[esp+18h]
0x62ab09: push eax
0x62ab0a: call 0062B310h
0x62ab0f: mov ecx,[edi+4]
0x62ab12: push ecx
0x62ab13: call 006516BAh
0x62ab18: add esp,4
0x62ab1b: xor eax,eax
0x62ab1d: mov [edi+4],eax
0x62ab20: mov [edi+8],eax
0x62ab23: pop edi
0x62ab24: mov esp,ebp
0x62ab26: pop ebp
0x62ab27: ret
````

`sub_62aaf0` is called by sub_6287e0. It delegates to sub_62b310, j_ORDINAL 764 (2 callees).

### sub_62b040 at 0x62b040 (38 instructions)

````text
0x62b040: cmp dword ptr [esi],0
0x62b043: push edi
0x62b044: mov edi,ds:[77D0E4h]
0x62b04a: jne short 0062B04Eh
0x62b04c: call edi
0x62b04e: mov eax,[esi+4]
0x62b051: cmp byte ptr [eax+89h],0
0x62b058: je short 0062B05Eh
0x62b05a: call edi
0x62b05c: pop edi
0x62b05d: ret
0x62b05e: mov ecx,[eax+8]
0x62b061: cmp byte ptr [ecx+89h],0
0x62b068: jne short 0062B087h
0x62b06a: mov eax,[ecx]
0x62b06c: cmp byte ptr [eax+89h],0
0x62b073: jne short 0062B082h
0x62b075: mov ecx,eax
0x62b077: mov eax,[ecx]
0x62b079: cmp byte ptr [eax+89h],0
0x62b080: je short 0062B075h
0x62b082: mov [esi+4],ecx
0x62b085: pop edi
0x62b086: ret
0x62b087: mov eax,[eax+4]
0x62b08a: cmp byte ptr [eax+89h],0
0x62b091: jne short 0062B0ACh
0x62b093: mov ecx,[esi+4]
0x62b096: cmp ecx,[eax+8]
0x62b099: jne short 0062B0ACh
0x62b09b: mov [esi+4],eax
0x62b09e: mov edx,eax
0x62b0a0: mov eax,[edx+4]
0x62b0a3: cmp byte ptr [eax+89h],0
0x62b0aa: je short 0062B093h
0x62b0ac: mov [esi+4],eax
0x62b0af: pop edi
0x62b0b0: ret
````

`sub_62b040` is called by sub_62a0c0, sub_62b310. It calls nothing else.

### sub_62b310 at 0x62b310 (72 instructions)

````text
0x62b310: mov eax,[edi+4]
0x62b313: sub esp,0Ch
0x62b316: push ebx
0x62b317: mov ebx,[esp+18h]
0x62b31b: test ebx,ebx
0x62b31d: push ebp
0x62b31e: push esi
0x62b31f: mov esi,[eax]
0x62b321: je short 0062B327h
0x62b323: cmp ebx,edi
0x62b325: je short 0062B32Dh
0x62b327: call dword ptr ds:[77D0E4h]
0x62b32d: mov ebp,[esp+24h]
0x62b331: cmp ebp,esi
0x62b333: jne short 0062B390h
0x62b335: mov eax,[esp+28h]
0x62b339: test eax,eax
0x62b33b: mov esi,[edi+4]
0x62b33e: je short 0062B344h
0x62b340: cmp eax,edi
0x62b342: je short 0062B34Ah
0x62b344: call dword ptr ds:[77D0E4h]
0x62b34a: cmp [esp+2Ch],esi
0x62b34e: jne short 0062B390h
0x62b350: mov ecx,[edi+4]
0x62b353: mov edx,[ecx+4]
0x62b356: push edx
0x62b357: mov ecx,edi
0x62b359: call 0062A960h
0x62b35e: mov eax,[edi+4]
0x62b361: mov [eax+4],eax
0x62b364: mov eax,[edi+4]
0x62b367: mov dword ptr [edi+8],0
0x62b36e: mov [eax],eax
0x62b370: mov eax,[edi+4]
0x62b373: mov [eax+8],eax
0x62b376: mov eax,[edi+4]
0x62b379: mov ecx,[eax]
0x62b37b: mov eax,[esp+1Ch]
0x62b37f: mov [eax+4],ecx
0x62b382: mov [eax],edi
0x62b384: pop esi
0x62b385: pop ebp
0x62b386: pop ebx
0x62b387: add esp,0Ch
0x62b38a: ret 14h
0x62b390: test ebx,ebx
0x62b392: je short 0062B39Ah
0x62b394: cmp ebx,[esp+28h]
0x62b398: je short 0062B3A0h
0x62b39a: call dword ptr ds:[77D0E4h]
0x62b3a0: cmp ebp,[esp+2Ch]
0x62b3a4: je short 0062B3C6h
0x62b3a6: lea esi,[esp+20h]
0x62b3aa: call 0062B040h
0x62b3af: push ebp
0x62b3b0: push ebx
0x62b3b1: lea edx,[esp+18h]
0x62b3b5: push edx
0x62b3b6: push edi
0x62b3b7: call 0062A0C0h
0x62b3bc: mov ebp,[esp+24h]
0x62b3c0: mov ebx,[esp+20h]
0x62b3c4: jmp short 0062B390h
0x62b3c6: mov eax,[esp+1Ch]
0x62b3ca: pop esi
0x62b3cb: mov [eax+4],ebp
0x62b3ce: pop ebp
0x62b3cf: mov [eax],ebx
0x62b3d1: pop ebx
0x62b3d2: add esp,0Ch
0x62b3d5: ret 14h
````

`sub_62b310` is called by sub_62aaf0. It delegates to sub_62a0c0, sub_62a960, sub_62b040 (3 callees).

### sub_62b5f0 at 0x62b5f0 (16 instructions)

````text
0x62b5f0: mov ecx,1
0x62b5f5: call 0062B850h
0x62b5fa: test eax,eax
0x62b5fc: je short 0062B604h
0x62b5fe: mov dword ptr [eax],0
0x62b604: lea ecx,[eax+4]
0x62b607: test ecx,ecx
0x62b609: je short 0062B611h
0x62b60b: mov dword ptr [ecx],0
0x62b611: lea ecx,[eax+8]
0x62b614: test ecx,ecx
0x62b616: je short 0062B61Eh
0x62b618: mov dword ptr [ecx],0
0x62b61e: mov byte ptr [eax+88h],1
0x62b625: mov byte ptr [eax+89h],0
0x62b62c: ret
````

`sub_62b5f0` is called by sub_628750. It delegates to sub_62b850 (1 callees).

### sub_62b850 at 0x62b850 (22 instructions)

````text
0x62b850: or eax,0FFFFFFFFh
0x62b853: xor edx,edx
0x62b855: div ecx
0x62b857: sub esp,10h
0x62b85a: cmp eax,8Ch
0x62b85f: jae short 0062B88Eh
0x62b861: lea eax,[esp]
0x62b864: push eax
0x62b865: lea ecx,[esp+8]
0x62b869: mov dword ptr [esp+4],0
0x62b871: call dword ptr ds:[77D0DCh]
0x62b877: push 80A2ACh
0x62b87c: lea ecx,[esp+8]
0x62b880: push ecx
0x62b881: mov dword ptr [esp+0Ch],78FFD4h
0x62b889: call 00652AC4h
0x62b88e: imul ecx,8Ch
0x62b894: push ecx
0x62b895: call 006516C0h
0x62b89a: add esp,4
0x62b89d: add esp,10h
0x62b8a0: ret
````

`sub_62b850` is called by sub_62b5f0. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_62bb40 at 0x62bb40 (63 instructions)

````text
0x62bb40: push 0FFFFFFFFh
0x62bb42: push 743441h
0x62bb47: mov eax,fs:[0]
0x62bb4d: push eax
0x62bb4e: sub esp,8
0x62bb51: push ebx
0x62bb52: mov eax,ds:[858220h]
0x62bb57: xor eax,esp
0x62bb59: push eax
0x62bb5a: lea eax,[esp+10h]
0x62bb5e: mov fs:[0],eax
0x62bb64: mov ecx,874E80h
0x62bb69: mov dword ptr [esp+0Ch],874E80h
0x62bb71: call dword ptr ds:[77CD80h]
0x62bb77: xor ebx,ebx
0x62bb79: mov ecx,874E9Ch
0x62bb7e: mov [esp+18h],ebx
0x62bb82: call dword ptr ds:[77CD80h]
0x62bb88: mov ecx,874EB8h
0x62bb8d: mov byte ptr [esp+18h],1
0x62bb92: call dword ptr ds:[77CD80h]
0x62bb98: mov ecx,874ED4h
0x62bb9d: mov byte ptr [esp+18h],2
0x62bba2: call dword ptr ds:[77CD80h]
0x62bba8: mov ecx,874EF0h
0x62bbad: mov byte ptr [esp+18h],3
0x62bbb2: call dword ptr ds:[77CD80h]
0x62bbb8: mov eax,1
0x62bbbd: mov ds:[874F0Ch],eax
0x62bbc2: mov ds:[874F10h],eax
0x62bbc7: mov ds:[874F14h],al
0x62bbcc: or eax,0FFFFFFFFh
0x62bbcf: mov dword ptr ds:[874F18h],1Fh
0x62bbd9: mov ds:[874F1Ch],ebx
0x62bbdf: mov ds:[874F20h],ebx
0x62bbe5: mov ds:[874F24h],eax
0x62bbea: mov ds:[874F28h],eax
0x62bbef: mov byte ptr ds:[874F2Ch],1
0x62bbf6: mov ds:[874F2Dh],bl
0x62bbfc: mov ds:[874F30h],ebx
0x62bc02: mov ds:[874F34h],ebx
0x62bc08: mov ds:[874F3Ch],ebx
0x62bc0e: mov ds:[874F40h],ebx
0x62bc14: mov ds:[874F44h],ebx
0x62bc1a: mov ds:[874F4Ch],ebx
0x62bc20: mov ds:[874F50h],ebx
0x62bc26: mov ds:[874F54h],ebx
0x62bc2c: mov ds:[874F5Ch],ebx
0x62bc32: mov ds:[874F60h],ebx
0x62bc38: mov ds:[874F64h],ebx
0x62bc3e: mov ds:[874F6Ch],ebx
0x62bc44: mov ds:[874F70h],ebx
0x62bc4a: mov ds:[874F74h],ebx
0x62bc50: mov ds:[874F7Ch],ebx
0x62bc56: mov ds:[874F80h],ebx
0x62bc5c: mov ds:[874F84h],ebx
0x62bc62: mov eax,874E80h
0x62bc67: mov ecx,[esp+10h]
0x62bc6b: mov fs:[0],ecx
0x62bc72: pop ecx
0x62bc73: pop ebx
0x62bc74: add esp,14h
0x62bc77: ret
````

`sub_62bb40` is called by sub_610980. It calls nothing else.

### sub_62bc80 at 0x62bc80 (79 instructions)

````text
0x62bc80: push 0FFFFFFFFh
0x62bc82: push 73E941h
0x62bc87: mov eax,fs:[0]
0x62bc8d: push eax
0x62bc8e: push ecx
0x62bc8f: push ebx
0x62bc90: push esi
0x62bc91: push edi
0x62bc92: mov eax,ds:[858220h]
0x62bc97: xor eax,esp
0x62bc99: push eax
0x62bc9a: lea eax,[esp+14h]
0x62bc9e: mov fs:[0],eax
0x62bca4: mov dword ptr [esp+10h],874E80h
0x62bcac: mov dword ptr [esp+1Ch],8
0x62bcb4: mov eax,ds:[874F7Ch]
0x62bcb9: xor esi,esi
0x62bcbb: cmp eax,esi
0x62bcbd: je short 0062BCDFh
0x62bcbf: mov ecx,[esp+10h]
0x62bcc3: mov edi,ds:[874F80h]
0x62bcc9: push ecx
0x62bcca: push eax
0x62bccb: call 004E96C0h
0x62bcd0: mov edx,ds:[874F7Ch]
0x62bcd6: push edx
0x62bcd7: call 006516BAh
0x62bcdc: add esp,0Ch
0x62bcdf: mov byte ptr [esp+1Ch],7
0x62bce4: mov eax,ds:[874F6Ch]
0x62bce9: cmp eax,esi
0x62bceb: mov ds:[874F7Ch],esi
0x62bcf1: mov ds:[874F80h],esi
0x62bcf7: mov ds:[874F84h],esi
0x62bcfd: je short 0062BD1Fh
0x62bcff: mov ecx,[esp+10h]
0x62bd03: mov edi,ds:[874F70h]
0x62bd09: push ecx
0x62bd0a: push eax
0x62bd0b: call 006127E0h
0x62bd10: mov edx,ds:[874F6Ch]
0x62bd16: push edx
0x62bd17: call 006516BAh
0x62bd1c: add esp,0Ch
0x62bd1f: mov ebx,874F58h
0x62bd24: mov ds:[874F6Ch],esi
0x62bd2a: mov ds:[874F70h],esi
0x62bd30: mov ds:[874F74h],esi
0x62bd36: mov byte ptr [esp+1Ch],6
0x62bd3b: call 0062ECA0h
0x62bd40: mov ebx,874F48h
0x62bd45: mov byte ptr [esp+1Ch],5
0x62bd4a: call 0062EB70h
0x62bd4f: mov ebx,874F38h
0x62bd54: mov byte ptr [esp+1Ch],4
0x62bd59: call 0062EB70h
0x62bd5e: mov ecx,874EF0h
0x62bd63: mov byte ptr [esp+1Ch],3
0x62bd68: call dword ptr ds:[77CD74h]
0x62bd6e: mov ecx,874ED4h
0x62bd73: mov byte ptr [esp+1Ch],2
0x62bd78: call dword ptr ds:[77CD74h]
0x62bd7e: mov ecx,874EB8h
0x62bd83: mov byte ptr [esp+1Ch],1
0x62bd88: call dword ptr ds:[77CD74h]
0x62bd8e: mov ecx,874E9Ch
0x62bd93: mov byte ptr [esp+1Ch],0
0x62bd98: call dword ptr ds:[77CD74h]
0x62bd9e: mov ecx,874E80h
0x62bda3: mov dword ptr [esp+1Ch],0FFFFFFFFh
0x62bdab: call dword ptr ds:[77CD74h]
0x62bdb1: mov ecx,[esp+14h]
0x62bdb5: mov fs:[0],ecx
0x62bdbc: pop ecx
0x62bdbd: pop edi
0x62bdbe: pop esi
0x62bdbf: pop ebx
0x62bdc0: add esp,10h
0x62bdc3: ret
````

`sub_62bc80` is called by sub_610c30. It delegates to sub_4e96c0, sub_6127e0, sub_62eb70 (5 callees).

### sub_62e680 at 0x62e680 (29 instructions)

````text
0x62e680: push 0FFFFFFFFh
0x62e682: push 738EF4h
0x62e687: mov eax,fs:[0]
0x62e68d: push eax
0x62e68e: push esi
0x62e68f: mov eax,ds:[858220h]
0x62e694: xor eax,esp
0x62e696: push eax
0x62e697: lea eax,[esp+8]
0x62e69b: mov fs:[0],eax
0x62e6a1: mov esi,[esp+18h]
0x62e6a5: lea ecx,[esi+58h]
0x62e6a8: mov dword ptr [esp+10h],2
0x62e6b0: call dword ptr ds:[77CD74h]
0x62e6b6: lea ecx,[esi+3Ch]
0x62e6b9: mov byte ptr [esp+10h],1
0x62e6be: call dword ptr ds:[77CD74h]
0x62e6c4: lea ecx,[esi+20h]
0x62e6c7: mov byte ptr [esp+10h],0
0x62e6cc: call dword ptr ds:[77CD74h]
0x62e6d2: lea ecx,[esi+4]
0x62e6d5: mov dword ptr [esp+10h],0FFFFFFFFh
0x62e6dd: call dword ptr ds:[77CD74h]
0x62e6e3: mov ecx,[esp+8]
0x62e6e7: mov fs:[0],ecx
0x62e6ee: pop ecx
0x62e6ef: pop esi
0x62e6f0: add esp,0Ch
0x62e6f3: ret 4
````

`sub_62e680` is called by sub_62eb70. It calls nothing else.

### sub_62e770 at 0x62e770 (26 instructions)

````text
0x62e770: push 0FFFFFFFFh
0x62e772: push 738EA8h
0x62e777: mov eax,fs:[0]
0x62e77d: push eax
0x62e77e: push esi
0x62e77f: mov eax,ds:[858220h]
0x62e784: xor eax,esp
0x62e786: push eax
0x62e787: lea eax,[esp+8]
0x62e78b: mov fs:[0],eax
0x62e791: mov esi,[esp+18h]
0x62e795: lea ecx,[esi+3Ch]
0x62e798: mov dword ptr [esp+10h],1
0x62e7a0: call dword ptr ds:[77CD74h]
0x62e7a6: lea ecx,[esi+20h]
0x62e7a9: mov byte ptr [esp+10h],0
0x62e7ae: call dword ptr ds:[77CD74h]
0x62e7b4: lea ecx,[esi+4]
0x62e7b7: mov dword ptr [esp+10h],0FFFFFFFFh
0x62e7bf: call dword ptr ds:[77CD74h]
0x62e7c5: mov ecx,[esp+8]
0x62e7c9: mov fs:[0],ecx
0x62e7d0: pop ecx
0x62e7d1: pop esi
0x62e7d2: add esp,0Ch
0x62e7d5: ret 4
````

`sub_62e770` is called by sub_62eca0. It calls nothing else.

### sub_62eb70 at 0x62eb70 (23 instructions)

````text
0x62eb70: push esi
0x62eb71: mov esi,[ebx+4]
0x62eb74: test esi,esi
0x62eb76: je short 0062EB9Ah
0x62eb78: push edi
0x62eb79: mov edi,[ebx+8]
0x62eb7c: cmp esi,edi
0x62eb7e: je short 0062EB8Dh
0x62eb80: push esi
0x62eb81: call 0062E680h
0x62eb86: add esi,74h
0x62eb89: cmp esi,edi
0x62eb8b: jne short 0062EB80h
0x62eb8d: mov eax,[ebx+4]
0x62eb90: push eax
0x62eb91: call 006516BAh
0x62eb96: add esp,4
0x62eb99: pop edi
0x62eb9a: mov dword ptr [ebx+4],0
0x62eba1: mov dword ptr [ebx+8],0
0x62eba8: mov dword ptr [ebx+0Ch],0
0x62ebaf: pop esi
0x62ebb0: ret
````

`sub_62eb70` is called by sub_62bc80. It delegates to sub_62e680, j_ORDINAL 764 (2 callees).

### sub_62eca0 at 0x62eca0 (23 instructions)

````text
0x62eca0: push esi
0x62eca1: mov esi,[ebx+4]
0x62eca4: test esi,esi
0x62eca6: je short 0062ECCAh
0x62eca8: push edi
0x62eca9: mov edi,[ebx+8]
0x62ecac: cmp esi,edi
0x62ecae: je short 0062ECBDh
0x62ecb0: push esi
0x62ecb1: call 0062E770h
0x62ecb6: add esi,58h
0x62ecb9: cmp esi,edi
0x62ecbb: jne short 0062ECB0h
0x62ecbd: mov eax,[ebx+4]
0x62ecc0: push eax
0x62ecc1: call 006516BAh
0x62ecc6: add esp,4
0x62ecc9: pop edi
0x62ecca: mov dword ptr [ebx+4],0
0x62ecd1: mov dword ptr [ebx+8],0
0x62ecd8: mov dword ptr [ebx+0Ch],0
0x62ecdf: pop esi
0x62ece0: ret
````

`sub_62eca0` is called by sub_62bc80. It delegates to sub_62e770, j_ORDINAL 764 (2 callees).

### sub_6300d0 at 0x6300d0 (38 instructions)

````text
0x6300d0: push 0FFFFFFFFh
0x6300d2: push 738DBCh
0x6300d7: mov eax,fs:[0]
0x6300dd: push eax
0x6300de: push ebx
0x6300df: push esi
0x6300e0: push edi
0x6300e1: mov eax,ds:[858220h]
0x6300e6: xor eax,esp
0x6300e8: push eax
0x6300e9: lea eax,[esp+10h]
0x6300ed: mov fs:[0],eax
0x6300f3: mov esi,[esp+20h]
0x6300f7: xor ebx,ebx
0x6300f9: mov eax,1
0x6300fe: lea edi,[esi+1Ch]
0x630101: mov ecx,edi
0x630103: mov dword ptr [esi],3
0x630109: mov [esi+4],ebx
0x63010c: mov dword ptr [esi+8],78h
0x630113: mov [esi+0Ch],eax
0x630116: mov [esi+10h],eax
0x630119: mov [esi+14h],ebx
0x63011c: mov [esi+18h],ebx
0x63011f: call dword ptr ds:[77CD80h]
0x630125: push 7F698Ch
0x63012a: mov ecx,edi
0x63012c: mov [esp+1Ch],ebx
0x630130: call dword ptr ds:[77CD50h]
0x630136: mov eax,esi
0x630138: mov ecx,[esp+10h]
0x63013c: mov fs:[0],ecx
0x630143: pop ecx
0x630144: pop edi
0x630145: pop esi
0x630146: pop ebx
0x630147: add esp,0Ch
0x63014a: ret 4
````

`sub_6300d0` is called by sub_610980. It calls nothing else.

### sub_631060 at 0x631060 (46 instructions)

````text
0x631060: push 0FFFFFFFFh
0x631062: push 74EFD3h
0x631067: mov eax,fs:[0]
0x63106d: push eax
0x63106e: push esi
0x63106f: push edi
0x631070: mov eax,ds:[858220h]
0x631075: xor eax,esp
0x631077: push eax
0x631078: lea eax,[esp+0Ch]
0x63107c: mov fs:[0],eax
0x631082: mov esi,[esp+1Ch]
0x631086: xor edi,edi
0x631088: mov [esi+4],edi
0x63108b: mov [esi+8],edi
0x63108e: mov [esi+0Ch],edi
0x631091: mov [esp+14h],edi
0x631095: call 00633900h
0x63109a: mov [esi+14h],eax
0x63109d: mov byte ptr [eax+39h],1
0x6310a1: mov eax,[esi+14h]
0x6310a4: mov [eax+4],eax
0x6310a7: mov eax,[esi+14h]
0x6310aa: mov [eax],eax
0x6310ac: mov eax,[esi+14h]
0x6310af: mov [eax+8],eax
0x6310b2: mov [esi+18h],edi
0x6310b5: mov byte ptr [esp+14h],1
0x6310ba: call 00633DF0h
0x6310bf: mov [esi+20h],eax
0x6310c2: mov byte ptr [eax+9Dh],1
0x6310c9: mov eax,[esi+20h]
0x6310cc: mov [eax+4],eax
0x6310cf: mov eax,[esi+20h]
0x6310d2: mov [eax],eax
0x6310d4: mov eax,[esi+20h]
0x6310d7: mov [eax+8],eax
0x6310da: mov [esi+24h],edi
0x6310dd: mov eax,esi
0x6310df: mov ecx,[esp+0Ch]
0x6310e3: mov fs:[0],ecx
0x6310ea: pop ecx
0x6310eb: pop edi
0x6310ec: pop esi
0x6310ed: add esp,0Ch
0x6310f0: ret 4
````

`sub_631060` is called by sub_610980. It delegates to sub_633900, sub_633df0 (2 callees).

### sub_631110 at 0x631110 (26 instructions)

````text
0x631110: push 0FFFFFFFFh
0x631112: push 74EFD3h
0x631117: mov eax,fs:[0]
0x63111d: push eax
0x63111e: push ecx
0x63111f: push ebx
0x631120: mov eax,ds:[858220h]
0x631125: xor eax,esp
0x631127: push eax
0x631128: lea eax,[esp+0Ch]
0x63112c: mov fs:[0],eax
0x631132: mov ebx,[esp+1Ch]
0x631136: lea eax,[ebx+1Ch]
0x631139: mov dword ptr [esp+14h],1
0x631141: call 006328D0h
0x631146: lea eax,[ebx+10h]
0x631149: mov byte ptr [esp+14h],0
0x63114e: call 00632650h
0x631153: mov dword ptr [esp+14h],0FFFFFFFFh
0x63115b: call 004CC190h
0x631160: mov ecx,[esp+0Ch]
0x631164: mov fs:[0],ecx
0x63116b: pop ecx
0x63116c: pop ebx
0x63116d: add esp,10h
0x631170: ret 4
````

`sub_631110` is called by sub_610c30. It delegates to sub_4cc190, sub_632650, sub_6328d0 (3 callees).

### sub_632130 at 0x632130 (25 instructions)

````text
0x632130: push 0FFFFFFFFh
0x632132: push 73E769h
0x632137: mov eax,fs:[0]
0x63213d: push eax
0x63213e: push ebx
0x63213f: push esi
0x632140: mov eax,ds:[858220h]
0x632145: xor eax,esp
0x632147: push eax
0x632148: lea eax,[esp+0Ch]
0x63214c: mov fs:[0],eax
0x632152: mov esi,[esp+1Ch]
0x632156: lea ebx,[esi+1Ch]
0x632159: mov dword ptr [esp+14h],0
0x632161: call 004CC190h
0x632166: mov ecx,esi
0x632168: mov dword ptr [esp+14h],0FFFFFFFFh
0x632170: call dword ptr ds:[77CD74h]
0x632176: mov ecx,[esp+0Ch]
0x63217a: mov fs:[0],ecx
0x632181: pop ecx
0x632182: pop esi
0x632183: pop ebx
0x632184: add esp,0Ch
0x632187: ret 4
````

`sub_632130` is called by sub_633610. It delegates to sub_4cc190 (1 callees).

### sub_632190 at 0x632190 (24 instructions)

````text
0x632190: push 0FFFFFFFFh
0x632192: push 73C439h
0x632197: mov eax,fs:[0]
0x63219d: push eax
0x63219e: push esi
0x63219f: mov eax,ds:[858220h]
0x6321a4: xor eax,esp
0x6321a6: push eax
0x6321a7: lea eax,[esp+8]
0x6321ab: mov fs:[0],eax
0x6321b1: mov esi,[esp+18h]
0x6321b5: lea eax,[esi+1Ch]
0x6321b8: push eax
0x6321b9: mov dword ptr [esp+14h],0
0x6321c1: call 004738D0h
0x6321c6: mov ecx,esi
0x6321c8: mov dword ptr [esp+10h],0FFFFFFFFh
0x6321d0: call dword ptr ds:[77CD74h]
0x6321d6: mov ecx,[esp+8]
0x6321da: mov fs:[0],ecx
0x6321e1: pop ecx
0x6321e2: pop esi
0x6321e3: add esp,0Ch
0x6321e6: ret 4
````

`sub_632190` is called by sub_6339e0. It delegates to sub_4738d0 (1 callees).

### sub_632570 at 0x632570 (69 instructions)

````text
0x632570: push 0FFFFFFFFh
0x632572: push 743339h
0x632577: mov eax,fs:[0]
0x63257d: push eax
0x63257e: sub esp,8
0x632581: push ebx
0x632582: push ebp
0x632583: push esi
0x632584: push edi
0x632585: mov eax,ds:[858220h]
0x63258a: xor eax,esp
0x63258c: push eax
0x63258d: lea eax,[esp+1Ch]
0x632591: mov fs:[0],eax
0x632597: mov [esp+14h],ecx
0x63259b: mov ebx,[esp+2Ch]
0x63259f: cmp byte ptr [ebx+39h],0
0x6325a3: mov ebp,ebx
0x6325a5: jne near ptr 0063262Bh
0x6325ab: jmp short 006325B4h
0x6325b0: mov ebx,[esp+2Ch]
0x6325b4: mov eax,[ebp+8]
0x6325b7: mov ecx,[esp+14h]
0x6325bb: push eax
0x6325bc: call 00632570h
0x6325c1: mov ebp,[ebp]
0x6325c4: lea esi,[ebx+0Ch]
0x6325c7: mov [esp+18h],esi
0x6325cb: xor eax,eax
0x6325cd: mov [esp+24h],eax
0x6325d1: mov edi,[esi+20h]
0x6325d4: cmp edi,eax
0x6325d6: je short 006325FFh
0x6325d8: mov ebx,[esi+24h]
0x6325db: cmp edi,ebx
0x6325dd: je short 006325EDh
0x6325df: nop
0x6325e0: push edi
0x6325e1: call 004738D0h
0x6325e6: add edi,74h
0x6325e9: cmp edi,ebx
0x6325eb: jne short 006325E0h
0x6325ed: mov eax,[esi+20h]
0x6325f0: push eax
0x6325f1: call 006516BAh
0x6325f6: mov ebx,[esp+30h]
0x6325fa: add esp,4
0x6325fd: xor eax,eax
0x6325ff: mov ecx,esi
0x632601: mov [esi+20h],eax
0x632604: mov [esi+24h],eax
0x632607: mov [esi+28h],eax
0x63260a: mov dword ptr [esp+24h],0FFFFFFFFh
0x632612: call dword ptr ds:[77CD74h]
0x632618: push ebx
0x632619: call 006516BAh
0x63261e: add esp,4
0x632621: cmp byte ptr [ebp+39h],0
0x632625: mov [esp+2Ch],ebp
0x632629: je short 006325B0h
0x63262b: mov ecx,[esp+1Ch]
0x63262f: mov fs:[0],ecx
0x632636: pop ecx
0x632637: pop edi
0x632638: pop esi
0x632639: pop ebp
0x63263a: pop ebx
0x63263b: add esp,14h
0x63263e: ret 4
````

`sub_632570` is called by sub_632570, sub_632fc0. It delegates to sub_4738d0, sub_632570, j_ORDINAL 764 (3 callees).

### sub_632650 at 0x632650 (26 instructions)

````text
0x632650: push ebp
0x632651: mov ebp,esp
0x632653: and esp,0FFFFFFF8h
0x632656: sub esp,0Ch
0x632659: push edi
0x63265a: mov edi,eax
0x63265c: mov eax,[edi+4]
0x63265f: mov ecx,[eax]
0x632661: push eax
0x632662: push edi
0x632663: push ecx
0x632664: push edi
0x632665: lea eax,[esp+18h]
0x632669: push eax
0x63266a: call 00632FC0h
0x63266f: mov ecx,[edi+4]
0x632672: push ecx
0x632673: call 006516BAh
0x632678: add esp,4
0x63267b: xor eax,eax
0x63267d: mov [edi+4],eax
0x632680: mov [edi+8],eax
0x632683: pop edi
0x632684: mov esp,ebp
0x632686: pop ebp
0x632687: ret
````

`sub_632650` is called by sub_631110. It delegates to sub_632fc0, j_ORDINAL 764 (2 callees).

### sub_6328d0 at 0x6328d0 (26 instructions)

````text
0x6328d0: push ebp
0x6328d1: mov ebp,esp
0x6328d3: and esp,0FFFFFFF8h
0x6328d6: sub esp,0Ch
0x6328d9: push edi
0x6328da: mov edi,eax
0x6328dc: mov eax,[edi+4]
0x6328df: mov ecx,[eax]
0x6328e1: push eax
0x6328e2: push edi
0x6328e3: push ecx
0x6328e4: push edi
0x6328e5: lea eax,[esp+18h]
0x6328e9: push eax
0x6328ea: call 00633340h
0x6328ef: mov ecx,[edi+4]
0x6328f2: push ecx
0x6328f3: call 006516BAh
0x6328f8: add esp,4
0x6328fb: xor eax,eax
0x6328fd: mov [edi+4],eax
0x632900: mov [edi+8],eax
0x632903: pop edi
0x632904: mov esp,ebp
0x632906: pop ebp
0x632907: ret
````

`sub_6328d0` is called by sub_631110. It delegates to sub_633340, j_ORDINAL 764 (2 callees).

### sub_632fc0 at 0x632fc0 (72 instructions)

````text
0x632fc0: mov eax,[edi+4]
0x632fc3: sub esp,0Ch
0x632fc6: push ebx
0x632fc7: mov ebx,[esp+18h]
0x632fcb: test ebx,ebx
0x632fcd: push ebp
0x632fce: push esi
0x632fcf: mov esi,[eax]
0x632fd1: je short 00632FD7h
0x632fd3: cmp ebx,edi
0x632fd5: je short 00632FDDh
0x632fd7: call dword ptr ds:[77D0E4h]
0x632fdd: mov ebp,[esp+24h]
0x632fe1: cmp ebp,esi
0x632fe3: jne short 00633040h
0x632fe5: mov eax,[esp+28h]
0x632fe9: test eax,eax
0x632feb: mov esi,[edi+4]
0x632fee: je short 00632FF4h
0x632ff0: cmp eax,edi
0x632ff2: je short 00632FFAh
0x632ff4: call dword ptr ds:[77D0E4h]
0x632ffa: cmp [esp+2Ch],esi
0x632ffe: jne short 00633040h
0x633000: mov ecx,[edi+4]
0x633003: mov edx,[ecx+4]
0x633006: push edx
0x633007: mov ecx,edi
0x633009: call 00632570h
0x63300e: mov eax,[edi+4]
0x633011: mov [eax+4],eax
0x633014: mov eax,[edi+4]
0x633017: mov dword ptr [edi+8],0
0x63301e: mov [eax],eax
0x633020: mov eax,[edi+4]
0x633023: mov [eax+8],eax
0x633026: mov eax,[edi+4]
0x633029: mov ecx,[eax]
0x63302b: mov eax,[esp+1Ch]
0x63302f: mov [eax+4],ecx
0x633032: mov [eax],edi
0x633034: pop esi
0x633035: pop ebp
0x633036: pop ebx
0x633037: add esp,0Ch
0x63303a: ret 14h
0x633040: test ebx,ebx
0x633042: je short 0063304Ah
0x633044: cmp ebx,[esp+28h]
0x633048: je short 00633050h
0x63304a: call dword ptr ds:[77D0E4h]
0x633050: cmp ebp,[esp+2Ch]
0x633054: je short 00633076h
0x633056: lea esi,[esp+20h]
0x63305a: call 00633EE0h
0x63305f: push ebp
0x633060: push ebx
0x633061: lea edx,[esp+18h]
0x633065: push edx
0x633066: push edi
0x633067: call 00633610h
0x63306c: mov ebp,[esp+24h]
0x633070: mov ebx,[esp+20h]
0x633074: jmp short 00633040h
0x633076: mov eax,[esp+1Ch]
0x63307a: pop esi
0x63307b: mov [eax+4],ebp
0x63307e: pop ebp
0x63307f: mov [eax],ebx
0x633081: pop ebx
0x633082: add esp,0Ch
0x633085: ret 14h
````

`sub_632fc0` is called by sub_632650. It delegates to sub_632570, sub_633610, sub_633ee0 (3 callees).

### sub_633340 at 0x633340 (72 instructions)

````text
0x633340: mov eax,[edi+4]
0x633343: sub esp,0Ch
0x633346: push ebx
0x633347: mov ebx,[esp+18h]
0x63334b: test ebx,ebx
0x63334d: push ebp
0x63334e: push esi
0x63334f: mov esi,[eax]
0x633351: je short 00633357h
0x633353: cmp ebx,edi
0x633355: je short 0063335Dh
0x633357: call dword ptr ds:[77D0E4h]
0x63335d: mov ebp,[esp+24h]
0x633361: cmp ebp,esi
0x633363: jne short 006333C0h
0x633365: mov eax,[esp+28h]
0x633369: test eax,eax
0x63336b: mov esi,[edi+4]
0x63336e: je short 00633374h
0x633370: cmp eax,edi
0x633372: je short 0063337Ah
0x633374: call dword ptr ds:[77D0E4h]
0x63337a: cmp [esp+2Ch],esi
0x63337e: jne short 006333C0h
0x633380: mov ecx,[edi+4]
0x633383: mov edx,[ecx+4]
0x633386: push edx
0x633387: mov ecx,edi
0x633389: call 00633F50h
0x63338e: mov eax,[edi+4]
0x633391: mov [eax+4],eax
0x633394: mov eax,[edi+4]
0x633397: mov dword ptr [edi+8],0
0x63339e: mov [eax],eax
0x6333a0: mov eax,[edi+4]
0x6333a3: mov [eax+8],eax
0x6333a6: mov eax,[edi+4]
0x6333a9: mov ecx,[eax]
0x6333ab: mov eax,[esp+1Ch]
0x6333af: mov [eax+4],ecx
0x6333b2: mov [eax],edi
0x6333b4: pop esi
0x6333b5: pop ebp
0x6333b6: pop ebx
0x6333b7: add esp,0Ch
0x6333ba: ret 14h
0x6333c0: test ebx,ebx
0x6333c2: je short 006333CAh
0x6333c4: cmp ebx,[esp+28h]
0x6333c8: je short 006333D0h
0x6333ca: call dword ptr ds:[77D0E4h]
0x6333d0: cmp ebp,[esp+2Ch]
0x6333d4: je short 006333F6h
0x6333d6: lea esi,[esp+20h]
0x6333da: call 006340C0h
0x6333df: push ebp
0x6333e0: push ebx
0x6333e1: lea edx,[esp+18h]
0x6333e5: push edx
0x6333e6: push edi
0x6333e7: call 006339E0h
0x6333ec: mov ebp,[esp+24h]
0x6333f0: mov ebx,[esp+20h]
0x6333f4: jmp short 006333C0h
0x6333f6: mov eax,[esp+1Ch]
0x6333fa: pop esi
0x6333fb: mov [eax+4],ebp
0x6333fe: pop ebp
0x6333ff: mov [eax],ebx
0x633401: pop ebx
0x633402: add esp,0Ch
0x633405: ret 14h
````

`sub_633340` is called by sub_6328d0. It delegates to sub_6339e0, sub_633f50, sub_6340c0 (3 callees).

### sub_633610 at 0x633610 (247 instructions)

````text
0x633610: push 0FFFFFFFFh
0x633612: push 7410D9h
0x633617: mov eax,fs:[0]
0x63361d: push eax
0x63361e: sub esp,44h
0x633621: push ebx
0x633622: push ebp
0x633623: push esi
0x633624: push edi
0x633625: mov eax,ds:[858220h]
0x63362a: xor eax,esp
0x63362c: push eax
0x63362d: lea eax,[esp+58h]
0x633631: mov fs:[0],eax
0x633637: mov eax,[esp+74h]
0x63363b: cmp byte ptr [eax+39h],0
0x63363f: je short 0063367Dh
0x633641: push 7C5AECh
0x633646: lea ecx,[esp+18h]
0x63364a: call dword ptr ds:[77CD7Ch]
0x633650: lea eax,[esp+14h]
0x633654: push eax
0x633655: lea ecx,[esp+34h]
0x633659: mov dword ptr [esp+64h],0
0x633661: call 00401230h
0x633666: push 80A4F8h
0x63366b: lea ecx,[esp+34h]
0x63366f: push ecx
0x633670: mov dword ptr [esp+38h],790F90h
0x633678: call 00652AC4h
0x63367d: lea esi,[esp+70h]
0x633681: mov ebp,eax
0x633683: call 00633EE0h
0x633688: mov eax,[ebp]
0x63368b: cmp byte ptr [eax+39h],0
0x63368f: je short 00633696h
0x633691: mov edi,[ebp+8]
0x633694: jmp short 006336AEh
0x633696: mov edx,[ebp+8]
0x633699: cmp byte ptr [edx+39h],0
0x63369d: je short 006336A3h
0x63369f: mov edi,eax
0x6336a1: jmp short 006336AEh
0x6336a3: mov ecx,[esp+74h]
0x6336a7: cmp ecx,ebp
0x6336a9: mov edi,[ecx+8]
0x6336ac: jne short 00633722h
0x6336ae: cmp byte ptr [edi+39h],0
0x6336b2: mov esi,[ebp+4]
0x6336b5: jne short 006336BAh
0x6336b7: mov [edi+4],esi
0x6336ba: mov ecx,[esp+68h]
0x6336be: mov eax,[ecx+4]
0x6336c1: cmp [eax+4],ebp
0x6336c4: jne short 006336CBh
0x6336c6: mov [eax+4],edi
0x6336c9: jmp short 006336D6h
0x6336cb: cmp [esi],ebp
0x6336cd: jne short 006336D3h
0x6336cf: mov [esi],edi
0x6336d1: jmp short 006336D6h
0x6336d3: mov [esi+8],edi
0x6336d6: mov edx,[ecx+4]
0x6336d9: cmp [edx],ebp
0x6336db: jne short 006336FDh
0x6336dd: cmp byte ptr [edi+39h],0
0x6336e1: je short 006336E7h
0x6336e3: mov ecx,esi
0x6336e5: jmp short 006336FBh
0x6336e7: mov eax,[edi]
0x6336e9: cmp byte ptr [eax+39h],0
0x6336ed: mov ecx,edi
0x6336ef: jne short 006336FBh
0x6336f1: mov ecx,eax
0x6336f3: mov eax,[ecx]
0x6336f5: cmp byte ptr [eax+39h],0
0x6336f9: je short 006336F1h
0x6336fb: mov [edx],ecx
0x6336fd: mov eax,[esp+68h]
0x633701: mov ebx,[eax+4]
0x633704: cmp [ebx+8],ebp
0x633707: jne short 0063377Eh
0x633709: cmp byte ptr [edi+39h],0
0x63370d: je short 00633716h
0x63370f: mov eax,esi
0x633711: mov [ebx+8],eax
0x633714: jmp short 0063377Eh
0x633716: mov eax,edi
0x633718: call 00458540h
0x63371d: mov [ebx+8],eax
0x633720: jmp short 0063377Eh
0x633722: mov [eax+4],ecx
0x633725: mov edx,[ebp]
0x633728: mov [ecx],edx
0x63372a: cmp ecx,[ebp+8]
0x63372d: jne short 00633733h
0x63372f: mov esi,ecx
0x633731: jmp short 0063374Dh
0x633733: cmp byte ptr [edi+39h],0
0x633737: mov esi,[ecx+4]
0x63373a: jne short 0063373Fh
0x63373c: mov [edi+4],esi
0x63373f: mov [esi],edi
0x633741: mov eax,[ebp+8]
0x633744: mov [ecx+8],eax
0x633747: mov edx,[ebp+8]
0x63374a: mov [edx+4],ecx
0x63374d: mov eax,[esp+68h]
0x633751: mov eax,[eax+4]
0x633754: cmp [eax+4],ebp
0x633757: jne short 0063375Eh
0x633759: mov [eax+4],ecx
0x63375c: jmp short 0063376Ch
0x63375e: mov eax,[ebp+4]
0x633761: cmp [eax],ebp
0x633763: jne short 00633769h
0x633765: mov [eax],ecx
0x633767: jmp short 0063376Ch
0x633769: mov [eax+8],ecx
0x63376c: mov edx,[ebp+4]
0x63376f: mov [ecx+4],edx
0x633772: mov dl,[ebp+38h]
0x633775: mov al,[ecx+38h]
0x633778: mov [ecx+38h],dl
0x63377b: mov [ebp+38h],al
0x63377e: mov bl,1
0x633780: cmp [ebp+38h],bl
0x633783: jne near ptr 006338AAh
0x633789: mov eax,[esp+68h]
0x63378d: mov ecx,[eax+4]
0x633790: cmp edi,[ecx+4]
0x633793: je near ptr 006338A7h
0x633799: lea esp,[esp]
0x6337a0: cmp [edi+38h],bl
0x6337a3: jne near ptr 006338A7h
0x6337a9: mov ecx,[esi]
0x6337ab: cmp edi,ecx
0x6337ad: jne short 00633825h
0x6337af: mov ecx,[esi+8]
0x6337b2: cmp byte ptr [ecx+38h],0
0x6337b6: jne short 006337CEh
0x6337b8: mov edx,[esp+68h]
0x6337bc: mov [ecx+38h],bl
0x6337bf: push edx
0x6337c0: mov ecx,esi
0x6337c2: mov byte ptr [esi+38h],0
0x6337c6: call 005F9650h
0x6337cb: mov ecx,[esi+8]
0x6337ce: cmp byte ptr [ecx+39h],0
0x6337d2: jne near ptr 00633859h
0x6337d8: mov eax,[ecx]
0x6337da: cmp [eax+38h],bl
0x6337dd: jne short 006337E7h
0x6337df: mov edx,[ecx+8]
0x6337e2: cmp [edx+38h],bl
0x6337e5: je short 00633855h
0x6337e7: mov eax,[ecx+8]
0x6337ea: cmp [eax+38h],bl
0x6337ed: jne short 00633805h
0x6337ef: mov edx,[ecx]
0x6337f1: mov eax,[esp+68h]
0x6337f5: mov [edx+38h],bl
0x6337f8: push eax
0x6337f9: mov byte ptr [ecx+38h],0
0x6337fd: call 004DD9C0h
0x633802: mov ecx,[esi+8]
0x633805: mov dl,[esi+38h]
0x633808: mov [ecx+38h],dl
0x63380b: mov [esi+38h],bl
0x63380e: mov eax,[ecx+8]
0x633811: mov ecx,[esp+68h]
0x633815: push ecx
0x633816: mov ecx,esi
0x633818: mov [eax+38h],bl
0x63381b: call 005F9650h
0x633820: jmp near ptr 006338A7h
0x633825: cmp byte ptr [ecx+38h],0
0x633829: jne short 00633840h
0x63382b: mov eax,[esp+68h]
0x63382f: mov [ecx+38h],bl
0x633832: push eax
0x633833: mov ecx,esi
0x633835: mov byte ptr [esi+38h],0
0x633839: call 004DD9C0h
0x63383e: mov ecx,[esi]
0x633840: cmp byte ptr [ecx+39h],0
0x633844: jne short 00633859h
0x633846: mov edx,[ecx+8]
0x633849: cmp [edx+38h],bl
0x63384c: jne short 00633870h
0x63384e: mov eax,[ecx]
0x633850: cmp [eax+38h],bl
0x633853: jne short 00633870h
0x633855: mov byte ptr [ecx+38h],0
0x633859: mov ecx,[esp+68h]
0x63385d: mov edx,[ecx+4]
0x633860: mov edi,esi
0x633862: cmp edi,[edx+4]
0x633865: mov esi,[esi+4]
0x633868: jne near ptr 006337A0h
0x63386e: jmp short 006338A7h
0x633870: mov edx,[ecx]
0x633872: cmp [edx+38h],bl
0x633875: jne short 0063388Dh
0x633877: mov eax,[ecx+8]
0x63387a: mov edx,[esp+68h]
0x63387e: mov [eax+38h],bl
0x633881: push edx
0x633882: mov byte ptr [ecx+38h],0
0x633886: call 005F9650h
0x63388b: mov ecx,[esi]
0x63388d: mov al,[esi+38h]
0x633890: mov edx,[esp+68h]
0x633894: mov [ecx+38h],al
0x633897: mov [esi+38h],bl
0x63389a: mov ecx,[ecx]
0x63389c: mov [ecx+38h],bl
0x63389f: push edx
0x6338a0: mov ecx,esi
0x6338a2: call 004DD9C0h
0x6338a7: mov [edi+38h],bl
0x6338aa: lea eax,[ebp+0Ch]
0x6338ad: push eax
0x6338ae: call 00632130h
0x6338b3: push ebp
0x6338b4: call 006516BAh
0x6338b9: mov ecx,[esp+6Ch]
0x6338bd: mov eax,[ecx+8]
0x6338c0: add esp,4
0x6338c3: test eax,eax
0x6338c5: jbe short 006338CDh
0x6338c7: add eax,0FFFFFFFFh
0x6338ca: mov [ecx+8],eax
0x6338cd: mov eax,[esp+6Ch]
0x6338d1: mov ecx,[esp+70h]
0x6338d5: mov edx,[esp+74h]
0x6338d9: mov [eax],ecx
0x6338db: mov [eax+4],edx
0x6338de: mov ecx,[esp+58h]
0x6338e2: mov fs:[0],ecx
0x6338e9: pop ecx
0x6338ea: pop edi
0x6338eb: pop esi
0x6338ec: pop ebp
0x6338ed: pop ebx
0x6338ee: add esp,50h
0x6338f1: ret 10h
````

`sub_633610` is called by sub_632fc0. It delegates to sub_401230, sub_458540, sub_4dd9c0 (8 callees).

### sub_633900 at 0x633900 (16 instructions)

````text
0x633900: mov ecx,1
0x633905: call 00602810h
0x63390a: test eax,eax
0x63390c: je short 00633914h
0x63390e: mov dword ptr [eax],0
0x633914: lea ecx,[eax+4]
0x633917: test ecx,ecx
0x633919: je short 00633921h
0x63391b: mov dword ptr [ecx],0
0x633921: lea ecx,[eax+8]
0x633924: test ecx,ecx
0x633926: je short 0063392Eh
0x633928: mov dword ptr [ecx],0
0x63392e: mov byte ptr [eax+38h],1
0x633932: mov byte ptr [eax+39h],0
0x633936: ret
````

`sub_633900` is called by sub_5dfc30, sub_5ea5d0, sub_5f5590, sub_619e20, sub_620460, sub_631060. It delegates to sub_602810 (1 callees).

### sub_6339e0 at 0x6339e0 (239 instructions)

````text
0x6339e0: push 0FFFFFFFFh
0x6339e2: push 7410D9h
0x6339e7: mov eax,fs:[0]
0x6339ed: push eax
0x6339ee: sub esp,44h
0x6339f1: push ebx
0x6339f2: push ebp
0x6339f3: push esi
0x6339f4: push edi
0x6339f5: mov eax,ds:[858220h]
0x6339fa: xor eax,esp
0x6339fc: push eax
0x6339fd: lea eax,[esp+58h]
0x633a01: mov fs:[0],eax
0x633a07: mov eax,[esp+74h]
0x633a0b: cmp byte ptr [eax+9Dh],0
0x633a12: je short 00633A50h
0x633a14: push 7C5AECh
0x633a19: lea ecx,[esp+18h]
0x633a1d: call dword ptr ds:[77CD7Ch]
0x633a23: lea eax,[esp+14h]
0x633a27: push eax
0x633a28: lea ecx,[esp+34h]
0x633a2c: mov dword ptr [esp+64h],0
0x633a34: call 00401230h
0x633a39: push 80A4F8h
0x633a3e: lea ecx,[esp+34h]
0x633a42: push ecx
0x633a43: mov dword ptr [esp+38h],790F90h
0x633a4b: call 00652AC4h
0x633a50: lea esi,[esp+70h]
0x633a54: mov ebp,eax
0x633a56: call 006340C0h
0x633a5b: mov eax,[ebp]
0x633a5e: cmp byte ptr [eax+9Dh],0
0x633a65: je short 00633A6Ch
0x633a67: mov edi,[ebp+8]
0x633a6a: jmp short 00633A87h
0x633a6c: mov edx,[ebp+8]
0x633a6f: cmp byte ptr [edx+9Dh],0
0x633a76: je short 00633A7Ch
0x633a78: mov edi,eax
0x633a7a: jmp short 00633A87h
0x633a7c: mov ecx,[esp+74h]
0x633a80: cmp ecx,ebp
0x633a82: mov edi,[ecx+8]
0x633a85: jne short 00633AFFh
0x633a87: cmp byte ptr [edi+9Dh],0
0x633a8e: mov esi,[ebp+4]
0x633a91: jne short 00633A96h
0x633a93: mov [edi+4],esi
0x633a96: mov edx,[esp+68h]
0x633a9a: mov eax,[edx+4]
0x633a9d: cmp [eax+4],ebp
0x633aa0: jne short 00633AA7h
0x633aa2: mov [eax+4],edi
0x633aa5: jmp short 00633AB2h
0x633aa7: cmp [esi],ebp
0x633aa9: jne short 00633AAFh
0x633aab: mov [esi],edi
0x633aad: jmp short 00633AB2h
0x633aaf: mov [esi+8],edi
0x633ab2: mov ebx,[edx+4]
0x633ab5: cmp [ebx],ebp
0x633ab7: jne short 00633AD3h
0x633ab9: cmp byte ptr [edi+9Dh],0
0x633ac0: je short 00633AC6h
0x633ac2: mov eax,esi
0x633ac4: jmp short 00633AD1h
0x633ac6: mov eax,edi
0x633ac8: call 00634010h
0x633acd: mov edx,[esp+68h]
0x633ad1: mov [ebx],eax
0x633ad3: mov ebx,[edx+4]
0x633ad6: cmp [ebx+8],ebp
0x633ad9: jne near ptr 00633B6Eh
0x633adf: cmp byte ptr [edi+9Dh],0
0x633ae6: je short 00633AEFh
0x633ae8: mov eax,esi
0x633aea: mov [ebx+8],eax
0x633aed: jmp short 00633B6Eh
0x633aef: mov eax,edi
0x633af1: call 00633FF0h
0x633af6: mov edx,[esp+68h]
0x633afa: mov [ebx+8],eax
0x633afd: jmp short 00633B6Eh
0x633aff: mov [eax+4],ecx
0x633b02: mov eax,[ebp]
0x633b05: mov [ecx],eax
0x633b07: cmp ecx,[ebp+8]
0x633b0a: jne short 00633B10h
0x633b0c: mov esi,ecx
0x633b0e: jmp short 00633B2Dh
0x633b10: cmp byte ptr [edi+9Dh],0
0x633b17: mov esi,[ecx+4]
0x633b1a: jne short 00633B1Fh
0x633b1c: mov [edi+4],esi
0x633b1f: mov [esi],edi
0x633b21: mov edx,[ebp+8]
0x633b24: mov [ecx+8],edx
0x633b27: mov eax,[ebp+8]
0x633b2a: mov [eax+4],ecx
0x633b2d: mov edx,[esp+68h]
0x633b31: mov eax,[edx+4]
0x633b34: cmp [eax+4],ebp
0x633b37: jne short 00633B3Eh
0x633b39: mov [eax+4],ecx
0x633b3c: jmp short 00633B4Ch
0x633b3e: mov eax,[ebp+4]
0x633b41: cmp [eax],ebp
0x633b43: jne short 00633B49h
0x633b45: mov [eax],ecx
0x633b47: jmp short 00633B4Ch
0x633b49: mov [eax+8],ecx
0x633b4c: mov eax,[ebp+4]
0x633b4f: mov [ecx+4],eax
0x633b52: mov dl,[ebp+9Ch]
0x633b58: mov al,[ecx+9Ch]
0x633b5e: mov [ecx+9Ch],dl
0x633b64: mov edx,[esp+68h]
0x633b68: mov [ebp+9Ch],al
0x633b6e: mov bl,1
0x633b70: cmp [ebp+9Ch],bl
0x633b76: jne near ptr 00633CEDh
0x633b7c: mov eax,[edx+4]
0x633b7f: cmp edi,[eax+4]
0x633b82: je near ptr 00633CE7h
0x633b88: jmp short 00633B90h
0x633b90: cmp [edi+9Ch],bl
0x633b96: jne near ptr 00633CE7h
0x633b9c: mov ecx,[esi]
0x633b9e: cmp edi,ecx
0x633ba0: jne near ptr 00633C43h
0x633ba6: mov ecx,[esi+8]
0x633ba9: cmp byte ptr [ecx+9Ch],0
0x633bb0: jne short 00633BCEh
0x633bb2: mov [ecx+9Ch],bl
0x633bb8: push edx
0x633bb9: mov ecx,esi
0x633bbb: mov byte ptr [esi+9Ch],0
0x633bc2: call 00633D40h
0x633bc7: mov ecx,[esi+8]
0x633bca: mov edx,[esp+68h]
0x633bce: cmp byte ptr [ecx+9Dh],0
0x633bd5: jne near ptr 00633C8Ch
0x633bdb: mov eax,[ecx]
0x633bdd: cmp [eax+9Ch],bl
0x633be3: jne short 00633BF4h
0x633be5: mov eax,[ecx+8]
0x633be8: cmp [eax+9Ch],bl
0x633bee: je near ptr 00633C85h
0x633bf4: mov eax,[ecx+8]
0x633bf7: cmp [eax+9Ch],bl
0x633bfd: jne short 00633C1Bh
0x633bff: mov eax,[ecx]
0x633c01: mov [eax+9Ch],bl
0x633c07: push edx
0x633c08: mov byte ptr [ecx+9Ch],0
0x633c0f: call 00633D90h
0x633c14: mov ecx,[esi+8]
0x633c17: mov edx,[esp+68h]
0x633c1b: mov al,[esi+9Ch]
0x633c21: mov [ecx+9Ch],al
0x633c27: mov [esi+9Ch],bl
0x633c2d: mov ecx,[ecx+8]
0x633c30: mov [ecx+9Ch],bl
0x633c36: push edx
0x633c37: mov ecx,esi
0x633c39: call 00633D40h
0x633c3e: jmp near ptr 00633CE7h
0x633c43: cmp byte ptr [ecx+9Ch],0
0x633c4a: jne short 00633C67h
0x633c4c: mov [ecx+9Ch],bl
0x633c52: push edx
0x633c53: mov ecx,esi
0x633c55: mov byte ptr [esi+9Ch],0
0x633c5c: call 00633D90h
0x633c61: mov ecx,[esi]
0x633c63: mov edx,[esp+68h]
0x633c67: cmp byte ptr [ecx+9Dh],0
0x633c6e: jne short 00633C8Ch
0x633c70: mov eax,[ecx+8]
0x633c73: cmp [eax+9Ch],bl
0x633c79: jne short 00633C9Fh
0x633c7b: mov eax,[ecx]
0x633c7d: cmp [eax+9Ch],bl
0x633c83: jne short 00633C9Fh
0x633c85: mov byte ptr [ecx+9Ch],0
0x633c8c: mov ecx,[edx+4]
0x633c8f: mov edi,esi
0x633c91: cmp edi,[ecx+4]
0x633c94: mov esi,[esi+4]
0x633c97: jne near ptr 00633B90h
0x633c9d: jmp short 00633CE7h
0x633c9f: mov eax,[ecx]
0x633ca1: cmp [eax+9Ch],bl
0x633ca7: jne short 00633CC5h
0x633ca9: mov eax,[ecx+8]
0x633cac: mov [eax+9Ch],bl
0x633cb2: push edx
0x633cb3: mov byte ptr [ecx+9Ch],0
0x633cba: call 00633D40h
0x633cbf: mov ecx,[esi]
0x633cc1: mov edx,[esp+68h]
0x633cc5: mov al,[esi+9Ch]
0x633ccb: mov [ecx+9Ch],al
0x633cd1: mov [esi+9Ch],bl
0x633cd7: mov ecx,[ecx]
0x633cd9: mov [ecx+9Ch],bl
0x633cdf: push edx
0x633ce0: mov ecx,esi
0x633ce2: call 00633D90h
0x633ce7: mov [edi+9Ch],bl
0x633ced: lea edx,[ebp+0Ch]
0x633cf0: push edx
0x633cf1: call 00632190h
0x633cf6: push ebp
0x633cf7: call 006516BAh
0x633cfc: mov ecx,[esp+6Ch]
0x633d00: mov eax,[ecx+8]
0x633d03: add esp,4
0x633d06: test eax,eax
0x633d08: jbe short 00633D10h
0x633d0a: add eax,0FFFFFFFFh
0x633d0d: mov [ecx+8],eax
0x633d10: mov eax,[esp+6Ch]
0x633d14: mov ecx,[esp+70h]
0x633d18: mov edx,[esp+74h]
0x633d1c: mov [eax],ecx
0x633d1e: mov [eax+4],edx
0x633d21: mov ecx,[esp+58h]
0x633d25: mov fs:[0],ecx
0x633d2c: pop ecx
0x633d2d: pop edi
0x633d2e: pop esi
0x633d2f: pop ebp
0x633d30: pop ebx
0x633d31: add esp,50h
0x633d34: ret 10h
````

`sub_6339e0` is called by sub_633340. It delegates to sub_401230, sub_632190, sub_633d40 (9 callees).

### sub_633d40 at 0x633d40 (28 instructions)

````text
0x633d40: mov eax,[ecx+8]
0x633d43: mov edx,[eax]
0x633d45: mov [ecx+8],edx
0x633d48: mov edx,[eax]
0x633d4a: cmp byte ptr [edx+9Dh],0
0x633d51: jne short 00633D56h
0x633d53: mov [edx+4],ecx
0x633d56: mov edx,[ecx+4]
0x633d59: mov [eax+4],edx
0x633d5c: mov edx,[esp+4]
0x633d60: mov edx,[edx+4]
0x633d63: cmp ecx,[edx+4]
0x633d66: jne short 00633D73h
0x633d68: mov [edx+4],eax
0x633d6b: mov [eax],ecx
0x633d6d: mov [ecx+4],eax
0x633d70: ret 4
0x633d73: mov edx,[ecx+4]
0x633d76: cmp ecx,[edx]
0x633d78: jne short 00633D84h
0x633d7a: mov [edx],eax
0x633d7c: mov [eax],ecx
0x633d7e: mov [ecx+4],eax
0x633d81: ret 4
0x633d84: mov [edx+8],eax
0x633d87: mov [eax],ecx
0x633d89: mov [ecx+4],eax
0x633d8c: ret 4
````

`sub_633d40` is called by sub_6339e0. It calls nothing else.

### sub_633d90 at 0x633d90 (28 instructions)

````text
0x633d90: mov eax,[ecx]
0x633d92: mov edx,[eax+8]
0x633d95: mov [ecx],edx
0x633d97: mov edx,[eax+8]
0x633d9a: cmp byte ptr [edx+9Dh],0
0x633da1: jne short 00633DA6h
0x633da3: mov [edx+4],ecx
0x633da6: mov edx,[ecx+4]
0x633da9: mov [eax+4],edx
0x633dac: mov edx,[esp+4]
0x633db0: mov edx,[edx+4]
0x633db3: cmp ecx,[edx+4]
0x633db6: jne short 00633DC4h
0x633db8: mov [edx+4],eax
0x633dbb: mov [eax+8],ecx
0x633dbe: mov [ecx+4],eax
0x633dc1: ret 4
0x633dc4: mov edx,[ecx+4]
0x633dc7: cmp ecx,[edx+8]
0x633dca: jne short 00633DD8h
0x633dcc: mov [edx+8],eax
0x633dcf: mov [eax+8],ecx
0x633dd2: mov [ecx+4],eax
0x633dd5: ret 4
0x633dd8: mov [edx],eax
0x633dda: mov [eax+8],ecx
0x633ddd: mov [ecx+4],eax
0x633de0: ret 4
````

`sub_633d90` is called by sub_6339e0. It calls nothing else.

### sub_633df0 at 0x633df0 (16 instructions)

````text
0x633df0: mov ecx,1
0x633df5: call 00634280h
0x633dfa: test eax,eax
0x633dfc: je short 00633E04h
0x633dfe: mov dword ptr [eax],0
0x633e04: lea ecx,[eax+4]
0x633e07: test ecx,ecx
0x633e09: je short 00633E11h
0x633e0b: mov dword ptr [ecx],0
0x633e11: lea ecx,[eax+8]
0x633e14: test ecx,ecx
0x633e16: je short 00633E1Eh
0x633e18: mov dword ptr [ecx],0
0x633e1e: mov byte ptr [eax+9Ch],1
0x633e25: mov byte ptr [eax+9Dh],0
0x633e2c: ret
````

`sub_633df0` is called by sub_631060. It delegates to sub_634280 (1 callees).

### sub_633ee0 at 0x633ee0 (39 instructions)

````text
0x633ee0: cmp dword ptr [esi],0
0x633ee3: push edi
0x633ee4: mov edi,ds:[77D0E4h]
0x633eea: jne short 00633EEEh
0x633eec: call edi
0x633eee: mov eax,[esi+4]
0x633ef1: cmp byte ptr [eax+39h],0
0x633ef5: je short 00633EFBh
0x633ef7: call edi
0x633ef9: pop edi
0x633efa: ret
0x633efb: mov ecx,[eax+8]
0x633efe: cmp byte ptr [ecx+39h],0
0x633f02: jne short 00633F1Fh
0x633f04: mov eax,[ecx]
0x633f06: cmp byte ptr [eax+39h],0
0x633f0a: jne short 00633F1Ah
0x633f0c: lea esp,[esp]
0x633f10: mov ecx,eax
0x633f12: mov eax,[ecx]
0x633f14: cmp byte ptr [eax+39h],0
0x633f18: je short 00633F10h
0x633f1a: mov [esi+4],ecx
0x633f1d: pop edi
0x633f1e: ret
0x633f1f: mov eax,[eax+4]
0x633f22: cmp byte ptr [eax+39h],0
0x633f26: jne short 00633F3Eh
0x633f28: mov ecx,[esi+4]
0x633f2b: cmp ecx,[eax+8]
0x633f2e: jne short 00633F3Eh
0x633f30: mov [esi+4],eax
0x633f33: mov edx,eax
0x633f35: mov eax,[edx+4]
0x633f38: cmp byte ptr [eax+39h],0
0x633f3c: je short 00633F28h
0x633f3e: mov [esi+4],eax
0x633f41: pop edi
0x633f42: ret
````

`sub_633ee0` is called by sub_4dd400, sub_4dd6d0, sub_506820, sub_506d20, sub_5e3ee0, sub_5e42e0, sub_5e5cd0, sub_5e6050, sub_5e63d0, sub_5e6990, sub_5ef4e0, sub_5f0420, sub_5f8c50, sub_5f9360, sub_622780, sub_6229f0, sub_632fc0, sub_633610. It calls nothing else.

### sub_633f50 at 0x633f50 (47 instructions)

````text
0x633f50: push 0FFFFFFFFh
0x633f52: push 73E709h
0x633f57: mov eax,fs:[0]
0x633f5d: push eax
0x633f5e: push ebx
0x633f5f: push ebp
0x633f60: push esi
0x633f61: push edi
0x633f62: mov eax,ds:[858220h]
0x633f67: xor eax,esp
0x633f69: push eax
0x633f6a: lea eax,[esp+14h]
0x633f6e: mov fs:[0],eax
0x633f74: mov ebx,ecx
0x633f76: mov edi,[esp+24h]
0x633f7a: cmp byte ptr [edi+9Dh],0
0x633f81: mov esi,edi
0x633f83: jne short 00633FCEh
0x633f85: mov eax,[esi+8]
0x633f88: push eax
0x633f89: mov ecx,ebx
0x633f8b: call 00633F50h
0x633f90: mov esi,[esi]
0x633f92: lea ebp,[edi+0Ch]
0x633f95: mov [esp+24h],ebp
0x633f99: lea ecx,[ebp+1Ch]
0x633f9c: push ecx
0x633f9d: mov dword ptr [esp+20h],0
0x633fa5: call 004738D0h
0x633faa: mov ecx,ebp
0x633fac: mov dword ptr [esp+1Ch],0FFFFFFFFh
0x633fb4: call dword ptr ds:[77CD74h]
0x633fba: push edi
0x633fbb: call 006516BAh
0x633fc0: add esp,4
0x633fc3: cmp byte ptr [esi+9Dh],0
0x633fca: mov edi,esi
0x633fcc: je short 00633F85h
0x633fce: mov ecx,[esp+14h]
0x633fd2: mov fs:[0],ecx
0x633fd9: pop ecx
0x633fda: pop edi
0x633fdb: pop esi
0x633fdc: pop ebp
0x633fdd: pop ebx
0x633fde: add esp,0Ch
0x633fe1: ret 4
````

`sub_633f50` is called by sub_633340, sub_633f50. It delegates to sub_4738d0, sub_633f50, j_ORDINAL 764 (3 callees).

### sub_633ff0 at 0x633ff0 (9 instructions)

````text
0x633ff0: mov ecx,[eax+8]
0x633ff3: cmp byte ptr [ecx+9Dh],0
0x633ffa: jne short 0063400Eh
0x633ffc: lea esp,[esp]
0x634000: mov eax,ecx
0x634002: mov ecx,[eax+8]
0x634005: cmp byte ptr [ecx+9Dh],0
0x63400c: je short 00634000h
0x63400e: ret
````

`sub_633ff0` is called by sub_6339e0. It calls nothing else.

### sub_634010 at 0x634010 (9 instructions)

````text
0x634010: mov ecx,[eax]
0x634012: cmp byte ptr [ecx+9Dh],0
0x634019: jne short 0063402Dh
0x63401b: jmp short 00634020h
0x634020: mov eax,ecx
0x634022: mov ecx,[eax]
0x634024: cmp byte ptr [ecx+9Dh],0
0x63402b: je short 00634020h
0x63402d: ret
````

`sub_634010` is called by sub_6339e0. It calls nothing else.

### sub_6340c0 at 0x6340c0 (38 instructions)

````text
0x6340c0: cmp dword ptr [esi],0
0x6340c3: push edi
0x6340c4: mov edi,ds:[77D0E4h]
0x6340ca: jne short 006340CEh
0x6340cc: call edi
0x6340ce: mov eax,[esi+4]
0x6340d1: cmp byte ptr [eax+9Dh],0
0x6340d8: je short 006340DEh
0x6340da: call edi
0x6340dc: pop edi
0x6340dd: ret
0x6340de: mov ecx,[eax+8]
0x6340e1: cmp byte ptr [ecx+9Dh],0
0x6340e8: jne short 00634107h
0x6340ea: mov eax,[ecx]
0x6340ec: cmp byte ptr [eax+9Dh],0
0x6340f3: jne short 00634102h
0x6340f5: mov ecx,eax
0x6340f7: mov eax,[ecx]
0x6340f9: cmp byte ptr [eax+9Dh],0
0x634100: je short 006340F5h
0x634102: mov [esi+4],ecx
0x634105: pop edi
0x634106: ret
0x634107: mov eax,[eax+4]
0x63410a: cmp byte ptr [eax+9Dh],0
0x634111: jne short 0063412Ch
0x634113: mov ecx,[esi+4]
0x634116: cmp ecx,[eax+8]
0x634119: jne short 0063412Ch
0x63411b: mov [esi+4],eax
0x63411e: mov edx,eax
0x634120: mov eax,[edx+4]
0x634123: cmp byte ptr [eax+9Dh],0
0x63412a: je short 00634113h
0x63412c: mov [esi+4],eax
0x63412f: pop edi
0x634130: ret
````

`sub_6340c0` is called by sub_633340, sub_6339e0. It calls nothing else.

### sub_634280 at 0x634280 (23 instructions)

````text
0x634280: or eax,0FFFFFFFFh
0x634283: xor edx,edx
0x634285: div ecx
0x634287: sub esp,10h
0x63428a: cmp eax,0A0h
0x63428f: jae short 006342BEh
0x634291: lea eax,[esp]
0x634294: push eax
0x634295: lea ecx,[esp+8]
0x634299: mov dword ptr [esp+4],0
0x6342a1: call dword ptr ds:[77D0DCh]
0x6342a7: push 80A2ACh
0x6342ac: lea ecx,[esp+8]
0x6342b0: push ecx
0x6342b1: mov dword ptr [esp+0Ch],78FFD4h
0x6342b9: call 00652AC4h
0x6342be: lea edx,[ecx+ecx*4]
0x6342c1: shl edx,5
0x6342c4: push edx
0x6342c5: call 006516C0h
0x6342ca: add esp,4
0x6342cd: add esp,10h
0x6342d0: ret
````

`sub_634280` is called by sub_633df0. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_6358b0 at 0x6358b0 (6 instructions)

````text
0x6358b0: mov eax,ecx
0x6358b2: xor ecx,ecx
0x6358b4: mov [eax+4],ecx
0x6358b7: mov [eax+8],ecx
0x6358ba: mov [eax+0Ch],ecx
0x6358bd: ret
````

`sub_6358b0` has no recorded callers; it is a leaf stub, likely reached through the vector table. It calls nothing else.

### sub_6358c0 at 0x6358c0 (5 instructions)

````text
0x6358c0: push ebx
0x6358c1: mov ebx,ecx
0x6358c3: call 00635D40h
0x6358c8: pop ebx
0x6358c9: ret
````

`sub_6358c0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_635d40 (1 callees).

### sub_635d40 at 0x635d40 (23 instructions)

````text
0x635d40: push esi
0x635d41: mov esi,[ebx+4]
0x635d44: test esi,esi
0x635d46: je short 00635D6Dh
0x635d48: push edi
0x635d49: mov edi,[ebx+8]
0x635d4c: cmp esi,edi
0x635d4e: je short 00635D60h
0x635d50: lea ecx,[esi+4]
0x635d53: call dword ptr ds:[77CD74h]
0x635d59: add esi,24h
0x635d5c: cmp esi,edi
0x635d5e: jne short 00635D50h
0x635d60: mov eax,[ebx+4]
0x635d63: push eax
0x635d64: call 006516BAh
0x635d69: add esp,4
0x635d6c: pop edi
0x635d6d: mov dword ptr [ebx+4],0
0x635d74: mov dword ptr [ebx+8],0
0x635d7b: mov dword ptr [ebx+0Ch],0
0x635d82: pop esi
0x635d83: ret
````

`sub_635d40` is called by sub_6358c0. It delegates to j_ORDINAL 764 (1 callees).

### sub_636c20 at 0x636c20 (31 instructions)

````text
0x636c20: push 0FFFFFFFFh
0x636c22: push 7479E5h
0x636c27: mov eax,fs:[0]
0x636c2d: push eax
0x636c2e: push esi
0x636c2f: push edi
0x636c30: mov eax,ds:[858220h]
0x636c35: xor eax,esp
0x636c37: push eax
0x636c38: lea eax,[esp+0Ch]
0x636c3c: mov fs:[0],eax
0x636c42: mov esi,[esp+1Ch]
0x636c46: mov ecx,esi
0x636c48: call dword ptr ds:[77CD80h]
0x636c4e: xor edi,edi
0x636c50: lea ecx,[esi+1Ch]
0x636c53: mov [esp+14h],edi
0x636c57: call dword ptr ds:[77CD80h]
0x636c5d: mov [esi+38h],edi
0x636c60: mov [esi+3Ch],edi
0x636c63: mov [esi+44h],edi
0x636c66: mov [esi+48h],edi
0x636c69: mov [esi+4Ch],edi
0x636c6c: mov eax,esi
0x636c6e: mov ecx,[esp+0Ch]
0x636c72: mov fs:[0],ecx
0x636c79: pop ecx
0x636c7a: pop edi
0x636c7b: pop esi
0x636c7c: add esp,0Ch
0x636c7f: ret 4
````

`sub_636c20` is called by sub_610980. It calls nothing else.

### sub_636c90 at 0x636c90 (38 instructions)

````text
0x636c90: push 0FFFFFFFFh
0x636c92: push 73E660h
0x636c97: mov eax,fs:[0]
0x636c9d: push eax
0x636c9e: push ebx
0x636c9f: push esi
0x636ca0: mov eax,ds:[858220h]
0x636ca5: xor eax,esp
0x636ca7: push eax
0x636ca8: lea eax,[esp+0Ch]
0x636cac: mov fs:[0],eax
0x636cb2: mov esi,[esp+1Ch]
0x636cb6: mov ecx,esi
0x636cb8: mov dword ptr [esp+14h],2
0x636cc0: call 00637190h
0x636cc5: mov eax,[esi+44h]
0x636cc8: xor ebx,ebx
0x636cca: cmp eax,ebx
0x636ccc: je short 00636CD7h
0x636cce: push eax
0x636ccf: call 006516BAh
0x636cd4: add esp,4
0x636cd7: lea ecx,[esi+1Ch]
0x636cda: mov [esi+44h],ebx
0x636cdd: mov [esi+48h],ebx
0x636ce0: mov [esi+4Ch],ebx
0x636ce3: mov [esp+14h],bl
0x636ce7: call dword ptr ds:[77CD74h]
0x636ced: mov ecx,esi
0x636cef: mov dword ptr [esp+14h],0FFFFFFFFh
0x636cf7: call dword ptr ds:[77CD74h]
0x636cfd: mov ecx,[esp+0Ch]
0x636d01: mov fs:[0],ecx
0x636d08: pop ecx
0x636d09: pop esi
0x636d0a: pop ebx
0x636d0b: add esp,0Ch
0x636d0e: ret 4
````

`sub_636c90` is called by sub_610c30. It delegates to sub_637190, j_ORDINAL 764 (2 callees).

### sub_637190 at 0x637190 (236 instructions)

````text
0x637190: push ebp
0x637191: mov ebp,esp
0x637193: and esp,0FFFFFFF8h
0x637196: push 0FFFFFFFFh
0x637198: push 73E606h
0x63719d: mov eax,fs:[0]
0x6371a3: push eax
0x6371a4: sub esp,90h
0x6371aa: mov eax,ds:[858220h]
0x6371af: xor eax,esp
0x6371b1: mov [esp+88h],eax
0x6371b8: push ebx
0x6371b9: push esi
0x6371ba: push edi
0x6371bb: mov eax,ds:[858220h]
0x6371c0: xor eax,esp
0x6371c2: push eax
0x6371c3: lea eax,[esp+0A0h]
0x6371ca: mov fs:[0],eax
0x6371d0: mov esi,ecx
0x6371d2: push 0
0x6371d4: lea ecx,[esp+1Ch]
0x6371d8: call dword ptr ds:[77DE3Ch]
0x6371de: mov dword ptr [esp+0A8h],0
0x6371e9: mov edi,ds:[77DE2Ch]
0x6371ef: push esi
0x6371f0: lea ecx,[esp+1Ch]
0x6371f4: call edi
0x6371f6: test al,al
0x6371f8: lea ecx,[esp+18h]
0x6371fc: jne short 00637216h
0x6371fe: mov dword ptr [esp+0A8h],0FFFFFFFFh
0x637209: call dword ptr ds:[77DE38h]
0x63720f: xor al,al
0x637211: jmp near ptr 006374E7h
0x637216: lea eax,[esi+1Ch]
0x637219: push eax
0x63721a: call edi
0x63721c: test al,al
0x63721e: je near ptr 00637452h
0x637224: mov ecx,[esi+38h]
0x637227: mov edi,ds:[77DE1Ch]
0x63722d: push ecx
0x63722e: lea ecx,[esp+1Ch]
0x637232: call edi
0x637234: test al,al
0x637236: lea ecx,[esp+18h]
0x63723a: je short 006371FEh
0x63723c: mov edx,[esi+3Ch]
0x63723f: push edx
0x637240: call edi
0x637242: test al,al
0x637244: je near ptr 00637452h
0x63724a: mov ecx,[esi+44h]
0x63724d: test ecx,ecx
0x63724f: jne short 00637255h
0x637251: xor eax,eax
0x637253: jmp short 0063725Ah
0x637255: mov eax,[esi+48h]
0x637258: sub eax,ecx
0x63725a: push eax
0x63725b: lea ecx,[esp+1Ch]
0x63725f: call dword ptr ds:[77DE34h]
0x637265: test al,al
0x637267: je near ptr 00637452h
0x63726d: mov ebx,ds:[77DE30h]
0x637273: xor edi,edi
0x637275: mov ecx,[esi+44h]
0x637278: test ecx,ecx
0x63727a: je short 006372B4h
0x63727c: mov eax,[esi+48h]
0x63727f: sub eax,ecx
0x637281: cmp edi,eax
0x637283: jae short 006372B4h
0x637285: test ecx,ecx
0x637287: je short 00637292h
0x637289: mov eax,[esi+48h]
0x63728c: sub eax,ecx
0x63728e: cmp edi,eax
0x637290: jb short 00637298h
0x637292: call dword ptr ds:[77D0E4h]
0x637298: mov eax,[esi+44h]
0x63729b: add eax,edi
0x63729d: movzx eax,byte ptr [eax]
0x6372a0: push eax
0x6372a1: lea ecx,[esp+1Ch]
0x6372a5: call ebx
0x6372a7: test al,al
0x6372a9: je near ptr 00637452h
0x6372af: add edi,1
0x6372b2: jmp short 00637275h
0x6372b4: mov esi,ds:[77DE20h]
0x6372ba: lea ecx,[esp+18h]
0x6372be: call esi
0x6372c0: mov edi,eax
0x6372c2: lea ebx,[esp+14h]
0x6372c6: call 004608F0h
0x6372cb: mov byte ptr [esp+0A8h],1
0x6372d3: mov eax,[esp+14h]
0x6372d7: test eax,eax
0x6372d9: jne short 006372DFh
0x6372db: xor edi,edi
0x6372dd: jmp short 006372E2h
0x6372df: mov edi,[eax+4]
0x6372e2: lea ecx,[esp+18h]
0x6372e6: call esi
0x6372e8: push eax
0x6372e9: lea ecx,[esp+1Ch]
0x6372ed: call dword ptr ds:[77DE18h]
0x6372f3: push eax
0x6372f4: push edi
0x6372f5: call 00652A82h
0x6372fa: add esp,0Ch
0x6372fd: lea ecx,[esp+44h]
0x637301: call dword ptr ds:[77CD80h]
0x637307: lea esi,[esp+28h]
0x63730b: lea eax,[esp+14h]
0x63730f: mov byte ptr [esp+0A8h],2
0x637317: call 004A4EA0h
0x63731c: lea ecx,[esp+44h]
0x637320: push ecx
0x637321: push eax
0x637322: push 7BFD20h
0x637327: mov byte ptr [esp+0B4h],3
0x63732f: call dword ptr ds:[77D15Ch]
0x637335: add esp,0Ch
0x637338: mov ecx,esi
0x63733a: mov byte ptr [esp+0A8h],2
0x637342: call dword ptr ds:[77CD74h]
0x637348: lea ecx,[esp+7Ch]
0x63734c: call dword ptr ds:[77CD80h]
0x637352: mov bl,4
0x637354: lea ecx,[esp+13h]
0x637358: mov [esp+0A8h],bl
0x63735f: call dword ptr ds:[77DF2Ch]
0x637365: mov byte ptr [esp+0A8h],5
0x63736d: mov ecx,[esp+48h]
0x637371: mov edi,10h
0x637376: cmp [esp+5Ch],edi
0x63737a: jae short 00637380h
0x63737c: lea ecx,[esp+48h]
0x637380: lea edx,[esp+7Ch]
0x637384: push edx
0x637385: mov edx,[esp+5Ch]
0x637389: push edx
0x63738a: push ecx
0x63738b: mov ecx,eax
0x63738d: call dword ptr ds:[77DF30h]
0x637393: lea ecx,[esp+13h]
0x637397: mov [esp+0A8h],bl
0x63739e: call dword ptr ds:[77DF28h]
0x6373a4: lea eax,[esp+7Ch]
0x6373a8: push eax
0x6373a9: lea ecx,[esp+48h]
0x6373ad: call dword ptr ds:[77CD70h]
0x6373b3: lea ecx,[esp+28h]
0x6373b7: push 7BFC67h
0x6373bc: push ecx
0x6373bd: call dword ptr ds:[77D130h]
0x6373c3: push 7F6AC4h
0x6373c8: push eax
0x6373c9: lea edx,[esp+70h]
0x6373cd: push edx
0x6373ce: mov byte ptr [esp+0BCh],6
0x6373d6: call dword ptr ds:[77CD84h]
0x6373dc: add esp,14h
0x6373df: lea ecx,[esp+28h]
0x6373e3: mov byte ptr [esp+0A8h],8
0x6373eb: call dword ptr ds:[77CD74h]
0x6373f1: cmp [esp+78h],edi
0x6373f5: mov eax,[esp+64h]
0x6373f9: jae short 006373FFh
0x6373fb: lea eax,[esp+64h]
0x6373ff: push 7CC4C0h
0x637404: push eax
0x637405: call dword ptr ds:[77D088h]
0x63740b: mov esi,eax
0x63740d: add esp,8
0x637410: test esi,esi
0x637412: jne short 0063746Bh
0x637414: lea ecx,[esp+60h]
0x637418: mov [esp+0A8h],bl
0x63741f: call dword ptr ds:[77CD74h]
0x637425: lea ecx,[esp+7Ch]
0x637429: mov byte ptr [esp+0A8h],2
0x637431: call dword ptr ds:[77CD74h]
0x637437: lea ecx,[esp+44h]
0x63743b: mov byte ptr [esp+0A8h],1
0x637443: call dword ptr ds:[77CD74h]
0x637449: lea edi,[esp+14h]
0x63744d: call 00460950h
0x637452: lea ecx,[esp+18h]
0x637456: mov dword ptr [esp+0A8h],0FFFFFFFFh
0x637461: call dword ptr ds:[77DE38h]
0x637467: xor al,al
0x637469: jmp short 006374E7h
0x63746b: cmp [esp+5Ch],edi
0x63746f: mov eax,[esp+48h]
0x637473: jae short 00637479h
0x637475: lea eax,[esp+48h]
0x637479: mov ecx,[esp+58h]
0x63747d: push esi
0x63747e: push ecx
0x63747f: push 1
0x637481: push eax
0x637482: call dword ptr ds:[77D074h]
0x637488: push esi
0x637489: call dword ptr ds:[77D0F0h]
0x63748f: add esp,14h
0x637492: lea ecx,[esp+60h]
0x637496: mov [esp+0A8h],bl
0x63749d: call dword ptr ds:[77CD74h]
0x6374a3: lea ecx,[esp+7Ch]
0x6374a7: mov byte ptr [esp+0A8h],2
0x6374af: call dword ptr ds:[77CD74h]
0x6374b5: lea ecx,[esp+44h]
0x6374b9: mov byte ptr [esp+0A8h],1
0x6374c1: call dword ptr ds:[77CD74h]
0x6374c7: lea edi,[esp+14h]
0x6374cb: call 00460950h
0x6374d0: lea ecx,[esp+18h]
0x6374d4: mov dword ptr [esp+0A8h],0FFFFFFFFh
0x6374df: call dword ptr ds:[77DE38h]
0x6374e5: mov al,1
0x6374e7: mov ecx,[esp+0A0h]
0x6374ee: mov fs:[0],ecx
0x6374f5: pop ecx
0x6374f6: pop edi
0x6374f7: pop esi
0x6374f8: pop ebx
0x6374f9: mov ecx,[esp+88h]
0x637500: xor ecx,esp
0x637502: call 00652739h
0x637507: mov esp,ebp
0x637509: pop ebp
0x63750a: ret
````

`sub_637190` is called by sub_636c90. It works with the text "\user.bin". It delegates to sub_4608f0, sub_460950, sub_4a4ea0 (5 callees).

### sub_638d10 at 0x638d10 (81 instructions)

````text
0x638d10: push 0FFFFFFFFh
0x638d12: push 7431C8h
0x638d17: mov eax,fs:[0]
0x638d1d: push eax
0x638d1e: sub esp,20h
0x638d21: push ebx
0x638d22: push ebp
0x638d23: push esi
0x638d24: push edi
0x638d25: mov eax,ds:[858220h]
0x638d2a: xor eax,esp
0x638d2c: push eax
0x638d2d: lea eax,[esp+34h]
0x638d31: mov fs:[0],eax
0x638d37: mov esi,[esp+44h]
0x638d3b: call 0063A4A0h
0x638d40: mov [esi+4],eax
0x638d43: mov byte ptr [eax+29h],1
0x638d47: mov eax,[esi+4]
0x638d4a: mov [eax+4],eax
0x638d4d: mov eax,[esi+4]
0x638d50: mov [eax],eax
0x638d52: mov eax,[esi+4]
0x638d55: xor ebx,ebx
0x638d57: mov [eax+8],eax
0x638d5a: mov [esi+8],ebx
0x638d5d: mov [esp+3Ch],ebx
0x638d61: lea ecx,[esp+18h]
0x638d65: mov eax,esi
0x638d67: mov edi,808000h
0x638d6c: lea ebp,[ebx+1]
0x638d6f: mov [esp+18h],ebx
0x638d73: call 00639B20h
0x638d78: mov [eax],ebx
0x638d7a: mov [eax+4],edi
0x638d7d: mov [eax+8],ebp
0x638d80: mov ecx,12h
0x638d85: mov [eax+0Ch],ecx
0x638d88: xor ecx,ecx
0x638d8a: mov [eax+10h],ecx
0x638d8d: mov [eax+14h],ecx
0x638d90: lea ecx,[esp+18h]
0x638d94: mov eax,esi
0x638d96: mov edi,0FFFFh
0x638d9b: lea ebp,[ebx+2]
0x638d9e: mov dword ptr [esp+18h],1Ah
0x638da6: call 00639B20h
0x638dab: mov [eax],ebx
0x638dad: mov [eax+4],edi
0x638db0: mov [eax+8],ebp
0x638db3: mov ecx,10h
0x638db8: mov [eax+0Ch],ecx
0x638dbb: xor ecx,ecx
0x638dbd: mov [eax+10h],ecx
0x638dc0: mov [eax+14h],ecx
0x638dc3: mov [esp+30h],ecx
0x638dc7: mov ebx,1
0x638dcc: lea ecx,[esp+18h]
0x638dd0: mov eax,esi
0x638dd2: mov ebp,ebx
0x638dd4: mov dword ptr [esp+18h],1Ch
0x638ddc: call 00639B20h
0x638de1: mov [eax],ebx
0x638de3: mov [eax+4],edi
0x638de6: mov [eax+8],ebp
0x638de9: mov ecx,10h
0x638dee: mov [eax+0Ch],ecx
0x638df1: xor ecx,ecx
0x638df3: mov [eax+10h],ecx
0x638df6: mov ecx,[esp+30h]
0x638dfa: mov [eax+14h],ecx
0x638dfd: mov eax,esi
0x638dff: mov ecx,[esp+34h]
0x638e03: mov fs:[0],ecx
0x638e0a: pop ecx
0x638e0b: pop edi
0x638e0c: pop esi
0x638e0d: pop ebp
0x638e0e: pop ebx
0x638e0f: add esp,2Ch
0x638e12: ret 4
````

`sub_638d10` is called by sub_610980. It delegates to sub_639b20, sub_63a4a0 (2 callees).

### sub_639b20 at 0x639b20 (61 instructions)

````text
0x639b20: push ebp
0x639b21: mov ebp,esp
0x639b23: and esp,0FFFFFFF8h
0x639b26: mov edx,[eax+4]
0x639b29: sub esp,24h
0x639b2c: push ebx
0x639b2d: mov ebx,ecx
0x639b2f: mov ecx,[edx+4]
0x639b32: cmp byte ptr [ecx+29h],0
0x639b36: push esi
0x639b37: push edi
0x639b38: jne short 00639B54h
0x639b3a: mov esi,[ebx]
0x639b3c: lea esp,[esp]
0x639b40: cmp [ecx+0Ch],esi
0x639b43: jge short 00639B4Ah
0x639b45: mov ecx,[ecx+8]
0x639b48: jmp short 00639B4Eh
0x639b4a: mov edx,ecx
0x639b4c: mov ecx,[ecx]
0x639b4e: cmp byte ptr [ecx+29h],0
0x639b52: je short 00639B40h
0x639b54: cmp edx,[eax+4]
0x639b57: mov edi,edx
0x639b59: mov esi,eax
0x639b5b: je short 00639B64h
0x639b5d: mov ecx,[ebx]
0x639b5f: cmp ecx,[edx+0Ch]
0x639b62: jge short 00639B9Ah
0x639b64: mov edx,[ebx]
0x639b66: xor ecx,ecx
0x639b68: push edi
0x639b69: mov [esp+1Ch],ecx
0x639b6d: mov [esp+20h],ecx
0x639b71: mov [esp+24h],ecx
0x639b75: mov [esp+28h],ecx
0x639b79: mov [esp+2Ch],ecx
0x639b7d: mov [esp+30h],ecx
0x639b81: push esi
0x639b82: lea ecx,[esp+1Ch]
0x639b86: mov [esp+1Ch],edx
0x639b8a: push ecx
0x639b8b: lea edx,[esp+18h]
0x639b8f: push edx
0x639b90: call 00639C30h
0x639b95: mov esi,[eax]
0x639b97: mov edi,[eax+4]
0x639b9a: test esi,esi
0x639b9c: mov ebx,ds:[77D0E4h]
0x639ba2: jne short 00639BA6h
0x639ba4: call ebx
0x639ba6: cmp edi,[esi+4]
0x639ba9: jne short 00639BADh
0x639bab: call ebx
0x639bad: lea eax,[edi+10h]
0x639bb0: pop edi
0x639bb1: pop esi
0x639bb2: pop ebx
0x639bb3: mov esp,ebp
0x639bb5: pop ebp
0x639bb6: ret
````

`sub_639b20` is called by sub_638d10. It delegates to sub_639c30 (1 callees).

### sub_639c30 at 0x639c30 (174 instructions)

````text
0x639c30: sub esp,1Ch
0x639c33: push ebx
0x639c34: push ebp
0x639c35: mov ebp,[esp+28h]
0x639c39: mov ebx,eax
0x639c3b: cmp dword ptr [ebx+8],0
0x639c3f: mov ecx,[ebx+4]
0x639c42: push esi
0x639c43: push edi
0x639c44: jne short 00639C61h
0x639c46: mov eax,[esp+34h]
0x639c4a: push eax
0x639c4b: push 1
0x639c4d: push ebp
0x639c4e: mov edi,ebx
0x639c50: call 00639FF0h
0x639c55: mov eax,ebp
0x639c57: pop edi
0x639c58: pop esi
0x639c59: pop ebp
0x639c5a: pop ebx
0x639c5b: add esp,1Ch
0x639c5e: ret 10h
0x639c61: mov edi,[esp+38h]
0x639c65: test edi,edi
0x639c67: mov edx,[ecx]
0x639c69: mov [esp+20h],edx
0x639c6d: je short 00639C73h
0x639c6f: cmp edi,ebx
0x639c71: je short 00639C79h
0x639c73: call dword ptr ds:[77D0E4h]
0x639c79: mov esi,[esp+3Ch]
0x639c7d: cmp esi,[esp+20h]
0x639c81: jne short 00639CABh
0x639c83: mov eax,[esp+34h]
0x639c87: mov ecx,[eax]
0x639c89: cmp ecx,[esi+0Ch]
0x639c8c: jge near ptr 00639DCFh
0x639c92: push eax
0x639c93: push 1
0x639c95: push ebp
0x639c96: mov ecx,esi
0x639c98: mov edi,ebx
0x639c9a: call 00639FF0h
0x639c9f: mov eax,ebp
0x639ca1: pop edi
0x639ca2: pop esi
0x639ca3: pop ebp
0x639ca4: pop ebx
0x639ca5: add esp,1Ch
0x639ca8: ret 10h
0x639cab: test edi,edi
0x639cad: mov edx,[ebx+4]
0x639cb0: mov [esp+20h],edx
0x639cb4: je short 00639CBAh
0x639cb6: cmp edi,ebx
0x639cb8: je short 00639CC0h
0x639cba: call dword ptr ds:[77D0E4h]
0x639cc0: cmp esi,[esp+20h]
0x639cc4: jne short 00639CF4h
0x639cc6: mov eax,[ebx+4]
0x639cc9: mov ecx,[eax+8]
0x639ccc: mov edx,[ecx+0Ch]
0x639ccf: mov eax,[esp+34h]
0x639cd3: cmp edx,[eax]
0x639cd5: jge near ptr 00639DCBh
0x639cdb: mov edx,eax
0x639cdd: push edx
0x639cde: push 0
0x639ce0: push ebp
0x639ce1: mov edi,ebx
0x639ce3: call 00639FF0h
0x639ce8: mov eax,ebp
0x639cea: pop edi
0x639ceb: pop esi
0x639cec: pop ebp
0x639ced: pop ebx
0x639cee: add esp,1Ch
0x639cf1: ret 10h
0x639cf4: mov eax,[esp+34h]
0x639cf8: mov eax,[eax]
0x639cfa: cmp [esi+0Ch],eax
0x639cfd: jle short 00639D4Ah
0x639cff: mov [esp+18h],esi
0x639d03: lea esi,[esp+14h]
0x639d07: mov [esp+14h],edi
0x639d0b: call 004C6520h
0x639d10: mov edx,[esp+34h]
0x639d14: mov eax,[edx]
0x639d16: mov ecx,[esp+18h]
0x639d1a: cmp [ecx+0Ch],eax
0x639d1d: jge short 00639D43h
0x639d1f: mov eax,[ecx+8]
0x639d22: cmp byte ptr [eax+29h],0
0x639d26: push edx
0x639d27: mov edi,ebx
0x639d29: jne short 00639D9Ch
0x639d2b: mov ecx,[esp+40h]
0x639d2f: push 1
0x639d31: push ebp
0x639d32: call 00639FF0h
0x639d37: mov eax,ebp
0x639d39: pop edi
0x639d3a: pop esi
0x639d3b: pop ebp
0x639d3c: pop ebx
0x639d3d: add esp,1Ch
0x639d40: ret 10h
0x639d43: mov esi,[esp+3Ch]
0x639d47: cmp [esi+0Ch],eax
0x639d4a: jge short 00639DCBh
0x639d4c: mov ecx,[ebx+4]
0x639d4f: mov [esp+18h],esi
0x639d53: lea esi,[esp+14h]
0x639d57: mov [esp+14h],edi
0x639d5b: mov [esp+20h],ecx
0x639d5f: mov [esp+1Ch],ebx
0x639d63: call 004B6660h
0x639d68: lea esi,[esp+1Ch]
0x639d6c: lea edi,[esp+14h]
0x639d70: call 005E56D0h
0x639d75: test al,al
0x639d77: mov eax,[esp+18h]
0x639d7b: jne short 00639D88h
0x639d7d: mov edx,[esp+34h]
0x639d81: mov ecx,[edx]
0x639d83: cmp ecx,[eax+0Ch]
0x639d86: jge short 00639DCBh
0x639d88: mov ecx,[esp+3Ch]
0x639d8c: mov edx,[ecx+8]
0x639d8f: cmp byte ptr [edx+29h],0
0x639d93: mov edi,ebx
0x639d95: je short 00639DB0h
0x639d97: mov eax,[esp+34h]
0x639d9b: push eax
0x639d9c: push 0
0x639d9e: push ebp
0x639d9f: call 00639FF0h
0x639da4: mov eax,ebp
0x639da6: pop edi
0x639da7: pop esi
0x639da8: pop ebp
0x639da9: pop ebx
0x639daa: add esp,1Ch
0x639dad: ret 10h
0x639db0: mov ecx,[esp+34h]
0x639db4: push ecx
0x639db5: push 1
0x639db7: push ebp
0x639db8: mov ecx,eax
0x639dba: call 00639FF0h
0x639dbf: mov eax,ebp
0x639dc1: pop edi
0x639dc2: pop esi
0x639dc3: pop ebp
0x639dc4: pop ebx
0x639dc5: add esp,1Ch
0x639dc8: ret 10h
0x639dcb: mov eax,[esp+34h]
0x639dcf: push eax
0x639dd0: lea edx,[esp+20h]
0x639dd4: push edx
0x639dd5: call 00639E40h
0x639dda: mov ecx,[eax]
0x639ddc: pop edi
0x639ddd: mov [ebp],ecx
0x639de0: mov edx,[eax+4]
0x639de3: pop esi
0x639de4: mov [ebp+4],edx
0x639de7: mov eax,ebp
0x639de9: pop ebp
0x639dea: pop ebx
0x639deb: add esp,1Ch
0x639dee: ret 10h
````

`sub_639c30` is called by sub_639b20. It delegates to sub_4b6660, sub_4c6520, sub_5e56d0 (5 callees).

### sub_639e00 at 0x639e00 (26 instructions)

````text
0x639e00: push ebp
0x639e01: mov ebp,esp
0x639e03: and esp,0FFFFFFF8h
0x639e06: sub esp,0Ch
0x639e09: push edi
0x639e0a: mov edi,eax
0x639e0c: mov eax,[edi+4]
0x639e0f: mov ecx,[eax]
0x639e11: push eax
0x639e12: push edi
0x639e13: push ecx
0x639e14: push edi
0x639e15: lea eax,[esp+18h]
0x639e19: push eax
0x639e1a: call 00639F20h
0x639e1f: mov ecx,[edi+4]
0x639e22: push ecx
0x639e23: call 006516BAh
0x639e28: add esp,4
0x639e2b: xor eax,eax
0x639e2d: mov [edi+4],eax
0x639e30: mov [edi+8],eax
0x639e33: pop edi
0x639e34: mov esp,ebp
0x639e36: pop ebp
0x639e37: ret
````

`sub_639e00` is called by sub_610c30. It delegates to sub_639f20, j_ORDINAL 764 (2 callees).

### sub_639e40 at 0x639e40 (86 instructions)

````text
0x639e40: sub esp,10h
0x639e43: push ebp
0x639e44: mov ebp,[esp+18h]
0x639e48: push esi
0x639e49: mov esi,[esp+20h]
0x639e4d: push edi
0x639e4e: mov edi,[ebx+4]
0x639e51: mov eax,[edi+4]
0x639e54: cmp byte ptr [eax+29h],0
0x639e58: mov cl,1
0x639e5a: mov [esp+20h],cl
0x639e5e: jne short 00639E7Fh
0x639e60: mov edx,[esi]
0x639e62: cmp edx,[eax+0Ch]
0x639e65: mov edi,eax
0x639e67: setl cl
0x639e6a: test cl,cl
0x639e6c: mov [esp+20h],cl
0x639e70: je short 00639E76h
0x639e72: mov eax,[eax]
0x639e74: jmp short 00639E79h
0x639e76: mov eax,[eax+8]
0x639e79: cmp byte ptr [eax+29h],0
0x639e7d: je short 00639E62h
0x639e7f: test cl,cl
0x639e81: mov eax,edi
0x639e83: mov [esp+14h],eax
0x639e87: mov [esp+10h],ebx
0x639e8b: je short 00639ED0h
0x639e8d: mov eax,[ebx+4]
0x639e90: cmp edi,[eax]
0x639e92: jne short 00639EBFh
0x639e94: push esi
0x639e95: push 1
0x639e97: lea ecx,[esp+18h]
0x639e9b: push ecx
0x639e9c: mov ecx,edi
0x639e9e: mov edi,ebx
0x639ea0: call 00639FF0h
0x639ea5: mov edx,[eax]
0x639ea7: mov eax,[eax+4]
0x639eaa: mov [ebp+4],eax
0x639ead: mov [ebp],edx
0x639eb0: mov byte ptr [ebp+8],1
0x639eb4: mov eax,ebp
0x639eb6: pop edi
0x639eb7: pop esi
0x639eb8: pop ebp
0x639eb9: add esp,10h
0x639ebc: ret 8
0x639ebf: lea esi,[esp+10h]
0x639ec3: call 004C6520h
0x639ec8: mov eax,[esp+14h]
0x639ecc: mov esi,[esp+24h]
0x639ed0: mov ecx,[eax+0Ch]
0x639ed3: cmp ecx,[esi]
0x639ed5: jge short 00639F05h
0x639ed7: mov edx,[esp+20h]
0x639edb: push esi
0x639edc: push edx
0x639edd: lea eax,[esp+18h]
0x639ee1: mov ecx,edi
0x639ee3: push eax
0x639ee4: mov edi,ebx
0x639ee6: call 00639FF0h
0x639eeb: mov ecx,[eax]
0x639eed: mov edx,[eax+4]
0x639ef0: mov [ebp],ecx
0x639ef3: mov [ebp+4],edx
0x639ef6: mov byte ptr [ebp+8],1
0x639efa: mov eax,ebp
0x639efc: pop edi
0x639efd: pop esi
0x639efe: pop ebp
0x639eff: add esp,10h
0x639f02: ret 8
0x639f05: mov ecx,[esp+10h]
0x639f09: pop edi
0x639f0a: mov [ebp+4],eax
0x639f0d: pop esi
0x639f0e: mov [ebp],ecx
0x639f11: mov byte ptr [ebp+8],0
0x639f15: mov eax,ebp
0x639f17: pop ebp
0x639f18: add esp,10h
0x639f1b: ret 8
````

`sub_639e40` is called by sub_639c30. It delegates to sub_4c6520, sub_639ff0 (2 callees).

### sub_639f20 at 0x639f20 (72 instructions)

````text
0x639f20: mov eax,[edi+4]
0x639f23: sub esp,0Ch
0x639f26: push ebx
0x639f27: mov ebx,[esp+18h]
0x639f2b: test ebx,ebx
0x639f2d: push ebp
0x639f2e: push esi
0x639f2f: mov esi,[eax]
0x639f31: je short 00639F37h
0x639f33: cmp ebx,edi
0x639f35: je short 00639F3Dh
0x639f37: call dword ptr ds:[77D0E4h]
0x639f3d: mov ebp,[esp+24h]
0x639f41: cmp ebp,esi
0x639f43: jne short 00639FA0h
0x639f45: mov eax,[esp+28h]
0x639f49: test eax,eax
0x639f4b: mov esi,[edi+4]
0x639f4e: je short 00639F54h
0x639f50: cmp eax,edi
0x639f52: je short 00639F5Ah
0x639f54: call dword ptr ds:[77D0E4h]
0x639f5a: cmp [esp+2Ch],esi
0x639f5e: jne short 00639FA0h
0x639f60: mov ecx,[edi+4]
0x639f63: mov edx,[ecx+4]
0x639f66: push edx
0x639f67: mov ecx,edi
0x639f69: call 0063A520h
0x639f6e: mov eax,[edi+4]
0x639f71: mov [eax+4],eax
0x639f74: mov eax,[edi+4]
0x639f77: mov dword ptr [edi+8],0
0x639f7e: mov [eax],eax
0x639f80: mov eax,[edi+4]
0x639f83: mov [eax+8],eax
0x639f86: mov eax,[edi+4]
0x639f89: mov ecx,[eax]
0x639f8b: mov eax,[esp+1Ch]
0x639f8f: mov [eax+4],ecx
0x639f92: mov [eax],edi
0x639f94: pop esi
0x639f95: pop ebp
0x639f96: pop ebx
0x639f97: add esp,0Ch
0x639f9a: ret 14h
0x639fa0: test ebx,ebx
0x639fa2: je short 00639FAAh
0x639fa4: cmp ebx,[esp+28h]
0x639fa8: je short 00639FB0h
0x639faa: call dword ptr ds:[77D0E4h]
0x639fb0: cmp ebp,[esp+2Ch]
0x639fb4: je short 00639FD6h
0x639fb6: lea esi,[esp+20h]
0x639fba: call 004B6660h
0x639fbf: push ebp
0x639fc0: push ebx
0x639fc1: lea edx,[esp+18h]
0x639fc5: push edx
0x639fc6: push edi
0x639fc7: call 0063A1A0h
0x639fcc: mov ebp,[esp+24h]
0x639fd0: mov ebx,[esp+20h]
0x639fd4: jmp short 00639FA0h
0x639fd6: mov eax,[esp+1Ch]
0x639fda: pop esi
0x639fdb: mov [eax+4],ebp
0x639fde: pop ebp
0x639fdf: mov [eax],ebx
0x639fe1: pop ebx
0x639fe2: add esp,0Ch
0x639fe5: ret 14h
````

`sub_639f20` is called by sub_639e00. It delegates to sub_4b6660, sub_63a1a0, sub_63a520 (3 callees).

### sub_639ff0 at 0x639ff0 (139 instructions)

````text
0x639ff0: push 0FFFFFFFFh
0x639ff2: push 740349h
0x639ff7: mov eax,fs:[0]
0x639ffd: push eax
0x639ffe: sub esp,4Ch
0x63a001: push ebx
0x63a002: push ebp
0x63a003: push esi
0x63a004: mov eax,ds:[858220h]
0x63a009: xor eax,esp
0x63a00b: push eax
0x63a00c: lea eax,[esp+5Ch]
0x63a010: mov fs:[0],eax
0x63a016: mov esi,ecx
0x63a018: cmp dword ptr [edi+8],9249248h
0x63a01f: jb short 0063A05Dh
0x63a021: push 7C5AD8h
0x63a026: lea ecx,[esp+18h]
0x63a02a: call dword ptr ds:[77CD7Ch]
0x63a030: lea eax,[esp+14h]
0x63a034: push eax
0x63a035: lea ecx,[esp+34h]
0x63a039: mov dword ptr [esp+68h],0
0x63a041: call 00401230h
0x63a046: push 80A274h
0x63a04b: lea ecx,[esp+34h]
0x63a04f: push ecx
0x63a050: mov dword ptr [esp+38h],78FFECh
0x63a058: call 00652AC4h
0x63a05d: mov edx,[esp+74h]
0x63a061: mov eax,[edi+4]
0x63a064: push edx
0x63a065: push eax
0x63a066: push esi
0x63a067: push eax
0x63a068: call 0063A4E0h
0x63a06d: mov ebp,eax
0x63a06f: mov eax,[edi+4]
0x63a072: mov ebx,1
0x63a077: add [edi+8],ebx
0x63a07a: cmp esi,eax
0x63a07c: jne short 0063A08Eh
0x63a07e: mov [eax+4],ebp
0x63a081: mov eax,[edi+4]
0x63a084: mov [eax],ebp
0x63a086: mov ecx,[edi+4]
0x63a089: mov [ecx+8],ebp
0x63a08c: jmp short 0063A0B0h
0x63a08e: cmp byte ptr [esp+70h],0
0x63a093: je short 0063A0A2h
0x63a095: mov [esi],ebp
0x63a097: mov eax,[edi+4]
0x63a09a: cmp esi,[eax]
0x63a09c: jne short 0063A0B0h
0x63a09e: mov [eax],ebp
0x63a0a0: jmp short 0063A0B0h
0x63a0a2: mov [esi+8],ebp
0x63a0a5: mov eax,[edi+4]
0x63a0a8: cmp esi,[eax+8]
0x63a0ab: jne short 0063A0B0h
0x63a0ad: mov [eax+8],ebp
0x63a0b0: mov edx,[ebp+4]
0x63a0b3: cmp byte ptr [edx+28h],0
0x63a0b7: lea eax,[ebp+4]
0x63a0ba: mov esi,ebp
0x63a0bc: jne near ptr 0063A16Bh
0x63a0c2: mov ecx,[eax]
0x63a0c4: mov edx,[ecx+4]
0x63a0c7: cmp ecx,[edx]
0x63a0c9: jne short 0063A115h
0x63a0cb: mov edx,[edx+8]
0x63a0ce: cmp byte ptr [edx+28h],0
0x63a0d2: jne short 0063A0EAh
0x63a0d4: mov [ecx+28h],bl
0x63a0d7: mov [edx+28h],bl
0x63a0da: mov edx,[eax]
0x63a0dc: mov ecx,[edx+4]
0x63a0df: mov byte ptr [ecx+28h],0
0x63a0e3: mov edx,[eax]
0x63a0e5: mov esi,[edx+4]
0x63a0e8: jmp short 0063A15Bh
0x63a0ea: cmp esi,[ecx+8]
0x63a0ed: jne short 0063A0F7h
0x63a0ef: push edi
0x63a0f0: mov esi,ecx
0x63a0f2: call 0063A450h
0x63a0f7: mov eax,[esi+4]
0x63a0fa: mov [eax+28h],bl
0x63a0fd: mov ecx,[esi+4]
0x63a100: mov edx,[ecx+4]
0x63a103: mov byte ptr [edx+28h],0
0x63a107: mov eax,[esi+4]
0x63a10a: mov ecx,[eax+4]
0x63a10d: push edi
0x63a10e: call 004B6360h
0x63a113: jmp short 0063A15Bh
0x63a115: mov edx,[edx]
0x63a117: cmp byte ptr [edx+28h],0
0x63a11b: jne short 0063A133h
0x63a11d: mov [ecx+28h],bl
0x63a120: mov [edx+28h],bl
0x63a123: mov edx,[eax]
0x63a125: mov ecx,[edx+4]
0x63a128: mov byte ptr [ecx+28h],0
0x63a12c: mov edx,[eax]
0x63a12e: mov esi,[edx+4]
0x63a131: jmp short 0063A15Bh
0x63a133: cmp esi,[ecx]
0x63a135: jne short 0063A13Fh
0x63a137: push edi
0x63a138: mov esi,ecx
0x63a13a: call 004B6360h
0x63a13f: mov eax,[esi+4]
0x63a142: mov [eax+28h],bl
0x63a145: mov ecx,[esi+4]
0x63a148: mov edx,[ecx+4]
0x63a14b: mov byte ptr [edx+28h],0
0x63a14f: mov eax,[esi+4]
0x63a152: mov ecx,[eax+4]
0x63a155: push edi
0x63a156: call 0063A450h
0x63a15b: mov ecx,[esi+4]
0x63a15e: cmp byte ptr [ecx+28h],0
0x63a162: lea eax,[esi+4]
0x63a165: je near ptr 0063A0C2h
0x63a16b: mov edx,[edi+4]
0x63a16e: mov eax,[edx+4]
0x63a171: mov [eax+28h],bl
0x63a174: mov eax,[esp+6Ch]
0x63a178: mov [eax+4],ebp
0x63a17b: mov [eax],edi
0x63a17d: mov ecx,[esp+5Ch]
0x63a181: mov fs:[0],ecx
0x63a188: pop ecx
0x63a189: pop esi
0x63a18a: pop ebp
0x63a18b: pop ebx
0x63a18c: add esp,58h
0x63a18f: ret 0Ch
````

`sub_639ff0` is called by sub_639c30, sub_639e40. It delegates to sub_401230, sub_4b6360, sub_63a450 (5 callees).

### sub_63a1a0 at 0x63a1a0 (236 instructions)

````text
0x63a1a0: push 0FFFFFFFFh
0x63a1a2: push 7410D9h
0x63a1a7: mov eax,fs:[0]
0x63a1ad: push eax
0x63a1ae: sub esp,44h
0x63a1b1: push ebx
0x63a1b2: push ebp
0x63a1b3: push esi
0x63a1b4: push edi
0x63a1b5: mov eax,ds:[858220h]
0x63a1ba: xor eax,esp
0x63a1bc: push eax
0x63a1bd: lea eax,[esp+58h]
0x63a1c1: mov fs:[0],eax
0x63a1c7: mov ebp,[esp+68h]
0x63a1cb: mov eax,[esp+74h]
0x63a1cf: cmp byte ptr [eax+29h],0
0x63a1d3: je short 0063A211h
0x63a1d5: push 7C5AECh
0x63a1da: lea ecx,[esp+18h]
0x63a1de: call dword ptr ds:[77CD7Ch]
0x63a1e4: lea eax,[esp+14h]
0x63a1e8: push eax
0x63a1e9: lea ecx,[esp+34h]
0x63a1ed: mov dword ptr [esp+64h],0
0x63a1f5: call 00401230h
0x63a1fa: push 80A4F8h
0x63a1ff: lea ecx,[esp+34h]
0x63a203: push ecx
0x63a204: mov dword ptr [esp+38h],790F90h
0x63a20c: call 00652AC4h
0x63a211: mov ebx,eax
0x63a213: lea esi,[esp+70h]
0x63a217: mov [esp+68h],ebx
0x63a21b: call 004B6660h
0x63a220: mov eax,[ebx]
0x63a222: cmp byte ptr [eax+29h],0
0x63a226: je short 0063A22Dh
0x63a228: mov edi,[ebx+8]
0x63a22b: jmp short 0063A245h
0x63a22d: mov edx,[ebx+8]
0x63a230: cmp byte ptr [edx+29h],0
0x63a234: je short 0063A23Ah
0x63a236: mov edi,eax
0x63a238: jmp short 0063A245h
0x63a23a: mov ecx,[esp+74h]
0x63a23e: cmp ecx,ebx
0x63a240: mov edi,[ecx+8]
0x63a243: jne short 0063A2B5h
0x63a245: cmp byte ptr [edi+29h],0
0x63a249: mov esi,[ebx+4]
0x63a24c: jne short 0063A251h
0x63a24e: mov [edi+4],esi
0x63a251: mov eax,[ebp+4]
0x63a254: cmp [eax+4],ebx
0x63a257: jne short 0063A25Eh
0x63a259: mov [eax+4],edi
0x63a25c: jmp short 0063A269h
0x63a25e: cmp [esi],ebx
0x63a260: jne short 0063A266h
0x63a262: mov [esi],edi
0x63a264: jmp short 0063A269h
0x63a266: mov [esi+8],edi
0x63a269: mov edx,[ebp+4]
0x63a26c: cmp [edx],ebx
0x63a26e: jne short 0063A290h
0x63a270: cmp byte ptr [edi+29h],0
0x63a274: je short 0063A27Ah
0x63a276: mov ecx,esi
0x63a278: jmp short 0063A28Eh
0x63a27a: mov eax,[edi]
0x63a27c: cmp byte ptr [eax+29h],0
0x63a280: mov ecx,edi
0x63a282: jne short 0063A28Eh
0x63a284: mov ecx,eax
0x63a286: mov eax,[ecx]
0x63a288: cmp byte ptr [eax+29h],0
0x63a28c: je short 0063A284h
0x63a28e: mov [edx],ecx
0x63a290: mov ebx,[ebp+4]
0x63a293: mov eax,[esp+68h]
0x63a297: cmp [ebx+8],eax
0x63a29a: jne short 0063A30Ch
0x63a29c: cmp byte ptr [edi+29h],0
0x63a2a0: je short 0063A2A9h
0x63a2a2: mov eax,esi
0x63a2a4: mov [ebx+8],eax
0x63a2a7: jmp short 0063A30Ch
0x63a2a9: mov eax,edi
0x63a2ab: call 004B6340h
0x63a2b0: mov [ebx+8],eax
0x63a2b3: jmp short 0063A30Ch
0x63a2b5: mov [eax+4],ecx
0x63a2b8: mov edx,[ebx]
0x63a2ba: mov [ecx],edx
0x63a2bc: cmp ecx,[ebx+8]
0x63a2bf: jne short 0063A2C5h
0x63a2c1: mov esi,ecx
0x63a2c3: jmp short 0063A2DFh
0x63a2c5: cmp byte ptr [edi+29h],0
0x63a2c9: mov esi,[ecx+4]
0x63a2cc: jne short 0063A2D1h
0x63a2ce: mov [edi+4],esi
0x63a2d1: mov [esi],edi
0x63a2d3: mov eax,[ebx+8]
0x63a2d6: mov [ecx+8],eax
0x63a2d9: mov edx,[ebx+8]
0x63a2dc: mov [edx+4],ecx
0x63a2df: mov eax,[ebp+4]
0x63a2e2: cmp [eax+4],ebx
0x63a2e5: jne short 0063A2ECh
0x63a2e7: mov [eax+4],ecx
0x63a2ea: jmp short 0063A2FAh
0x63a2ec: mov eax,[ebx+4]
0x63a2ef: cmp [eax],ebx
0x63a2f1: jne short 0063A2F7h
0x63a2f3: mov [eax],ecx
0x63a2f5: jmp short 0063A2FAh
0x63a2f7: mov [eax+8],ecx
0x63a2fa: mov eax,[ebx+4]
0x63a2fd: mov [ecx+4],eax
0x63a300: mov dl,[ebx+28h]
0x63a303: mov al,[ecx+28h]
0x63a306: mov [ecx+28h],dl
0x63a309: mov [ebx+28h],al
0x63a30c: mov eax,[esp+68h]
0x63a310: mov bl,1
0x63a312: cmp [eax+28h],bl
0x63a315: jne near ptr 0063A40Eh
0x63a31b: mov ecx,[ebp+4]
0x63a31e: cmp edi,[ecx+4]
0x63a321: je near ptr 0063A40Bh
0x63a327: cmp [edi+28h],bl
0x63a32a: jne near ptr 0063A40Bh
0x63a330: mov ecx,[esi]
0x63a332: cmp edi,ecx
0x63a334: jne short 0063A399h
0x63a336: mov ecx,[esi+8]
0x63a339: cmp byte ptr [ecx+28h],0
0x63a33d: jne short 0063A351h
0x63a33f: mov [ecx+28h],bl
0x63a342: push ebp
0x63a343: mov ecx,esi
0x63a345: mov byte ptr [esi+28h],0
0x63a349: call 0063A450h
0x63a34e: mov ecx,[esi+8]
0x63a351: cmp byte ptr [ecx+29h],0
0x63a355: jne short 0063A3C9h
0x63a357: mov edx,[ecx]
0x63a359: cmp [edx+28h],bl
0x63a35c: jne short 0063A366h
0x63a35e: mov eax,[ecx+8]
0x63a361: cmp [eax+28h],bl
0x63a364: je short 0063A3C5h
0x63a366: mov edx,[ecx+8]
0x63a369: cmp [edx+28h],bl
0x63a36c: jne short 0063A380h
0x63a36e: mov eax,[ecx]
0x63a370: mov [eax+28h],bl
0x63a373: push ebp
0x63a374: mov byte ptr [ecx+28h],0
0x63a378: call 004B6360h
0x63a37d: mov ecx,[esi+8]
0x63a380: mov dl,[esi+28h]
0x63a383: mov [ecx+28h],dl
0x63a386: mov [esi+28h],bl
0x63a389: mov eax,[ecx+8]
0x63a38c: push ebp
0x63a38d: mov ecx,esi
0x63a38f: mov [eax+28h],bl
0x63a392: call 0063A450h
0x63a397: jmp short 0063A40Bh
0x63a399: cmp byte ptr [ecx+28h],0
0x63a39d: jne short 0063A3B0h
0x63a39f: mov [ecx+28h],bl
0x63a3a2: push ebp
0x63a3a3: mov ecx,esi
0x63a3a5: mov byte ptr [esi+28h],0
0x63a3a9: call 004B6360h
0x63a3ae: mov ecx,[esi]
0x63a3b0: cmp byte ptr [ecx+29h],0
0x63a3b4: jne short 0063A3C9h
0x63a3b6: mov edx,[ecx+8]
0x63a3b9: cmp [edx+28h],bl
0x63a3bc: jne short 0063A3DCh
0x63a3be: mov eax,[ecx]
0x63a3c0: cmp [eax+28h],bl
0x63a3c3: jne short 0063A3DCh
0x63a3c5: mov byte ptr [ecx+28h],0
0x63a3c9: mov ecx,[ebp+4]
0x63a3cc: mov edi,esi
0x63a3ce: cmp edi,[ecx+4]
0x63a3d1: mov esi,[esi+4]
0x63a3d4: jne near ptr 0063A327h
0x63a3da: jmp short 0063A40Bh
0x63a3dc: mov edx,[ecx]
0x63a3de: cmp [edx+28h],bl
0x63a3e1: jne short 0063A3F5h
0x63a3e3: mov eax,[ecx+8]
0x63a3e6: mov [eax+28h],bl
0x63a3e9: push ebp
0x63a3ea: mov byte ptr [ecx+28h],0
0x63a3ee: call 0063A450h
0x63a3f3: mov ecx,[esi]
0x63a3f5: mov dl,[esi+28h]
0x63a3f8: mov [ecx+28h],dl
0x63a3fb: mov [esi+28h],bl
0x63a3fe: mov eax,[ecx]
0x63a400: push ebp
0x63a401: mov ecx,esi
0x63a403: mov [eax+28h],bl
0x63a406: call 004B6360h
0x63a40b: mov [edi+28h],bl
0x63a40e: mov ecx,[esp+68h]
0x63a412: push ecx
0x63a413: call 006516BAh
0x63a418: mov eax,[ebp+8]
0x63a41b: add esp,4
0x63a41e: test eax,eax
0x63a420: jbe short 0063A428h
0x63a422: add eax,0FFFFFFFFh
0x63a425: mov [ebp+8],eax
0x63a428: mov eax,[esp+6Ch]
0x63a42c: mov edx,[esp+70h]
0x63a430: mov ecx,[esp+74h]
0x63a434: mov [eax],edx
0x63a436: mov [eax+4],ecx
0x63a439: mov ecx,[esp+58h]
0x63a43d: mov fs:[0],ecx
0x63a444: pop ecx
0x63a445: pop edi
0x63a446: pop esi
0x63a447: pop ebp
0x63a448: pop ebx
0x63a449: add esp,50h
0x63a44c: ret 10h
````

`sub_63a1a0` is called by sub_639f20. It delegates to sub_401230, sub_4b6340, sub_4b6360 (7 callees).

### sub_63a450 at 0x63a450 (28 instructions)

````text
0x63a450: mov eax,[ecx+8]
0x63a453: mov edx,[eax]
0x63a455: mov [ecx+8],edx
0x63a458: mov edx,[eax]
0x63a45a: cmp byte ptr [edx+29h],0
0x63a45e: jne short 0063A463h
0x63a460: mov [edx+4],ecx
0x63a463: mov edx,[ecx+4]
0x63a466: mov [eax+4],edx
0x63a469: mov edx,[esp+4]
0x63a46d: mov edx,[edx+4]
0x63a470: cmp ecx,[edx+4]
0x63a473: jne short 0063A480h
0x63a475: mov [edx+4],eax
0x63a478: mov [eax],ecx
0x63a47a: mov [ecx+4],eax
0x63a47d: ret 4
0x63a480: mov edx,[ecx+4]
0x63a483: cmp ecx,[edx]
0x63a485: jne short 0063A491h
0x63a487: mov [edx],eax
0x63a489: mov [eax],ecx
0x63a48b: mov [ecx+4],eax
0x63a48e: ret 4
0x63a491: mov [edx+8],eax
0x63a494: mov [eax],ecx
0x63a496: mov [ecx+4],eax
0x63a499: ret 4
````

`sub_63a450` is called by sub_4b5ab0, sub_639ff0, sub_63a1a0. It calls nothing else.

### sub_63a4a0 at 0x63a4a0 (16 instructions)

````text
0x63a4a0: mov ecx,1
0x63a4a5: call 0063A560h
0x63a4aa: test eax,eax
0x63a4ac: je short 0063A4B4h
0x63a4ae: mov dword ptr [eax],0
0x63a4b4: lea ecx,[eax+4]
0x63a4b7: test ecx,ecx
0x63a4b9: je short 0063A4C1h
0x63a4bb: mov dword ptr [ecx],0
0x63a4c1: lea ecx,[eax+8]
0x63a4c4: test ecx,ecx
0x63a4c6: je short 0063A4CEh
0x63a4c8: mov dword ptr [ecx],0
0x63a4ce: mov byte ptr [eax+28h],1
0x63a4d2: mov byte ptr [eax+29h],0
0x63a4d6: ret
````

`sub_63a4a0` is called by sub_5dfc30, sub_638d10. It delegates to sub_63a560 (1 callees).

### sub_63a4e0 at 0x63a4e0 (22 instructions)

````text
0x63a4e0: mov ecx,1
0x63a4e5: call 0063A560h
0x63a4ea: xor edx,edx
0x63a4ec: cmp eax,edx
0x63a4ee: je short 0063A51Ch
0x63a4f0: mov ecx,[esp+4]
0x63a4f4: mov [eax],ecx
0x63a4f6: mov ecx,[esp+8]
0x63a4fa: push esi
0x63a4fb: mov esi,[esp+14h]
0x63a4ff: mov [eax+4],ecx
0x63a502: mov ecx,[esp+10h]
0x63a506: push edi
0x63a507: mov [eax+8],ecx
0x63a50a: lea edi,[eax+0Ch]
0x63a50d: mov ecx,7
0x63a512: rep movsd
0x63a514: pop edi
0x63a515: mov [eax+28h],dl
0x63a518: mov [eax+29h],dl
0x63a51b: pop esi
0x63a51c: ret 10h
````

`sub_63a4e0` is called by sub_639ff0. It delegates to sub_63a560 (1 callees).

### sub_63a520 at 0x63a520 (23 instructions)

````text
0x63a520: push ebx
0x63a521: push esi
0x63a522: push edi
0x63a523: mov edi,[esp+10h]
0x63a527: cmp byte ptr [edi+29h],0
0x63a52b: mov ebx,ecx
0x63a52d: mov esi,edi
0x63a52f: jne short 0063A54Fh
0x63a531: mov eax,[esi+8]
0x63a534: push eax
0x63a535: mov ecx,ebx
0x63a537: call 0063A520h
0x63a53c: mov esi,[esi]
0x63a53e: push edi
0x63a53f: call 006516BAh
0x63a544: add esp,4
0x63a547: cmp byte ptr [esi+29h],0
0x63a54b: mov edi,esi
0x63a54d: je short 0063A531h
0x63a54f: pop edi
0x63a550: pop esi
0x63a551: pop ebx
0x63a552: ret 4
````

`sub_63a520` is called by sub_639f20, sub_63a520. It delegates to sub_63a520, j_ORDINAL 764 (2 callees).

### sub_63a560 at 0x63a560 (22 instructions)

````text
0x63a560: or eax,0FFFFFFFFh
0x63a563: xor edx,edx
0x63a565: div ecx
0x63a567: sub esp,10h
0x63a56a: cmp eax,2Ch
0x63a56d: jae short 0063A59Ch
0x63a56f: lea eax,[esp]
0x63a572: push eax
0x63a573: lea ecx,[esp+8]
0x63a577: mov dword ptr [esp+4],0
0x63a57f: call dword ptr ds:[77D0DCh]
0x63a585: push 80A2ACh
0x63a58a: lea ecx,[esp+8]
0x63a58e: push ecx
0x63a58f: mov dword ptr [esp+0Ch],78FFD4h
0x63a597: call 00652AC4h
0x63a59c: imul ecx,2Ch
0x63a59f: push ecx
0x63a5a0: call 006516C0h
0x63a5a5: add esp,4
0x63a5a8: add esp,10h
0x63a5ab: ret
````

`sub_63a560` is called by sub_63a4a0, sub_63a4e0. It delegates to j_ORDINAL 762, j__CxxThrowException (2 callees).

### sub_63a5b0 at 0x63a5b0 (33 instructions)

````text
0x63a5b0: push 0FFFFFFFFh
0x63a5b2: push 7479E5h
0x63a5b7: mov eax,fs:[0]
0x63a5bd: push eax
0x63a5be: push esi
0x63a5bf: push edi
0x63a5c0: mov eax,ds:[858220h]
0x63a5c5: xor eax,esp
0x63a5c7: push eax
0x63a5c8: lea eax,[esp+0Ch]
0x63a5cc: mov fs:[0],eax
0x63a5d2: mov esi,[esp+1Ch]
0x63a5d6: mov ecx,esi
0x63a5d8: call dword ptr ds:[77CD80h]
0x63a5de: lea edi,[esi+1Ch]
0x63a5e1: mov ecx,edi
0x63a5e3: mov dword ptr [esp+14h],0
0x63a5eb: call dword ptr ds:[77CD80h]
0x63a5f1: push 7C31C7h
0x63a5f6: mov ecx,esi
0x63a5f8: mov byte ptr [esp+18h],1
0x63a5fd: call dword ptr ds:[77CD50h]
0x63a603: push 7C31C7h
0x63a608: mov ecx,edi
0x63a60a: call dword ptr ds:[77CD50h]
0x63a610: mov eax,esi
0x63a612: mov ecx,[esp+0Ch]
0x63a616: mov fs:[0],ecx
0x63a61d: pop ecx
0x63a61e: pop edi
0x63a61f: pop esi
0x63a620: add esp,0Ch
0x63a623: ret 4
````

`sub_63a5b0` is called by sub_610980. It calls nothing else.

### sub_63cfa0 at 0x63cfa0 (47 instructions)

````text
0x63cfa0: push 0FFFFFFFFh
0x63cfa2: push 74A228h
0x63cfa7: mov eax,fs:[0]
0x63cfad: push eax
0x63cfae: push ecx
0x63cfaf: push ebx
0x63cfb0: mov eax,ds:[858220h]
0x63cfb5: xor eax,esp
0x63cfb7: push eax
0x63cfb8: lea eax,[esp+0Ch]
0x63cfbc: mov fs:[0],eax
0x63cfc2: mov ecx,874D58h
0x63cfc7: mov dword ptr [esp+8],874D54h
0x63cfcf: mov dword ptr ds:[874D54h],7F6D3Ch
0x63cfd9: call dword ptr ds:[77DF80h]
0x63cfdf: xor ebx,ebx
0x63cfe1: mov ds:[874D64h],ebx
0x63cfe7: mov ds:[874D68h],ebx
0x63cfed: mov ds:[874D6Ch],ebx
0x63cff3: mov ds:[874D70h],ebx
0x63cff9: mov dword ptr ds:[874D74h],0F4240h
0x63d003: mov [esp+14h],ebx
0x63d007: push 20h
0x63d009: mov ds:[874D78h],ebx
0x63d00f: call 006516C0h
0x63d014: add esp,4
0x63d017: cmp eax,ebx
0x63d019: je short 0063D048h
0x63d01b: mov [eax+4],ebx
0x63d01e: mov [eax+8],ebx
0x63d021: mov dword ptr [eax+0Ch],1F4h
0x63d028: mov [eax+10h],ebx
0x63d02b: mov [eax+14h],ebx
0x63d02e: mov [eax+18h],bl
0x63d031: mov [eax+19h],bl
0x63d034: mov dword ptr [eax],7F6D44h
0x63d03a: mov dword ptr [eax+1Ch],874D54h
0x63d041: mov ds:[874D78h],eax
0x63d046: jmp short 0063D04Eh
0x63d048: mov ds:[874D78h],ebx
0x63d04e: mov eax,874D54h
0x63d053: mov ecx,[esp+0Ch]
0x63d057: mov fs:[0],ecx
0x63d05e: pop ecx
0x63d05f: pop ebx
0x63d060: add esp,10h
0x63d063: ret
````

`sub_63cfa0` is called by ?get_mutable_instance@?$singleton@VCTaskProc@@@serialization@boost@@SAAAVCTaskProc@@XZ, ?get_instance@?$singleton@VCTaskProc@@@serialization@boost@@CAAAVCTaskProc@@XZ. It delegates to j_ORDINAL 762 (1 callees).

### sub_63d180 at 0x63d180 (26 instructions)

````text
0x63d180: push 0FFFFFFFFh
0x63d182: push 74AF5Ch
0x63d187: mov eax,fs:[0]
0x63d18d: push eax
0x63d18e: push ecx
0x63d18f: push esi
0x63d190: mov eax,ds:[858220h]
0x63d195: xor eax,esp
0x63d197: push eax
0x63d198: lea eax,[esp+0Ch]
0x63d19c: mov fs:[0],eax
0x63d1a2: mov esi,ecx
0x63d1a4: mov [esp+8],esi
0x63d1a8: mov dword ptr [esi],7F6D3Ch
0x63d1ae: lea eax,[esi+0Ch]
0x63d1b1: mov dword ptr [esp+14h],0
0x63d1b9: call 004664C0h
0x63d1be: lea ecx,[esi+4]
0x63d1c1: mov dword ptr [esp+14h],0FFFFFFFFh
0x63d1c9: call dword ptr ds:[77DF7Ch]
0x63d1cf: mov ecx,[esp+0Ch]
0x63d1d3: mov fs:[0],ecx
0x63d1da: pop ecx
0x63d1db: pop esi
0x63d1dc: add esp,10h
0x63d1df: ret
````

`sub_63d180` is called by sub_77b510. It delegates to sub_4664c0 (1 callees).

### ?get_mutable_instance@?$singleton@VCTaskProc@@@serialization@boost@@SAAAVCTaskProc@@XZ at 0x63d2b0 (25 instructions)

````text
0x63d2b0: jmp near ptr 0063D2E0h
0x63d2e0: push 0FFFFFFFFh
0x63d2e2: push 74EF9Eh
0x63d2e7: mov eax,fs:[0]
0x63d2ed: push eax
0x63d2ee: mov eax,ds:[858220h]
0x63d2f3: xor eax,esp
0x63d2f5: push eax
0x63d2f6: lea eax,[esp+4]
0x63d2fa: mov fs:[0],eax
0x63d300: mov eax,1
0x63d305: test ds:[875D48h],al
0x63d30b: jne short 0063D32Dh
0x63d30d: or ds:[875D48h],eax
0x63d313: mov dword ptr [esp+0Ch],0
0x63d31b: call 0063CFA0h
0x63d320: push 77B510h
0x63d325: call 006527EDh
0x63d32a: add esp,4
0x63d32d: mov eax,874D54h
0x63d332: mov ecx,[esp+4]
0x63d336: mov fs:[0],ecx
0x63d33d: pop ecx
0x63d33e: add esp,0Ch
0x63d341: ret
````

`?get_mutable_instance@?$singleton@VCTaskProc@@@serialization@boost@@SAAAVCTaskProc@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_63cfa0, sub_6527ed (2 callees).

### ?get_instance@?$singleton@VCTaskProc@@@serialization@boost@@CAAAVCTaskProc@@XZ at 0x63d2e0 (24 instructions)

````text
0x63d2e0: push 0FFFFFFFFh
0x63d2e2: push 74EF9Eh
0x63d2e7: mov eax,fs:[0]
0x63d2ed: push eax
0x63d2ee: mov eax,ds:[858220h]
0x63d2f3: xor eax,esp
0x63d2f5: push eax
0x63d2f6: lea eax,[esp+4]
0x63d2fa: mov fs:[0],eax
0x63d300: mov eax,1
0x63d305: test ds:[875D48h],al
0x63d30b: jne short 0063D32Dh
0x63d30d: or ds:[875D48h],eax
0x63d313: mov dword ptr [esp+0Ch],0
0x63d31b: call 0063CFA0h
0x63d320: push 77B510h
0x63d325: call 006527EDh
0x63d32a: add esp,4
0x63d32d: mov eax,874D54h
0x63d332: mov ecx,[esp+4]
0x63d336: mov fs:[0],ecx
0x63d33d: pop ecx
0x63d33e: add esp,0Ch
0x63d341: ret
````

`?get_instance@?$singleton@VCTaskProc@@@serialization@boost@@CAAAVCTaskProc@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_63cfa0, sub_6527ed (2 callees).

### sub_63d770 at 0x63d770 (17 instructions)

````text
0x63d770: xor eax,eax
0x63d772: mov ds:[8748FCh],eax
0x63d777: mov ds:[874900h],eax
0x63d77c: mov ds:[874904h],eax
0x63d781: mov ds:[874908h],eax
0x63d786: mov ds:[87490Ch],eax
0x63d78b: mov ds:[874910h],eax
0x63d790: mov ds:[874914h],eax
0x63d795: mov ds:[874918h],eax
0x63d79a: mov ds:[87491Ch],eax
0x63d79f: mov ds:[874920h],eax
0x63d7a4: mov ds:[874924h],eax
0x63d7a9: mov ds:[874928h],eax
0x63d7ae: mov ds:[87492Ch],eax
0x63d7b3: mov ds:[874930h],eax
0x63d7b8: mov eax,8748FCh
0x63d7bd: ret
````

`sub_63d770` is called by ?get_mutable_instance@?$singleton@VChromeBrowser@@@serialization@boost@@SAAAVChromeBrowser@@XZ. It calls nothing else.

### ?get_mutable_instance@?$singleton@VChromeBrowser@@@serialization@boost@@SAAAVChromeBrowser@@XZ at 0x63d7c0 (10 instructions)

````text
0x63d7c0: mov eax,1
0x63d7c5: test ds:[874D50h],al
0x63d7cb: jne short 0063D7E5h
0x63d7cd: or ds:[874D50h],eax
0x63d7d3: call 0063D770h
0x63d7d8: push 77B520h
0x63d7dd: call 006527EDh
0x63d7e2: add esp,4
0x63d7e5: mov eax,8748FCh
0x63d7ea: ret
````

`?get_mutable_instance@?$singleton@VChromeBrowser@@@serialization@boost@@SAAAVChromeBrowser@@XZ` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_63d770, sub_6527ed (2 callees).

### j_ORDINAL 764 at 0x6516ba (1 instructions)

````text
0x6516ba: jmp dword ptr ds:[77C460h]
````

`j_ORDINAL 764` is called by sub_401f60, sub_40d1f0, sub_40e150, sub_40e310, sub_425810, sub_433080, sub_445d90, sub_460950, sub_4655a0, sub_465d70, sub_465fb0, sub_466200, sub_466240, sub_4664c0, sub_466a30, sub_497e50, sub_4a3a30, sub_4a3aa0, sub_4b3ba0, sub_4b3e00, sub_4b3ff0, sub_4b4320, sub_4b4360, sub_4b4b50, sub_4b5020, sub_4b57e0, sub_4b5ab0, sub_4b6300, sub_4cc190, sub_4cf400, sub_4dc5a0, sub_4dd230, sub_4dd6d0, sub_4ddaa0, sub_4ef1a0, sub_5064e0, sub_506590, sub_5069d0, sub_506d20, sub_506ff0, sub_5071d0, sub_573040, sub_573610, sub_575110, sub_584970, sub_584ed0, sub_584f40, sub_585a40, sub_58e330, sub_5af9c0, sub_5afa10, sub_5b0180, sub_5c5180, sub_5c5310, sub_5c5820, sub_5c6b00, sub_5dcbb0, sub_5df910, sub_5dfe00, sub_5e3990, sub_5e3ee0, sub_5e42e0, sub_5e4a20, sub_5e4aa0, sub_5e4b30, sub_5e5020, sub_5e5290, sub_5e5500, sub_5e5540, sub_5e6990, sub_5e6d20, sub_5e6d60, sub_5ea9c0, sub_5ef4e0, sub_5efa60, sub_5efd10, sub_5efd50, sub_5eff00, sub_5f00f0, sub_5f08a0, sub_5f8640, sub_5f88f0, sub_5f8930, sub_5f9360, sub_60ac40, sub_60ac80, sub_60b1c0, sub_60d680, sub_60f240, sub_60f470, sub_60fe40, sub_6102c0, sub_610750, sub_611d90, sub_612890, sub_615070, sub_619ee0, sub_61da40, sub_622660, sub_6229f0, sub_622da0, sub_6245b0, sub_627510, sub_627720, sub_627940, sub_62a0c0, sub_62a960, sub_62aaf0, sub_62bc80, sub_62eb70, sub_62eca0, sub_632570, sub_632650, sub_6328d0, sub_633610, sub_6339e0, sub_633f50, sub_635d40, sub_636c90, sub_639e00, sub_63a1a0, sub_63a520, sub_77b380, sub_77b450. It calls nothing else.

### j_ORDINAL 762 at 0x6516c0 (1 instructions)

````text
0x6516c0: jmp dword ptr ds:[77C45Ch]
````

`j_ORDINAL 762` is called by sub_40d150, sub_40f000, sub_425810, sub_42d470, sub_44c0a0, sub_450370, sub_4608f0, sub_488a40, sub_49a870, sub_4db900, sub_4dc4d0, sub_4fa340, sub_591fd0, sub_5c5b80, sub_5ce370, sub_5d7560, sub_5d9fc0, sub_5ea5d0, sub_5f0f40, sub_602810, sub_607960, sub_6101d0, sub_610210, sub_610650, sub_610690, sub_62b850, sub_634280, sub_63a560, sub_63cfa0. It calls nothing else.

### entry at 0x65272f (135 instructions)

````text
0x652473: push 5Ch
0x652475: push 807608h
0x65247a: call 00652CF8h
0x65247f: xor ebx,ebx
0x652481: mov [ebp-1Ch],ebx
0x652484: mov [ebp-4],ebx
0x652487: lea eax,[ebp-6Ch]
0x65248a: push eax
0x65248b: call dword ptr ds:[77C17Ch]
0x652491: mov dword ptr [ebp-4],0FFFFFFFEh
0x652498: mov dword ptr [ebp-4],1
0x65249f: mov eax,fs:[18h]
0x6524a5: mov esi,[eax+4]
0x6524a8: mov [ebp-20h],ebx
0x6524ab: mov edi,87C670h
0x6524b0: push ebx
0x6524b1: push esi
0x6524b2: push edi
0x6524b3: call dword ptr ds:[77C180h]
0x6524b9: cmp eax,ebx
0x6524bb: je short 006524D6h
0x6524bd: cmp eax,esi
0x6524bf: jne short 006524C9h
0x6524c1: xor esi,esi
0x6524c3: inc esi
0x6524c4: mov [ebp-20h],esi
0x6524c7: jmp short 006524D9h
0x6524c9: push 3E8h
0x6524ce: call dword ptr ds:[77C1F8h]
0x6524d4: jmp short 006524B0h
0x6524d6: xor esi,esi
0x6524d8: inc esi
0x6524d9: mov eax,ds:[87C66Ch]
0x6524de: cmp eax,esi
0x6524e0: jne short 006524ECh
0x6524e2: push 1Fh
0x6524e4: call 00652B54h
0x6524e9: pop ecx
0x6524ea: jmp short 0065251Bh
0x6524ec: mov eax,ds:[87C66Ch]
0x6524f1: test eax,eax
0x6524f3: jne short 00652515h
0x6524f5: mov ds:[87C66Ch],esi
0x6524fb: push 78FB60h
0x652500: push 78FB4Ch
0x652505: call 00652CF2h
0x65250a: pop ecx
0x65250b: pop ecx
0x65250c: test eax,eax
0x65250e: je short 0065251Bh
0x652510: jmp near ptr 0065263Fh
0x652515: mov ds:[86A8A4h],esi
0x65251b: mov eax,ds:[87C66Ch]
0x652520: cmp eax,esi
0x652522: jne short 0065253Fh
0x652524: push 78FB48h
0x652529: push 77DFBCh
0x65252e: call 00652CECh
0x652533: pop ecx
0x652534: pop ecx
0x652535: mov dword ptr ds:[87C66Ch],2
0x65253f: cmp [ebp-20h],ebx
0x652542: jne short 0065254Ch
0x652544: push ebx
0x652545: push edi
0x652546: call dword ptr ds:[77C20Ch]
0x65254c: cmp ds:[87C67Ch],ebx
0x652552: je short 0065256Dh
0x652554: push 87C67Ch
0x652559: call 00652C30h
0x65255e: pop ecx
0x65255f: test eax,eax
0x652561: je short 0065256Dh
0x652563: push ebx
0x652564: push 2
0x652566: push ebx
0x652567: call dword ptr ds:[87C67Ch]
0x65256d: mov eax,ds:[77CEE4h]
0x652572: cmp [eax],ebx
0x652574: je near ptr 0065263Fh
0x65257a: mov eax,[eax]
0x65257c: mov [ebp-24h],eax
0x65257f: movzx ecx,word ptr [eax]
0x652582: cmp cx,20h
0x652586: ja short 006525D7h
0x652588: cmp cx,bx
0x65258b: je short 00652592h
0x65258d: cmp [ebp-1Ch],ebx
0x652590: jne short 006525D7h
0x652592: movzx ecx,word ptr [eax]
0x652595: cmp cx,bx
0x652598: je short 006525A7h
0x65259a: cmp cx,20h
0x65259e: ja short 006525A7h
0x6525a0: inc eax
0x6525a1: inc eax
0x6525a2: mov [ebp-24h],eax
0x6525a5: jmp short 00652592h
0x6525a7: test byte ptr [ebp-40h],1
0x6525ab: je short 006525B3h
0x6525ad: movzx ecx,word ptr [ebp-3Ch]
0x6525b1: jmp short 006525B6h
0x6525b3: push 0Ah
0x6525b5: pop ecx
0x6525b6: push ecx
0x6525b7: push eax
0x6525b8: push ebx
0x6525b9: push 400000h
0x6525be: call 007337BDh
0x6525c3: mov ds:[86A8A0h],eax
0x6525c8: cmp ds:[86A894h],ebx
0x6525ce: jne short 0065261Ch
0x6525d0: push eax
0x6525d1: call dword ptr ds:[77CEE8h]
0x6525d7: cmp cx,22h
0x6525db: jne short 006525E8h
0x6525dd: xor ecx,ecx
0x6525df: cmp [ebp-1Ch],ebx
0x6525e2: sete cl
0x6525e5: mov [ebp-1Ch],ecx
0x6525e8: inc eax
0x6525e9: inc eax
0x6525ea: jmp short 0065257Ch
0x65261c: cmp ds:[86A8A4h],ebx
0x652622: jne short 0065262Ah
0x652624: call dword ptr ds:[77CEF4h]
0x65262a: mov dword ptr [ebp-4],0FFFFFFFEh
0x652631: mov eax,ds:[86A8A0h]
0x652636: jmp short 0065264Bh
0x65263f: mov dword ptr [ebp-4],0FFFFFFFEh
0x652646: mov eax,0FFh
0x65264b: call 00652D3Dh
0x652650: ret
0x65272f: call 00652DA0h
0x652734: jmp near ptr 00652473h
````

`entry` is the reset handler: the first code that runs after boot. It delegates to j__amsg_exit, sub_652c30, j__initterm (8 callees).

### sub_652739 at 0x652739 (57 instructions)

````text
0x652739: cmp ecx,ds:[858220h]
0x65273f: jne short 00652743h
0x652741: rep ret
0x652743: jmp near ptr 00652E34h
0x652e34: push ebp
0x652e35: mov ebp,esp
0x652e37: sub esp,328h
0x652e3d: mov ds:[86A9D0h],eax
0x652e42: mov ds:[86A9CCh],ecx
0x652e48: mov ds:[86A9C8h],edx
0x652e4e: mov ds:[86A9C4h],ebx
0x652e54: mov ds:[86A9C0h],esi
0x652e5a: mov ds:[86A9BCh],edi
0x652e60: mov ds:[86A9E8h],ss
0x652e67: mov ds:[86A9DCh],cs
0x652e6e: mov ds:[86A9B8h],ds
0x652e75: mov ds:[86A9B4h],es
0x652e7c: mov ds:[86A9B0h],fs
0x652e83: mov ds:[86A9ACh],gs
0x652e8a: pushfd
0x652e8b: pop dword ptr ds:[86A9E0h]
0x652e91: mov eax,[ebp]
0x652e94: mov ds:[86A9D4h],eax
0x652e99: mov eax,[ebp+4]
0x652e9c: mov ds:[86A9D8h],eax
0x652ea1: lea eax,[ebp+8]
0x652ea4: mov ds:[86A9E4h],eax
0x652ea9: mov eax,[ebp-320h]
0x652eaf: mov dword ptr ds:[86A920h],10001h
0x652eb9: mov eax,ds:[86A9D8h]
0x652ebe: mov ds:[86A8D4h],eax
0x652ec3: mov dword ptr ds:[86A8C8h],0C0000409h
0x652ecd: mov dword ptr ds:[86A8CCh],1
0x652ed7: mov eax,ds:[858220h]
0x652edc: mov [ebp-328h],eax
0x652ee2: mov eax,ds:[858224h]
0x652ee7: mov [ebp-324h],eax
0x652eed: call dword ptr ds:[77C160h]
0x652ef3: mov ds:[86A918h],eax
0x652ef8: push 1
0x652efa: call 0065306Ah
0x652eff: pop ecx
0x652f00: push 0
0x652f02: call dword ptr ds:[77C178h]
0x652f08: push 790A50h
0x652f0d: call dword ptr ds:[77C164h]
0x652f13: cmp dword ptr ds:[86A918h],0
0x652f1a: jne short 00652F24h
0x652f1c: push 1
0x652f1e: call 0065306Ah
0x652f23: pop ecx
0x652f24: push 0C0000409h
0x652f29: call dword ptr ds:[77C19Ch]
0x652f2f: push eax
0x652f30: call dword ptr ds:[77C168h]
0x652f36: leave
0x652f37: ret
````

`sub_652739` is called by sub_460da0, sub_461120, sub_637190, sub_738d91, sub_738dbc, sub_738ea8, sub_738ef4, sub_738f69, sub_739029, sub_73931c, sub_73973c, sub_739e19, sub_73a3c5, sub_73a498, sub_73a76c, sub_73a809, sub_73aa18, sub_73aa51, sub_73aa81, sub_73b050, sub_73b5a8, sub_73bee9, sub_73c188, sub_73c439, sub_73d713, sub_73db58, sub_73dbd0, sub_73e289, sub_73e2d7, sub_73e344, sub_73e606, sub_73e660, sub_73e709, sub_73e769, sub_73e941, sub_73ec8d, sub_73edf9, sub_73ee74, sub_73f2eb, sub_740349, sub_7410d9, sub_741199, sub_74202c, sub_742061, sub_742088, sub_7421c9, sub_7431c8, sub_743339, sub_743441, sub_74355e, sub_74359e, sub_743714, sub_743788, sub_7437b9, sub_7437f1, sub_743818, sub_7438ce, sub_7445e1, sub_744611, sub_74463a, sub_746ee8, sub_7479e5, sub_7484c4, sub_7484f4, sub_74a1f8, sub_74a228, sub_74a467, sub_74a4f5, sub_74a569, sub_74a634, sub_74a69f, sub_74a798, sub_74acd9, sub_74af5c, sub_74b6fe, sub_74ca09, sub_74e2de, sub_74ef9e, sub_74efd3, sub_74f003, sub_74f0e7, sub_74f2a6, sub_74f476, sub_74f4dc, sub_74f84c, sub_74faee, sub_750170, sub_750535, sub_75091e, sub_751867, sub_7518a7, sub_75451e, sub_75454e, sub_75457e, sub_75478e, sub_7548f3, sub_754c46, sub_754d98, sub_754dd4, sub_7551ff, sub_7569a7, sub_75910e, sub_75913e, sub_75d04e, sub_75d658, sub_760f7e, sub_761099, sub_76123e, sub_761458, sub_762525, sub_76275f, sub_76857e, sub_768aee, sub_76992e, sub_76d64e, sub_76dcbe, sub_76dcee. It accesses memory-mapped peripheral registers at 0xc0000409. It delegates to j__crt_debugger_hook (1 callees).

### sub_652748 at 0x652748 (49 instructions)

````text
0x652748: push 14h
0x65274a: push 807630h
0x65274f: call 00652CF8h
0x652754: push dword ptr ds:[87C678h]
0x65275a: mov esi,ds:[77CEACh]
0x652760: call esi
0x652762: pop ecx
0x652763: mov [ebp-1Ch],eax
0x652766: cmp eax,0FFFFFFFFh
0x652769: jne short 00652777h
0x65276b: push dword ptr [ebp+8]
0x65276e: call dword ptr ds:[77CEB0h]
0x652774: pop ecx
0x652775: jmp short 006527DEh
0x652777: push 8
0x652779: call 00652F44h
0x65277e: pop ecx
0x65277f: and dword ptr [ebp-4],0
0x652783: push dword ptr ds:[87C678h]
0x652789: call esi
0x65278b: mov [ebp-1Ch],eax
0x65278e: push dword ptr ds:[87C674h]
0x652794: call esi
0x652796: pop ecx
0x652797: pop ecx
0x652798: mov [ebp-20h],eax
0x65279b: lea eax,[ebp-20h]
0x65279e: push eax
0x65279f: lea eax,[ebp-1Ch]
0x6527a2: push eax
0x6527a3: push dword ptr [ebp+8]
0x6527a6: mov esi,ds:[77CEC4h]
0x6527ac: call esi
0x6527ae: pop ecx
0x6527af: push eax
0x6527b0: call 00652F3Eh
0x6527b5: mov [ebp-24h],eax
0x6527b8: push dword ptr [ebp-1Ch]
0x6527bb: call esi
0x6527bd: mov ds:[87C678h],eax
0x6527c2: push dword ptr [ebp-20h]
0x6527c5: call esi
0x6527c7: add esp,14h
0x6527ca: mov ds:[87C674h],eax
0x6527cf: mov dword ptr [ebp-4],0FFFFFFFEh
0x6527d6: call 006527E4h
0x6527db: mov eax,[ebp-24h]
0x6527de: call 00652D3Dh
0x6527e3: ret
````

`sub_652748` is called by sub_6527ed. It delegates to sub_6527e4, sub_652cf8, sub_652d3d (5 callees).

### sub_6527e4 at 0x6527e4 (4 instructions)

````text
0x6527e4: push 8
0x6527e6: call 00652F38h
0x6527eb: pop ecx
0x6527ec: ret
````

`sub_6527e4` is called by sub_652748. It delegates to j__unlock (1 callees).

### sub_6527ed at 0x6527ed (8 instructions)

````text
0x6527ed: push dword ptr [esp+4]
0x6527f1: call 00652748h
0x6527f6: neg eax
0x6527f8: sbb eax,eax
0x6527fa: neg eax
0x6527fc: pop ecx
0x6527fd: dec eax
0x6527fe: ret
````

`sub_6527ed` is called by ?get_instance@?$singleton@V_DownloadInfo@@@serialization@boost@@CAAAV_DownloadInfo@@XZ, ?get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ, ?get_mutable_instance@?$singleton@VCViewManager@@@serialization@boost@@SAAAVCViewManager@@XZ, ?get_instance@?$singleton@VCViewManager@@@serialization@boost@@CAAAVCViewManager@@XZ, ?get_instance@?$singleton@VCSymbolManager@@@serialization@boost@@CAAAVCSymbolManager@@XZ, ?get_mutable_instance@?$singleton@VComboSymbol@@@serialization@boost@@SAAAVComboSymbol@@XZ, ?get_instance@?$singleton@VComboSymbol@@@serialization@boost@@CAAAVComboSymbol@@XZ, ?get_mutable_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@SAAAVCComboSymbolTask@@XZ, ?get_instance@?$singleton@VCComboSymbolTask@@@serialization@boost@@CAAAVCComboSymbolTask@@XZ, ?get_mutable_instance@?$singleton@VXDrawManager@@@serialization@boost@@SAAAVXDrawManager@@XZ, ?get_instance@?$singleton@VXDrawManager@@@serialization@boost@@CAAAVXDrawManager@@XZ, ?get_mutable_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@SAAAVTAF_AsynCalcTagging@@XZ, ?get_mutable_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@SAAAVTAF_AsynCalcMatrix@@XZ, ?get_instance@?$singleton@VTAF_AsynCalcTagging@@@serialization@boost@@CAAAVTAF_AsynCalcTagging@@XZ, ?get_instance@?$singleton@VTAF_AsynCalcMatrix@@@serialization@boost@@CAAAVTAF_AsynCalcMatrix@@XZ, ?get_instance@?$singleton@VTAF_Manager@@@serialization@boost@@CAAAVTAF_Manager@@XZ, ?get_instance@?$singleton@VTAF_TemplateManager@@@serialization@boost@@CAAAVTAF_TemplateManager@@XZ, ?get_instance@?$singleton@VTAS_Alerter@@@serialization@boost@@CAAAVTAS_Alerter@@XZ, ?get_instance@?$singleton@VTAS_SelectorPlan@@@serialization@boost@@CAAAVTAS_SelectorPlan@@XZ, ?get_mutable_instance@?$singleton@VCHotKey@@@serialization@boost@@SAAAVCHotKey@@XZ, ?get_instance@?$singleton@VCHotKey@@@serialization@boost@@CAAAVCHotKey@@XZ, ?get_instance@?$singleton@VCFrameManager@@@serialization@boost@@CAAAVCFrameManager@@XZ, ?get_instance@?$singleton@VColorScheme@@@serialization@boost@@CAAAVColorScheme@@XZ, ?get_instance@?$singleton@VCConfig@@@serialization@boost@@CAAAVCConfig@@XZ, ?get_instance@?$singleton@VCSigNoConfig@@@serialization@boost@@CAAAVCSigNoConfig@@XZ, ?get_mutable_instance@?$singleton@VCTaskProc@@@serialization@boost@@SAAAVCTaskProc@@XZ, ?get_instance@?$singleton@VCTaskProc@@@serialization@boost@@CAAAVCTaskProc@@XZ, ?get_mutable_instance@?$singleton@VChromeBrowser@@@serialization@boost@@SAAAVChromeBrowser@@XZ. It delegates to sub_652748 (1 callees).

### sub_652868 at 0x652868 (14 instructions)

````text
0x652868: push 14h
0x65286a: push 807650h
0x65286f: call 00652CF8h
0x652874: and dword ptr [ebp-4],0
0x652878: dec dword ptr [ebp+10h]
0x65287b: js short 006528B7h
0x65287d: mov ecx,[ebp+8]
0x652880: sub ecx,[ebp+0Ch]
0x652883: mov [ebp+8],ecx
0x652886: call dword ptr [ebp+14h]
0x652889: jmp short 00652878h
0x6528b7: mov dword ptr [ebp-4],0FFFFFFFEh
0x6528be: call 00652D3Dh
0x6528c3: ret 10h
````

`sub_652868` is called by sub_652911, sub_652976. It delegates to sub_652cf8, sub_652d3d (2 callees).

### sub_6528c6 at 0x6528c6 (20 instructions)

````text
0x6528c6: push 0Ch
0x6528c8: push 807670h
0x6528cd: call 00652CF8h
0x6528d2: and dword ptr [ebp-1Ch],0
0x6528d6: mov esi,[ebp+0Ch]
0x6528d9: mov eax,esi
0x6528db: imul eax,[ebp+10h]
0x6528df: add [ebp+8],eax
0x6528e2: and dword ptr [ebp-4],0
0x6528e6: dec dword ptr [ebp+10h]
0x6528e9: js short 006528F6h
0x6528eb: sub [ebp+8],esi
0x6528ee: mov ecx,[ebp+8]
0x6528f1: call dword ptr [ebp+14h]
0x6528f4: jmp short 006528E6h
0x6528f6: mov dword ptr [ebp-1Ch],1
0x6528fd: mov dword ptr [ebp-4],0FFFFFFFEh
0x652904: call 00652911h
0x652909: call 00652D3Dh
0x65290e: ret 10h
````

`sub_6528c6` is called by sub_610c30. It delegates to sub_652911, sub_652cf8, sub_652d3d (3 callees).

### sub_652911 at 0x652911 (8 instructions)

````text
0x652911: cmp dword ptr [ebp-1Ch],0
0x652915: jne short 00652928h
0x652917: push dword ptr [ebp+14h]
0x65291a: push dword ptr [ebp+10h]
0x65291d: push dword ptr [ebp+0Ch]
0x652920: push dword ptr [ebp+8]
0x652923: call 00652868h
0x652928: ret
````

`sub_652911` is called by sub_6528c6. It delegates to sub_652868 (1 callees).

### sub_652929 at 0x652929 (22 instructions)

````text
0x652929: push 10h
0x65292b: push 807690h
0x652930: call 00652CF8h
0x652935: xor eax,eax
0x652937: mov [ebp-20h],eax
0x65293a: mov [ebp-4],eax
0x65293d: mov [ebp-1Ch],eax
0x652940: mov eax,[ebp-1Ch]
0x652943: cmp eax,[ebp+10h]
0x652946: jge short 0065295Bh
0x652948: mov esi,[ebp+8]
0x65294b: mov ecx,esi
0x65294d: call dword ptr [ebp+14h]
0x652950: add esi,[ebp+0Ch]
0x652953: mov [ebp+8],esi
0x652956: inc dword ptr [ebp-1Ch]
0x652959: jmp short 00652940h
0x65295b: mov dword ptr [ebp-20h],1
0x652962: mov dword ptr [ebp-4],0FFFFFFFEh
0x652969: call 00652976h
0x65296e: call 00652D3Dh
0x652973: ret 14h
````

`sub_652929` is called by sub_610980. It delegates to sub_652976, sub_652cf8, sub_652d3d (3 callees).

### sub_652976 at 0x652976 (8 instructions)

````text
0x652976: cmp dword ptr [ebp-20h],0
0x65297a: jne short 0065298Dh
0x65297c: push dword ptr [ebp+18h]
0x65297f: push dword ptr [ebp-1Ch]
0x652982: push dword ptr [ebp+0Ch]
0x652985: push dword ptr [ebp+8]
0x652988: call 00652868h
0x65298d: ret
````

`sub_652976` is called by sub_652929. It delegates to sub_652868 (1 callees).

### j_memcpy at 0x652a82 (1 instructions)

````text
0x652a82: jmp dword ptr ds:[77CF6Ch]
````

`j_memcpy` is called by sub_637190. It calls nothing else.

### j_memset at 0x652a94 (1 instructions)

````text
0x652a94: jmp dword ptr ds:[77CF60h]
````

`j_memset` is called by sub_4608f0. It calls nothing else.

### j__CxxThrowException at 0x652ac4 (1 instructions)

````text
0x652ac4: jmp dword ptr ds:[77CF1Ch]
````

`j__CxxThrowException` is called by sub_40f000, sub_42d310, sub_42d470, sub_450370, sub_4655a0, sub_466710, sub_466a30, sub_488a40, sub_49a870, sub_4b4b50, sub_4b5020, sub_4b57e0, sub_4b5ab0, sub_4db900, sub_4dd6d0, sub_4fa340, sub_5069d0, sub_506d20, sub_573040, sub_584970, sub_591fd0, sub_5b0180, sub_5c5310, sub_5c5b80, sub_5ce370, sub_5d9fc0, sub_5e3990, sub_5e3ee0, sub_5e42e0, sub_5e6990, sub_5ef4e0, sub_5f08a0, sub_5f9360, sub_602810, sub_60b1c0, sub_60f810, sub_60fc20, sub_60fe40, sub_6102c0, sub_6229f0, sub_627940, sub_62a0c0, sub_62b850, sub_633610, sub_6339e0, sub_634280, sub_639ff0, sub_63a1a0, sub_63a560. It calls nothing else.

### j__amsg_exit at 0x652b54 (1 instructions)

````text
0x652b54: jmp dword ptr ds:[77CEFCh]
````

`j__amsg_exit` is called by entry. It calls nothing else.

### sub_652bb0 at 0x652bb0 (14 instructions)

````text
0x652bb0: mov ecx,[esp+4]
0x652bb4: cmp word ptr [ecx],5A4Dh
0x652bb9: je short 00652BBEh
0x652bbb: xor eax,eax
0x652bbd: ret
0x652bbe: mov eax,[ecx+3Ch]
0x652bc1: add eax,ecx
0x652bc3: cmp dword ptr [eax],4550h
0x652bc9: jne short 00652BBBh
0x652bcb: xor ecx,ecx
0x652bcd: cmp word ptr [eax+18h],10Bh
0x652bd3: sete cl
0x652bd6: mov eax,ecx
0x652bd8: ret
````

`sub_652bb0` is called by sub_652c30. It calls nothing else.

### sub_652be0 at 0x652be0 (29 instructions)

````text
0x652be0: mov eax,[esp+4]
0x652be4: mov ecx,[eax+3Ch]
0x652be7: add ecx,eax
0x652be9: movzx eax,word ptr [ecx+14h]
0x652bed: push ebx
0x652bee: push esi
0x652bef: movzx esi,word ptr [ecx+6]
0x652bf3: xor edx,edx
0x652bf5: test esi,esi
0x652bf7: push edi
0x652bf8: lea eax,[eax+ecx+18h]
0x652bfc: jbe short 00652C1Ch
0x652bfe: mov edi,[esp+14h]
0x652c02: mov ecx,[eax+0Ch]
0x652c05: cmp edi,ecx
0x652c07: jb short 00652C12h
0x652c09: mov ebx,[eax+8]
0x652c0c: add ebx,ecx
0x652c0e: cmp edi,ebx
0x652c10: jb short 00652C1Eh
0x652c12: add edx,1
0x652c15: add eax,28h
0x652c18: cmp edx,esi
0x652c1a: jb short 00652C02h
0x652c1c: xor eax,eax
0x652c1e: pop edi
0x652c1f: pop esi
0x652c20: pop ebx
0x652c21: ret
````

`sub_652be0` is called by sub_652c30. It calls nothing else.

### sub_652c30 at 0x652c30 (57 instructions)

````text
0x652c30: push ebp
0x652c31: mov ebp,esp
0x652c33: push 0FFFFFFFEh
0x652c35: push 807708h
0x652c3a: push 652D51h
0x652c3f: mov eax,fs:[0]
0x652c45: push eax
0x652c46: sub esp,8
0x652c49: push ebx
0x652c4a: push esi
0x652c4b: push edi
0x652c4c: mov eax,ds:[858220h]
0x652c51: xor [ebp-8],eax
0x652c54: xor eax,ebp
0x652c56: push eax
0x652c57: lea eax,[ebp-10h]
0x652c5a: mov fs:[0],eax
0x652c60: mov [ebp-18h],esp
0x652c63: mov dword ptr [ebp-4],0
0x652c6a: push 400000h
0x652c6f: call 00652BB0h
0x652c74: add esp,4
0x652c77: test eax,eax
0x652c79: je short 00652CD0h
0x652c7b: mov eax,[ebp+8]
0x652c7e: sub eax,400000h
0x652c83: push eax
0x652c84: push 400000h
0x652c89: call 00652BE0h
0x652c8e: add esp,8
0x652c91: test eax,eax
0x652c93: je short 00652CD0h
0x652c95: mov eax,[eax+24h]
0x652c98: shr eax,1Fh
0x652c9b: not eax
0x652c9d: and eax,1
0x652ca0: mov dword ptr [ebp-4],0FFFFFFFEh
0x652ca7: mov ecx,[ebp-10h]
0x652caa: mov fs:[0],ecx
0x652cb1: pop ecx
0x652cb2: pop edi
0x652cb3: pop esi
0x652cb4: pop ebx
0x652cb5: mov esp,ebp
0x652cb7: pop ebp
0x652cb8: ret
0x652cd0: mov dword ptr [ebp-4],0FFFFFFFEh
0x652cd7: xor eax,eax
0x652cd9: mov ecx,[ebp-10h]
0x652cdc: mov fs:[0],ecx
0x652ce3: pop ecx
0x652ce4: pop edi
0x652ce5: pop esi
0x652ce6: pop ebx
0x652ce7: mov esp,ebp
0x652ce9: pop ebp
0x652cea: ret
````

`sub_652c30` is called by entry. It delegates to sub_652bb0, sub_652be0 (2 callees).

### j__initterm at 0x652cec (1 instructions)

````text
0x652cec: jmp dword ptr ds:[77CEE0h]
````

`j__initterm` is called by entry. It calls nothing else.

### j__initterm_e at 0x652cf2 (1 instructions)

````text
0x652cf2: jmp dword ptr ds:[77CEDCh]
````

`j__initterm_e` is called by entry. It calls nothing else.

### sub_652cf8 at 0x652cf8 (21 instructions)

````text
0x652cf8: push 652D51h
0x652cfd: push dword ptr fs:[0]
0x652d04: mov eax,[esp+10h]
0x652d08: mov [esp+10h],ebp
0x652d0c: lea ebp,[esp+10h]
0x652d10: sub esp,eax
0x652d12: push ebx
0x652d13: push esi
0x652d14: push edi
0x652d15: mov eax,ds:[858220h]
0x652d1a: xor [ebp-4],eax
0x652d1d: xor eax,ebp
0x652d1f: push eax
0x652d20: mov [ebp-18h],esp
0x652d23: push dword ptr [ebp-8]
0x652d26: mov eax,[ebp-4]
0x652d29: mov dword ptr [ebp-4],0FFFFFFFEh
0x652d30: mov [ebp-8],eax
0x652d33: lea eax,[ebp-10h]
0x652d36: mov fs:[0],eax
0x652d3c: ret
````

`sub_652cf8` is called by entry, sub_652748, sub_652868, sub_6528c6, sub_652929. It calls nothing else.

### sub_652d3d at 0x652d3d (11 instructions)

````text
0x652d3d: mov ecx,[ebp-10h]
0x652d40: mov fs:[0],ecx
0x652d47: pop ecx
0x652d48: pop edi
0x652d49: pop edi
0x652d4a: pop esi
0x652d4b: pop ebx
0x652d4c: mov esp,ebp
0x652d4e: pop ebp
0x652d4f: push ecx
0x652d50: ret
````

`sub_652d3d` is called by entry, sub_652748, sub_652868, sub_6528c6, sub_652929. It calls nothing else.

### sub_652d51 at 0x652d51 (9 instructions)

````text
0x652d51: push dword ptr [esp+10h]
0x652d55: push dword ptr [esp+10h]
0x652d59: push dword ptr [esp+10h]
0x652d5d: push dword ptr [esp+10h]
0x652d61: push 652739h
0x652d66: push 858220h
0x652d6b: call 00653058h
0x652d70: add esp,18h
0x652d73: ret
````

`sub_652d51` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to j__except_handler4_common (1 callees).

### sub_652da0 at 0x652da0 (52 instructions)

````text
0x652da0: push ebp
0x652da1: mov ebp,esp
0x652da3: sub esp,10h
0x652da6: mov eax,ds:[858220h]
0x652dab: and dword ptr [ebp-8],0
0x652daf: and dword ptr [ebp-4],0
0x652db3: push ebx
0x652db4: push edi
0x652db5: mov edi,0BB40E64Eh
0x652dba: cmp eax,edi
0x652dbc: mov ebx,0FFFF0000h
0x652dc1: je short 00652DD0h
0x652dc3: test ebx,eax
0x652dc5: je short 00652DD0h
0x652dc7: not eax
0x652dc9: mov ds:[858224h],eax
0x652dce: jmp short 00652E30h
0x652dd0: push esi
0x652dd1: lea eax,[ebp-8]
0x652dd4: push eax
0x652dd5: call dword ptr ds:[77C16Ch]
0x652ddb: mov esi,[ebp-4]
0x652dde: xor esi,[ebp-8]
0x652de1: call dword ptr ds:[77C1D8h]
0x652de7: xor esi,eax
0x652de9: call dword ptr ds:[77C170h]
0x652def: xor esi,eax
0x652df1: call dword ptr ds:[77C184h]
0x652df7: xor esi,eax
0x652df9: lea eax,[ebp-10h]
0x652dfc: push eax
0x652dfd: call dword ptr ds:[77C174h]
0x652e03: mov eax,[ebp-0Ch]
0x652e06: xor eax,[ebp-10h]
0x652e09: xor esi,eax
0x652e0b: cmp esi,edi
0x652e0d: jne short 00652E16h
0x652e0f: mov esi,0BB40E64Fh
0x652e14: jmp short 00652E21h
0x652e16: test ebx,esi
0x652e18: jne short 00652E21h
0x652e1a: mov eax,esi
0x652e1c: shl eax,10h
0x652e1f: or esi,eax
0x652e21: mov ds:[858220h],esi
0x652e27: not esi
0x652e29: mov ds:[858224h],esi
0x652e2f: pop esi
0x652e30: pop edi
0x652e31: pop ebx
0x652e32: leave
0x652e33: ret
````

`sub_652da0` is called by entry. It accesses memory-mapped peripheral registers at 0xbb40e64e. It calls nothing else.

### j__unlock at 0x652f38 (1 instructions)

````text
0x652f38: jmp dword ptr ds:[77CEBCh]
````

`j__unlock` is called by sub_6527e4. It calls nothing else.

### j___dllonexit at 0x652f3e (1 instructions)

````text
0x652f3e: jmp dword ptr ds:[77CEB8h]
````

`j___dllonexit` is called by sub_652748. It calls nothing else.

### j__lock at 0x652f44 (1 instructions)

````text
0x652f44: jmp dword ptr ds:[77CEB4h]
````

`j__lock` is called by sub_652748. It calls nothing else.

### j__except_handler4_common at 0x653058 (1 instructions)

````text
0x653058: jmp dword ptr ds:[77CEA0h]
````

`j__except_handler4_common` is called by sub_652d51. It calls nothing else.

### j__crt_debugger_hook at 0x65306a (1 instructions)

````text
0x65306a: jmp dword ptr ds:[77CE94h]
````

`j__crt_debugger_hook` is called by sub_652739. It calls nothing else.

### j_ORDINAL 1198 at 0x7337bd (2 instructions)

````text
0x7337bd: jmp near ptr 00735FF2h
0x735ff2: jmp dword ptr ds:[77C668h]
````

`j_ORDINAL 1198` is called by entry. It calls nothing else.

### sub_738d91 at 0x738d91 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x738d91: mov edx,[esp+8]
0x738d95: lea eax,[edx-4]
0x738d98: mov ecx,[edx-8]
0x738d9b: xor ecx,eax
0x738d9d: call 00652739h
0x738da2: mov eax,80AB38h
0x738da7: jmp near ptr 00652A88h
````

`sub_738d91` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_738dbc at 0x738dbc (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x738dbc: mov edx,[esp+8]
0x738dc0: lea eax,[edx-0Ch]
0x738dc3: mov ecx,[edx-10h]
0x738dc6: xor ecx,eax
0x738dc8: call 00652739h
0x738dcd: mov eax,80AB64h
0x738dd2: jmp near ptr 00652A88h
````

`sub_738dbc` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_738ea8 at 0x738ea8 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x738ea8: mov edx,[esp+8]
0x738eac: lea eax,[edx-4]
0x738eaf: mov ecx,[edx-8]
0x738eb2: xor ecx,eax
0x738eb4: call 00652739h
0x738eb9: mov eax,80AC34h
0x738ebe: jmp near ptr 00652A88h
````

`sub_738ea8` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_738ef4 at 0x738ef4 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x738ef4: mov edx,[esp+8]
0x738ef8: lea eax,[edx-4]
0x738efb: mov ecx,[edx-8]
0x738efe: xor ecx,eax
0x738f00: call 00652739h
0x738f05: mov eax,80AC70h
0x738f0a: jmp near ptr 00652A88h
````

`sub_738ef4` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_738f69 at 0x738f69 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x738f69: mov edx,[esp+8]
0x738f6d: lea eax,[edx-8]
0x738f70: mov ecx,[edx-0Ch]
0x738f73: xor ecx,eax
0x738f75: call 00652739h
0x738f7a: mov eax,80ACD0h
0x738f7f: jmp near ptr 00652A88h
````

`sub_738f69` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_739029 at 0x739029 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x739029: mov edx,[esp+8]
0x73902d: lea eax,[edx-4]
0x739030: mov ecx,[edx-8]
0x739033: xor ecx,eax
0x739035: call 00652739h
0x73903a: mov eax,80AD88h
0x73903f: jmp near ptr 00652A88h
````

`sub_739029` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73931c at 0x73931c (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73931c: mov edx,[esp+8]
0x739320: lea eax,[edx-4]
0x739323: mov ecx,[edx-8]
0x739326: xor ecx,eax
0x739328: call 00652739h
0x73932d: mov eax,80B030h
0x739332: jmp near ptr 00652A88h
````

`sub_73931c` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73973c at 0x73973c (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73973c: mov edx,[esp+8]
0x739740: lea eax,[edx-4]
0x739743: mov ecx,[edx-8]
0x739746: xor ecx,eax
0x739748: call 00652739h
0x73974d: mov eax,80B3A8h
0x739752: jmp near ptr 00652A88h
````

`sub_73973c` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_739e19 at 0x739e19 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x739e19: mov edx,[esp+8]
0x739e1d: lea eax,[edx]
0x739e1f: mov ecx,[edx-4]
0x739e22: xor ecx,eax
0x739e24: call 00652739h
0x739e29: mov eax,80B97Ch
0x739e2e: jmp near ptr 00652A88h
````

`sub_739e19` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73a3c5 at 0x73a3c5 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73a3c5: mov edx,[esp+8]
0x73a3c9: lea eax,[edx-4]
0x73a3cc: mov ecx,[edx-8]
0x73a3cf: xor ecx,eax
0x73a3d1: call 00652739h
0x73a3d6: mov eax,80BEC4h
0x73a3db: jmp near ptr 00652A88h
````

`sub_73a3c5` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73a498 at 0x73a498 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73a498: mov edx,[esp+8]
0x73a49c: lea eax,[edx-4]
0x73a49f: mov ecx,[edx-8]
0x73a4a2: xor ecx,eax
0x73a4a4: call 00652739h
0x73a4a9: mov eax,80BF8Ch
0x73a4ae: jmp near ptr 00652A88h
````

`sub_73a498` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73a76c at 0x73a76c (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73a76c: mov edx,[esp+8]
0x73a770: lea eax,[edx-0Ch]
0x73a773: mov ecx,[edx-10h]
0x73a776: xor ecx,eax
0x73a778: call 00652739h
0x73a77d: mov eax,80C1F0h
0x73a782: jmp near ptr 00652A88h
````

`sub_73a76c` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73a809 at 0x73a809 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73a809: mov edx,[esp+8]
0x73a80d: lea eax,[edx-8]
0x73a810: mov ecx,[edx-0Ch]
0x73a813: xor ecx,eax
0x73a815: call 00652739h
0x73a81a: mov eax,80C274h
0x73a81f: jmp near ptr 00652A88h
````

`sub_73a809` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73aa18 at 0x73aa18 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73aa18: mov edx,[esp+8]
0x73aa1c: lea eax,[edx-0Ch]
0x73aa1f: mov ecx,[edx-10h]
0x73aa22: xor ecx,eax
0x73aa24: call 00652739h
0x73aa29: mov eax,80C624h
0x73aa2e: jmp near ptr 00652A88h
````

`sub_73aa18` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73aa51 at 0x73aa51 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73aa51: mov edx,[esp+8]
0x73aa55: lea eax,[edx+0Ch]
0x73aa58: mov ecx,[edx-1Ch]
0x73aa5b: xor ecx,eax
0x73aa5d: call 00652739h
0x73aa62: mov eax,80C684h
0x73aa67: jmp near ptr 00652A88h
````

`sub_73aa51` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73aa81 at 0x73aa81 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73aa81: mov edx,[esp+8]
0x73aa85: lea eax,[edx+0Ch]
0x73aa88: mov ecx,[edx-1Ch]
0x73aa8b: xor ecx,eax
0x73aa8d: call 00652739h
0x73aa92: mov eax,80C6E4h
0x73aa97: jmp near ptr 00652A88h
````

`sub_73aa81` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73b050 at 0x73b050 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73b050: mov edx,[esp+8]
0x73b054: lea eax,[edx+0Ch]
0x73b057: mov ecx,[edx-14h]
0x73b05a: xor ecx,eax
0x73b05c: call 00652739h
0x73b061: mov eax,80CF40h
0x73b066: jmp near ptr 00652A88h
````

`sub_73b050` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73b5a8 at 0x73b5a8 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73b5a8: mov edx,[esp+8]
0x73b5ac: lea eax,[edx-8]
0x73b5af: mov ecx,[edx-0Ch]
0x73b5b2: xor ecx,eax
0x73b5b4: call 00652739h
0x73b5b9: mov eax,80D800h
0x73b5be: jmp near ptr 00652A88h
````

`sub_73b5a8` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73bee9 at 0x73bee9 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73bee9: mov edx,[esp+8]
0x73beed: lea eax,[edx-0Ch]
0x73bef0: mov ecx,[edx-10h]
0x73bef3: xor ecx,eax
0x73bef5: call 00652739h
0x73befa: mov eax,80E49Ch
0x73beff: jmp near ptr 00652A88h
````

`sub_73bee9` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73c188 at 0x73c188 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73c188: mov edx,[esp+8]
0x73c18c: lea eax,[edx-14h]
0x73c18f: mov ecx,[edx-18h]
0x73c192: xor ecx,eax
0x73c194: call 00652739h
0x73c199: mov eax,80E7F4h
0x73c19e: jmp near ptr 00652A88h
````

`sub_73c188` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73c439 at 0x73c439 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73c439: mov edx,[esp+8]
0x73c43d: lea eax,[edx-4]
0x73c440: mov ecx,[edx-8]
0x73c443: xor ecx,eax
0x73c445: call 00652739h
0x73c44a: mov eax,80EAD4h
0x73c44f: jmp near ptr 00652A88h
````

`sub_73c439` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73d713 at 0x73d713 (12 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73d713: mov edx,[esp+8]
0x73d717: lea eax,[edx-6Ch]
0x73d71a: mov ecx,[edx-70h]
0x73d71d: xor ecx,eax
0x73d71f: call 00652739h
0x73d724: add eax,8
0x73d727: mov ecx,[edx-8]
0x73d72a: xor ecx,eax
0x73d72c: call 00652739h
0x73d731: mov eax,80FF78h
0x73d736: jmp near ptr 00652A88h
````

`sub_73d713` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73db58 at 0x73db58 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73db58: mov edx,[esp+8]
0x73db5c: lea eax,[edx-4]
0x73db5f: mov ecx,[edx-8]
0x73db62: xor ecx,eax
0x73db64: call 00652739h
0x73db69: mov eax,8103E4h
0x73db6e: jmp near ptr 00652A88h
````

`sub_73db58` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73dbd0 at 0x73dbd0 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73dbd0: mov edx,[esp+8]
0x73dbd4: lea eax,[edx+0Ch]
0x73dbd7: mov ecx,[edx-14h]
0x73dbda: xor ecx,eax
0x73dbdc: call 00652739h
0x73dbe1: mov eax,8104C0h
0x73dbe6: jmp near ptr 00652A88h
````

`sub_73dbd0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73e289 at 0x73e289 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73e289: mov edx,[esp+8]
0x73e28d: lea eax,[edx-0Ch]
0x73e290: mov ecx,[edx-10h]
0x73e293: xor ecx,eax
0x73e295: call 00652739h
0x73e29a: mov eax,8113ACh
0x73e29f: jmp near ptr 00652A88h
````

`sub_73e289` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73e2d7 at 0x73e2d7 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73e2d7: mov edx,[esp+8]
0x73e2db: lea eax,[edx-0Ch]
0x73e2de: mov ecx,[edx-10h]
0x73e2e1: xor ecx,eax
0x73e2e3: call 00652739h
0x73e2e8: mov eax,8113D8h
0x73e2ed: jmp near ptr 00652A88h
````

`sub_73e2d7` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73e344 at 0x73e344 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73e344: mov edx,[esp+8]
0x73e348: lea eax,[edx-14h]
0x73e34b: mov ecx,[edx-18h]
0x73e34e: xor ecx,eax
0x73e350: call 00652739h
0x73e355: mov eax,811438h
0x73e35a: jmp near ptr 00652A88h
````

`sub_73e344` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73e606 at 0x73e606 (12 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73e606: mov edx,[esp+8]
0x73e60a: lea eax,[edx-9Ch]
0x73e610: mov ecx,[edx-0A0h]
0x73e616: xor ecx,eax
0x73e618: call 00652739h
0x73e61d: add eax,0Ch
0x73e620: mov ecx,[edx-8]
0x73e623: xor ecx,eax
0x73e625: call 00652739h
0x73e62a: mov eax,8117D0h
0x73e62f: jmp near ptr 00652A88h
````

`sub_73e606` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73e660 at 0x73e660 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73e660: mov edx,[esp+8]
0x73e664: lea eax,[edx-8]
0x73e667: mov ecx,[edx-0Ch]
0x73e66a: xor ecx,eax
0x73e66c: call 00652739h
0x73e671: mov eax,81180Ch
0x73e676: jmp near ptr 00652A88h
````

`sub_73e660` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73e709 at 0x73e709 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73e709: mov edx,[esp+8]
0x73e70d: lea eax,[edx-10h]
0x73e710: mov ecx,[edx-14h]
0x73e713: xor ecx,eax
0x73e715: call 00652739h
0x73e71a: mov eax,811950h
0x73e71f: jmp near ptr 00652A88h
````

`sub_73e709` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73e769 at 0x73e769 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73e769: mov edx,[esp+8]
0x73e76d: lea eax,[edx-8]
0x73e770: mov ecx,[edx-0Ch]
0x73e773: xor ecx,eax
0x73e775: call 00652739h
0x73e77a: mov eax,8119DCh
0x73e77f: jmp near ptr 00652A88h
````

`sub_73e769` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73e941 at 0x73e941 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73e941: mov edx,[esp+8]
0x73e945: lea eax,[edx-10h]
0x73e948: mov ecx,[edx-14h]
0x73e94b: xor ecx,eax
0x73e94d: call 00652739h
0x73e952: mov eax,811CF0h
0x73e957: jmp near ptr 00652A88h
````

`sub_73e941` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73ec8d at 0x73ec8d (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73ec8d: mov edx,[esp+8]
0x73ec91: lea eax,[edx-8]
0x73ec94: mov ecx,[edx-0Ch]
0x73ec97: xor ecx,eax
0x73ec99: call 00652739h
0x73ec9e: mov eax,8120C8h
0x73eca3: jmp near ptr 00652A88h
````

`sub_73ec8d` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73edf9 at 0x73edf9 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73edf9: mov edx,[esp+8]
0x73edfd: lea eax,[edx-5Ch]
0x73ee00: mov ecx,[edx-60h]
0x73ee03: xor ecx,eax
0x73ee05: call 00652739h
0x73ee0a: mov eax,81238Ch
0x73ee0f: jmp near ptr 00652A88h
````

`sub_73edf9` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73ee74 at 0x73ee74 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73ee74: mov edx,[esp+8]
0x73ee78: lea eax,[edx-0Ch]
0x73ee7b: mov ecx,[edx-10h]
0x73ee7e: xor ecx,eax
0x73ee80: call 00652739h
0x73ee85: mov eax,8124A4h
0x73ee8a: jmp near ptr 00652A88h
````

`sub_73ee74` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_73f2eb at 0x73f2eb (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x73f2eb: mov edx,[esp+8]
0x73f2ef: lea eax,[edx-8]
0x73f2f2: mov ecx,[edx-0Ch]
0x73f2f5: xor ecx,eax
0x73f2f7: call 00652739h
0x73f2fc: mov eax,812BC0h
0x73f301: jmp near ptr 00652A88h
````

`sub_73f2eb` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_740349 at 0x740349 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x740349: mov edx,[esp+8]
0x74034d: lea eax,[edx-58h]
0x740350: mov ecx,[edx-5Ch]
0x740353: xor ecx,eax
0x740355: call 00652739h
0x74035a: mov eax,814184h
0x74035f: jmp near ptr 00652A88h
````

`sub_740349` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7410d9 at 0x7410d9 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7410d9: mov edx,[esp+8]
0x7410dd: lea eax,[edx-54h]
0x7410e0: mov ecx,[edx-58h]
0x7410e3: xor ecx,eax
0x7410e5: call 00652739h
0x7410ea: mov eax,815234h
0x7410ef: jmp near ptr 00652A88h
````

`sub_7410d9` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_741199 at 0x741199 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x741199: mov edx,[esp+8]
0x74119d: lea eax,[edx-4Ch]
0x7411a0: mov ecx,[edx-50h]
0x7411a3: xor ecx,eax
0x7411a5: call 00652739h
0x7411aa: mov eax,81539Ch
0x7411af: jmp near ptr 00652A88h
````

`sub_741199` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74202c at 0x74202c (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74202c: mov edx,[esp+8]
0x742030: lea eax,[edx-0Ch]
0x742033: mov ecx,[edx-10h]
0x742036: xor ecx,eax
0x742038: call 00652739h
0x74203d: mov eax,816490h
0x742042: jmp near ptr 00652A88h
````

`sub_74202c` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_742061 at 0x742061 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x742061: mov edx,[esp+8]
0x742065: lea eax,[edx+0Ch]
0x742068: mov ecx,[edx-20h]
0x74206b: xor ecx,eax
0x74206d: call 00652739h
0x742072: mov eax,8164F0h
0x742077: jmp near ptr 00652A88h
````

`sub_742061` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_742088 at 0x742088 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x742088: mov edx,[esp+8]
0x74208c: lea eax,[edx-78h]
0x74208f: mov ecx,[edx-7Ch]
0x742092: xor ecx,eax
0x742094: call 00652739h
0x742099: mov eax,81651Ch
0x74209e: jmp near ptr 00652A88h
````

`sub_742088` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7421c9 at 0x7421c9 (12 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7421c9: mov edx,[esp+8]
0x7421cd: lea eax,[edx-8Ch]
0x7421d3: mov ecx,[edx-90h]
0x7421d9: xor ecx,eax
0x7421db: call 00652739h
0x7421e0: add eax,0Ch
0x7421e3: mov ecx,[edx-8]
0x7421e6: xor ecx,eax
0x7421e8: call 00652739h
0x7421ed: mov eax,816624h
0x7421f2: jmp near ptr 00652A88h
````

`sub_7421c9` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7431c8 at 0x7431c8 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7431c8: mov edx,[esp+8]
0x7431cc: lea eax,[edx-30h]
0x7431cf: mov ecx,[edx-34h]
0x7431d2: xor ecx,eax
0x7431d4: call 00652739h
0x7431d9: mov eax,817AE4h
0x7431de: jmp near ptr 00652A88h
````

`sub_7431c8` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_743339 at 0x743339 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x743339: mov edx,[esp+8]
0x74333d: lea eax,[edx-18h]
0x743340: mov ecx,[edx-1Ch]
0x743343: xor ecx,eax
0x743345: call 00652739h
0x74334a: mov eax,817D84h
0x74334f: jmp near ptr 00652A88h
````

`sub_743339` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_743441 at 0x743441 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x743441: mov edx,[esp+8]
0x743445: lea eax,[edx-0Ch]
0x743448: mov ecx,[edx-10h]
0x74344b: xor ecx,eax
0x74344d: call 00652739h
0x743452: mov eax,817EB8h
0x743457: jmp near ptr 00652A88h
````

`sub_743441` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74355e at 0x74355e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74355e: mov edx,[esp+8]
0x743562: lea eax,[edx-8]
0x743565: mov ecx,[edx-0Ch]
0x743568: xor ecx,eax
0x74356a: call 00652739h
0x74356f: mov eax,817FE0h
0x743574: jmp near ptr 00652A88h
````

`sub_74355e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74359e at 0x74359e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74359e: mov edx,[esp+8]
0x7435a2: lea eax,[edx]
0x7435a4: mov ecx,[edx-4]
0x7435a7: xor ecx,eax
0x7435a9: call 00652739h
0x7435ae: mov eax,81801Ch
0x7435b3: jmp near ptr 00652A88h
````

`sub_74359e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_743714 at 0x743714 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x743714: mov edx,[esp+8]
0x743718: lea eax,[edx-0Ch]
0x74371b: mov ecx,[edx-10h]
0x74371e: xor ecx,eax
0x743720: call 00652739h
0x743725: mov eax,8181A8h
0x74372a: jmp near ptr 00652A88h
````

`sub_743714` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_743788 at 0x743788 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x743788: mov edx,[esp+8]
0x74378c: lea eax,[edx-10h]
0x74378f: mov ecx,[edx-14h]
0x743792: xor ecx,eax
0x743794: call 00652739h
0x743799: mov eax,8182C0h
0x74379e: jmp near ptr 00652A88h
````

`sub_743788` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7437b9 at 0x7437b9 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7437b9: mov edx,[esp+8]
0x7437bd: lea eax,[edx-64h]
0x7437c0: mov ecx,[edx-68h]
0x7437c3: xor ecx,eax
0x7437c5: call 00652739h
0x7437ca: mov eax,8182ECh
0x7437cf: jmp near ptr 00652A88h
````

`sub_7437b9` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7437f1 at 0x7437f1 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7437f1: mov edx,[esp+8]
0x7437f5: lea eax,[edx-6Ch]
0x7437f8: mov ecx,[edx-70h]
0x7437fb: xor ecx,eax
0x7437fd: call 00652739h
0x743802: mov eax,818320h
0x743807: jmp near ptr 00652A88h
````

`sub_7437f1` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_743818 at 0x743818 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x743818: mov edx,[esp+8]
0x74381c: lea eax,[edx-4]
0x74381f: mov ecx,[edx-8]
0x743822: xor ecx,eax
0x743824: call 00652739h
0x743829: mov eax,81834Ch
0x74382e: jmp near ptr 00652A88h
````

`sub_743818` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7438ce at 0x7438ce (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7438ce: mov edx,[esp+8]
0x7438d2: lea eax,[edx-4]
0x7438d5: mov ecx,[edx-8]
0x7438d8: xor ecx,eax
0x7438da: call 00652739h
0x7438df: mov eax,818460h
0x7438e4: jmp near ptr 00652A88h
````

`sub_7438ce` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7445e1 at 0x7445e1 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7445e1: mov edx,[esp+8]
0x7445e5: lea eax,[edx-4]
0x7445e8: mov ecx,[edx-8]
0x7445eb: xor ecx,eax
0x7445ed: call 00652739h
0x7445f2: mov eax,819430h
0x7445f7: jmp near ptr 00652A88h
````

`sub_7445e1` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_744611 at 0x744611 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x744611: mov edx,[esp+8]
0x744615: lea eax,[edx-8]
0x744618: mov ecx,[edx-0Ch]
0x74461b: xor ecx,eax
0x74461d: call 00652739h
0x744622: mov eax,819464h
0x744627: jmp near ptr 00652A88h
````

`sub_744611` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74463a at 0x74463a (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74463a: mov edx,[esp+8]
0x74463e: lea eax,[edx-8]
0x744641: mov ecx,[edx-0Ch]
0x744644: xor ecx,eax
0x744646: call 00652739h
0x74464b: mov eax,819490h
0x744650: jmp near ptr 00652A88h
````

`sub_74463a` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_746ee8 at 0x746ee8 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x746ee8: mov edx,[esp+8]
0x746eec: lea eax,[edx-3Ch]
0x746eef: mov ecx,[edx-40h]
0x746ef2: xor ecx,eax
0x746ef4: call 00652739h
0x746ef9: mov eax,81C564h
0x746efe: jmp near ptr 00652A88h
````

`sub_746ee8` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7479e5 at 0x7479e5 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7479e5: mov edx,[esp+8]
0x7479e9: lea eax,[edx-8]
0x7479ec: mov ecx,[edx-0Ch]
0x7479ef: xor ecx,eax
0x7479f1: call 00652739h
0x7479f6: mov eax,81D114h
0x7479fb: jmp near ptr 00652A88h
````

`sub_7479e5` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7484c4 at 0x7484c4 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7484c4: mov edx,[esp+8]
0x7484c8: lea eax,[edx-0Ch]
0x7484cb: mov ecx,[edx-10h]
0x7484ce: xor ecx,eax
0x7484d0: call 00652739h
0x7484d5: mov eax,81DAF4h
0x7484da: jmp near ptr 00652A88h
````

`sub_7484c4` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7484f4 at 0x7484f4 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7484f4: mov edx,[esp+8]
0x7484f8: lea eax,[edx-4]
0x7484fb: mov ecx,[edx-8]
0x7484fe: xor ecx,eax
0x748500: call 00652739h
0x748505: mov eax,81DB28h
0x74850a: jmp near ptr 00652A88h
````

`sub_7484f4` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74a1f8 at 0x74a1f8 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74a1f8: mov edx,[esp+8]
0x74a1fc: lea eax,[edx-4]
0x74a1ff: mov ecx,[edx-8]
0x74a202: xor ecx,eax
0x74a204: call 00652739h
0x74a209: mov eax,81F86Ch
0x74a20e: jmp near ptr 00652A88h
````

`sub_74a1f8` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74a228 at 0x74a228 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74a228: mov edx,[esp+8]
0x74a22c: lea eax,[edx-8]
0x74a22f: mov ecx,[edx-0Ch]
0x74a232: xor ecx,eax
0x74a234: call 00652739h
0x74a239: mov eax,81F898h
0x74a23e: jmp near ptr 00652A88h
````

`sub_74a228` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74a467 at 0x74a467 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74a467: mov edx,[esp+8]
0x74a46b: lea eax,[edx-10h]
0x74a46e: mov ecx,[edx-14h]
0x74a471: xor ecx,eax
0x74a473: call 00652739h
0x74a478: mov eax,81FB28h
0x74a47d: jmp near ptr 00652A88h
````

`sub_74a467` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74a4f5 at 0x74a4f5 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74a4f5: mov edx,[esp+8]
0x74a4f9: lea eax,[edx-8]
0x74a4fc: mov ecx,[edx-0Ch]
0x74a4ff: xor ecx,eax
0x74a501: call 00652739h
0x74a506: mov eax,81FBA0h
0x74a50b: jmp near ptr 00652A88h
````

`sub_74a4f5` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74a569 at 0x74a569 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74a569: mov edx,[esp+8]
0x74a56d: lea eax,[edx-8]
0x74a570: mov ecx,[edx-0Ch]
0x74a573: xor ecx,eax
0x74a575: call 00652739h
0x74a57a: mov eax,81FC18h
0x74a57f: jmp near ptr 00652A88h
````

`sub_74a569` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74a634 at 0x74a634 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74a634: mov edx,[esp+8]
0x74a638: lea eax,[edx-8]
0x74a63b: mov ecx,[edx-0Ch]
0x74a63e: xor ecx,eax
0x74a640: call 00652739h
0x74a645: mov eax,81FCA0h
0x74a64a: jmp near ptr 00652A88h
````

`sub_74a634` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74a69f at 0x74a69f (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74a69f: mov edx,[esp+8]
0x74a6a3: lea eax,[edx-8]
0x74a6a6: mov ecx,[edx-0Ch]
0x74a6a9: xor ecx,eax
0x74a6ab: call 00652739h
0x74a6b0: mov eax,81FD08h
0x74a6b5: jmp near ptr 00652A88h
````

`sub_74a69f` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74a798 at 0x74a798 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74a798: mov edx,[esp+8]
0x74a79c: lea eax,[edx-8]
0x74a79f: mov ecx,[edx-0Ch]
0x74a7a2: xor ecx,eax
0x74a7a4: call 00652739h
0x74a7a9: mov eax,81FE14h
0x74a7ae: jmp near ptr 00652A88h
````

`sub_74a798` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74acd9 at 0x74acd9 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74acd9: mov edx,[esp+8]
0x74acdd: lea eax,[edx-0Ch]
0x74ace0: mov ecx,[edx-10h]
0x74ace3: xor ecx,eax
0x74ace5: call 00652739h
0x74acea: mov eax,820358h
0x74acef: jmp near ptr 00652A88h
````

`sub_74acd9` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74af5c at 0x74af5c (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74af5c: mov edx,[esp+8]
0x74af60: lea eax,[edx-8]
0x74af63: mov ecx,[edx-0Ch]
0x74af66: xor ecx,eax
0x74af68: call 00652739h
0x74af6d: mov eax,82066Ch
0x74af72: jmp near ptr 00652A88h
````

`sub_74af5c` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74b6fe at 0x74b6fe (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74b6fe: mov edx,[esp+8]
0x74b702: lea eax,[edx]
0x74b704: mov ecx,[edx-4]
0x74b707: xor ecx,eax
0x74b709: call 00652739h
0x74b70e: mov eax,820DE8h
0x74b713: jmp near ptr 00652A88h
````

`sub_74b6fe` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74ca09 at 0x74ca09 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74ca09: mov edx,[esp+8]
0x74ca0d: lea eax,[edx-4]
0x74ca10: mov ecx,[edx-8]
0x74ca13: xor ecx,eax
0x74ca15: call 00652739h
0x74ca1a: mov eax,821FE0h
0x74ca1f: jmp near ptr 00652A88h
````

`sub_74ca09` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74e2de at 0x74e2de (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74e2de: mov edx,[esp+8]
0x74e2e2: lea eax,[edx-4]
0x74e2e5: mov ecx,[edx-8]
0x74e2e8: xor ecx,eax
0x74e2ea: call 00652739h
0x74e2ef: mov eax,823500h
0x74e2f4: jmp near ptr 00652A88h
````

`sub_74e2de` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74ef9e at 0x74ef9e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74ef9e: mov edx,[esp+8]
0x74efa2: lea eax,[edx]
0x74efa4: mov ecx,[edx-4]
0x74efa7: xor ecx,eax
0x74efa9: call 00652739h
0x74efae: mov eax,823FC8h
0x74efb3: jmp near ptr 00652A88h
````

`sub_74ef9e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74efd3 at 0x74efd3 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74efd3: mov edx,[esp+8]
0x74efd7: lea eax,[edx-8]
0x74efda: mov ecx,[edx-0Ch]
0x74efdd: xor ecx,eax
0x74efdf: call 00652739h
0x74efe4: mov eax,823FFCh
0x74efe9: jmp near ptr 00652A88h
````

`sub_74efd3` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74f003 at 0x74f003 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74f003: mov edx,[esp+8]
0x74f007: lea eax,[edx-8]
0x74f00a: mov ecx,[edx-0Ch]
0x74f00d: xor ecx,eax
0x74f00f: call 00652739h
0x74f014: mov eax,824030h
0x74f019: jmp near ptr 00652A88h
````

`sub_74f003` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74f0e7 at 0x74f0e7 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74f0e7: mov edx,[esp+8]
0x74f0eb: lea eax,[edx-14h]
0x74f0ee: mov ecx,[edx-18h]
0x74f0f1: xor ecx,eax
0x74f0f3: call 00652739h
0x74f0f8: mov eax,8240E8h
0x74f0fd: jmp near ptr 00652A88h
````

`sub_74f0e7` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74f2a6 at 0x74f2a6 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74f2a6: mov edx,[esp+8]
0x74f2aa: lea eax,[edx-0Ch]
0x74f2ad: mov ecx,[edx-10h]
0x74f2b0: xor ecx,eax
0x74f2b2: call 00652739h
0x74f2b7: mov eax,8241F8h
0x74f2bc: jmp near ptr 00652A88h
````

`sub_74f2a6` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74f476 at 0x74f476 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74f476: mov edx,[esp+8]
0x74f47a: lea eax,[edx-14h]
0x74f47d: mov ecx,[edx-18h]
0x74f480: xor ecx,eax
0x74f482: call 00652739h
0x74f487: mov eax,824318h
0x74f48c: jmp near ptr 00652A88h
````

`sub_74f476` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74f4dc at 0x74f4dc (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74f4dc: mov edx,[esp+8]
0x74f4e0: lea eax,[edx-50h]
0x74f4e3: mov ecx,[edx-54h]
0x74f4e6: xor ecx,eax
0x74f4e8: call 00652739h
0x74f4ed: mov eax,82436Ch
0x74f4f2: jmp near ptr 00652A88h
````

`sub_74f4dc` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74f84c at 0x74f84c (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74f84c: mov edx,[esp+8]
0x74f850: lea eax,[edx-4]
0x74f853: mov ecx,[edx-8]
0x74f856: xor ecx,eax
0x74f858: call 00652739h
0x74f85d: mov eax,8246E4h
0x74f862: jmp near ptr 00652A88h
````

`sub_74f84c` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_74faee at 0x74faee (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x74faee: mov edx,[esp+8]
0x74faf2: lea eax,[edx-4]
0x74faf5: mov ecx,[edx-8]
0x74faf8: xor ecx,eax
0x74fafa: call 00652739h
0x74faff: mov eax,824998h
0x74fb04: jmp near ptr 00652A88h
````

`sub_74faee` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_750170 at 0x750170 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x750170: mov edx,[esp+8]
0x750174: lea eax,[edx-4]
0x750177: mov ecx,[edx-8]
0x75017a: xor ecx,eax
0x75017c: call 00652739h
0x750181: mov eax,824FE4h
0x750186: jmp near ptr 00652A88h
````

`sub_750170` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_750535 at 0x750535 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x750535: mov edx,[esp+8]
0x750539: lea eax,[edx]
0x75053b: mov ecx,[edx-4]
0x75053e: xor ecx,eax
0x750540: call 00652739h
0x750545: mov eax,825434h
0x75054a: jmp near ptr 00652A88h
````

`sub_750535` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_75091e at 0x75091e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x75091e: mov edx,[esp+8]
0x750922: lea eax,[edx]
0x750924: mov ecx,[edx-4]
0x750927: xor ecx,eax
0x750929: call 00652739h
0x75092e: mov eax,825860h
0x750933: jmp near ptr 00652A88h
````

`sub_75091e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_751867 at 0x751867 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x751867: mov edx,[esp+8]
0x75186b: lea eax,[edx-0Ch]
0x75186e: mov ecx,[edx-10h]
0x751871: xor ecx,eax
0x751873: call 00652739h
0x751878: mov eax,826598h
0x75187d: jmp near ptr 00652A88h
````

`sub_751867` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7518a7 at 0x7518a7 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7518a7: mov edx,[esp+8]
0x7518ab: lea eax,[edx-10h]
0x7518ae: mov ecx,[edx-14h]
0x7518b1: xor ecx,eax
0x7518b3: call 00652739h
0x7518b8: mov eax,8265CCh
0x7518bd: jmp near ptr 00652A88h
````

`sub_7518a7` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_75451e at 0x75451e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x75451e: mov edx,[esp+8]
0x754522: lea eax,[edx-4]
0x754525: mov ecx,[edx-8]
0x754528: xor ecx,eax
0x75452a: call 00652739h
0x75452f: mov eax,828A30h
0x754534: jmp near ptr 00652A88h
````

`sub_75451e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_75454e at 0x75454e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x75454e: mov edx,[esp+8]
0x754552: lea eax,[edx-4]
0x754555: mov ecx,[edx-8]
0x754558: xor ecx,eax
0x75455a: call 00652739h
0x75455f: mov eax,828A5Ch
0x754564: jmp near ptr 00652A88h
````

`sub_75454e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_75457e at 0x75457e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x75457e: mov edx,[esp+8]
0x754582: lea eax,[edx-4]
0x754585: mov ecx,[edx-8]
0x754588: xor ecx,eax
0x75458a: call 00652739h
0x75458f: mov eax,828A88h
0x754594: jmp near ptr 00652A88h
````

`sub_75457e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_75478e at 0x75478e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x75478e: mov edx,[esp+8]
0x754792: lea eax,[edx-4]
0x754795: mov ecx,[edx-8]
0x754798: xor ecx,eax
0x75479a: call 00652739h
0x75479f: mov eax,828D34h
0x7547a4: jmp near ptr 00652A88h
````

`sub_75478e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7548f3 at 0x7548f3 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7548f3: mov edx,[esp+8]
0x7548f7: lea eax,[edx-34h]
0x7548fa: mov ecx,[edx-38h]
0x7548fd: xor ecx,eax
0x7548ff: call 00652739h
0x754904: mov eax,828E40h
0x754909: jmp near ptr 00652A88h
````

`sub_7548f3` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_754c46 at 0x754c46 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x754c46: mov edx,[esp+8]
0x754c4a: lea eax,[edx-0Ch]
0x754c4d: mov ecx,[edx-10h]
0x754c50: xor ecx,eax
0x754c52: call 00652739h
0x754c57: mov eax,8291A0h
0x754c5c: jmp near ptr 00652A88h
````

`sub_754c46` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_754d98 at 0x754d98 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x754d98: mov edx,[esp+8]
0x754d9c: lea eax,[edx-0Ch]
0x754d9f: mov ecx,[edx-10h]
0x754da2: xor ecx,eax
0x754da4: call 00652739h
0x754da9: mov eax,829360h
0x754dae: jmp near ptr 00652A88h
````

`sub_754d98` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_754dd4 at 0x754dd4 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x754dd4: mov edx,[esp+8]
0x754dd8: lea eax,[edx-4]
0x754ddb: mov ecx,[edx-8]
0x754dde: xor ecx,eax
0x754de0: call 00652739h
0x754de5: mov eax,829394h
0x754dea: jmp near ptr 00652A88h
````

`sub_754dd4` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7551ff at 0x7551ff (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7551ff: mov edx,[esp+8]
0x755203: lea eax,[edx-8]
0x755206: mov ecx,[edx-0Ch]
0x755209: xor ecx,eax
0x75520b: call 00652739h
0x755210: mov eax,8296D4h
0x755215: jmp near ptr 00652A88h
````

`sub_7551ff` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_7569a7 at 0x7569a7 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x7569a7: mov edx,[esp+8]
0x7569ab: lea eax,[edx-0Ch]
0x7569ae: mov ecx,[edx-10h]
0x7569b1: xor ecx,eax
0x7569b3: call 00652739h
0x7569b8: mov eax,82AA74h
0x7569bd: jmp near ptr 00652A88h
````

`sub_7569a7` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_75910e at 0x75910e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x75910e: mov edx,[esp+8]
0x759112: lea eax,[edx]
0x759114: mov ecx,[edx-4]
0x759117: xor ecx,eax
0x759119: call 00652739h
0x75911e: mov eax,82CC88h
0x759123: jmp near ptr 00652A88h
````

`sub_75910e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_75913e at 0x75913e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x75913e: mov edx,[esp+8]
0x759142: lea eax,[edx]
0x759144: mov ecx,[edx-4]
0x759147: xor ecx,eax
0x759149: call 00652739h
0x75914e: mov eax,82CCB4h
0x759153: jmp near ptr 00652A88h
````

`sub_75913e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_75d04e at 0x75d04e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x75d04e: mov edx,[esp+8]
0x75d052: lea eax,[edx-4]
0x75d055: mov ecx,[edx-8]
0x75d058: xor ecx,eax
0x75d05a: call 00652739h
0x75d05f: mov eax,8300D4h
0x75d064: jmp near ptr 00652A88h
````

`sub_75d04e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_75d658 at 0x75d658 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x75d658: mov edx,[esp+8]
0x75d65c: lea eax,[edx-10h]
0x75d65f: mov ecx,[edx-14h]
0x75d662: xor ecx,eax
0x75d664: call 00652739h
0x75d669: mov eax,8305B0h
0x75d66e: jmp near ptr 00652A88h
````

`sub_75d658` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_760f7e at 0x760f7e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x760f7e: mov edx,[esp+8]
0x760f82: lea eax,[edx-0Ch]
0x760f85: mov ecx,[edx-10h]
0x760f88: xor ecx,eax
0x760f8a: call 00652739h
0x760f8f: mov eax,833A8Ch
0x760f94: jmp near ptr 00652A88h
````

`sub_760f7e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_761099 at 0x761099 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x761099: mov edx,[esp+8]
0x76109d: lea eax,[edx-14h]
0x7610a0: mov ecx,[edx-18h]
0x7610a3: xor ecx,eax
0x7610a5: call 00652739h
0x7610aa: mov eax,833BD8h
0x7610af: jmp near ptr 00652A88h
````

`sub_761099` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_76123e at 0x76123e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x76123e: mov edx,[esp+8]
0x761242: lea eax,[edx-4]
0x761245: mov ecx,[edx-8]
0x761248: xor ecx,eax
0x76124a: call 00652739h
0x76124f: mov eax,833DB0h
0x761254: jmp near ptr 00652A88h
````

`sub_76123e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_761458 at 0x761458 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x761458: mov edx,[esp+8]
0x76145c: lea eax,[edx-10h]
0x76145f: mov ecx,[edx-14h]
0x761462: xor ecx,eax
0x761464: call 00652739h
0x761469: mov eax,834100h
0x76146e: jmp near ptr 00652A88h
````

`sub_761458` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_762525 at 0x762525 (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x762525: mov edx,[esp+8]
0x762529: lea eax,[edx-10h]
0x76252c: mov ecx,[edx-14h]
0x76252f: xor ecx,eax
0x762531: call 00652739h
0x762536: mov eax,834DDCh
0x76253b: jmp near ptr 00652A88h
````

`sub_762525` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_76275f at 0x76275f (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x76275f: mov edx,[esp+8]
0x762763: lea eax,[edx-4]
0x762766: mov ecx,[edx-8]
0x762769: xor ecx,eax
0x76276b: call 00652739h
0x762770: mov eax,834F94h
0x762775: jmp near ptr 00652A88h
````

`sub_76275f` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_76857e at 0x76857e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x76857e: mov edx,[esp+8]
0x768582: lea eax,[edx-4]
0x768585: mov ecx,[edx-8]
0x768588: xor ecx,eax
0x76858a: call 00652739h
0x76858f: mov eax,83A1D0h
0x768594: jmp near ptr 00652A88h
````

`sub_76857e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_768aee at 0x768aee (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x768aee: mov edx,[esp+8]
0x768af2: lea eax,[edx-4]
0x768af5: mov ecx,[edx-8]
0x768af8: xor ecx,eax
0x768afa: call 00652739h
0x768aff: mov eax,83A6D8h
0x768b04: jmp near ptr 00652A88h
````

`sub_768aee` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_76992e at 0x76992e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x76992e: mov edx,[esp+8]
0x769932: lea eax,[edx-4]
0x769935: mov ecx,[edx-8]
0x769938: xor ecx,eax
0x76993a: call 00652739h
0x76993f: mov eax,83B5FCh
0x769944: jmp near ptr 00652A88h
````

`sub_76992e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_76d64e at 0x76d64e (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x76d64e: mov edx,[esp+8]
0x76d652: lea eax,[edx]
0x76d654: mov ecx,[edx-4]
0x76d657: xor ecx,eax
0x76d659: call 00652739h
0x76d65e: mov eax,83EA54h
0x76d663: jmp near ptr 00652A88h
````

`sub_76d64e` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_76dcbe at 0x76dcbe (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x76dcbe: mov edx,[esp+8]
0x76dcc2: lea eax,[edx]
0x76dcc4: mov ecx,[edx-4]
0x76dcc7: xor ecx,eax
0x76dcc9: call 00652739h
0x76dcce: mov eax,83F0A4h
0x76dcd3: jmp near ptr 00652A88h
````

`sub_76dcbe` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_76dcee at 0x76dcee (8 instructions)

````text
0x652a88: jmp dword ptr ds:[77CF68h]
0x76dcee: mov edx,[esp+8]
0x76dcf2: lea eax,[edx]
0x76dcf4: mov ecx,[edx-4]
0x76dcf7: xor ecx,eax
0x76dcf9: call 00652739h
0x76dcfe: mov eax,83F0D0h
0x76dd03: jmp near ptr 00652A88h
````

`sub_76dcee` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_652739 (1 callees).

### sub_77af50 at 0x77af50 (5 instructions)

````text
0x77af50: push ecx
0x77af51: mov byte ptr ds:[874873h],1
0x77af58: call 00460A70h
0x77af5d: pop ecx
0x77af5e: ret
````

`sub_77af50` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_460a70 (1 callees).

### sub_77b180 at 0x77b180 (5 instructions)

````text
0x77b180: push ecx
0x77b181: mov byte ptr ds:[8748ACh],1
0x77b188: call 004DC5A0h
0x77b18d: pop ecx
0x77b18e: ret
````

`sub_77b180` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_4dc5a0 (1 callees).

### sub_77b380 at 0x77b380 (29 instructions)

````text
0x573410: push ebp
0x573411: mov ebp,esp
0x573413: and esp,0FFFFFFF8h
0x573416: sub esp,0Ch
0x573419: push edi
0x57341a: mov edi,eax
0x57341c: mov eax,[edi+4]
0x57341f: mov ecx,[eax]
0x573421: push eax
0x573422: push edi
0x573423: push ecx
0x573424: push edi
0x573425: lea eax,[esp+18h]
0x573429: push eax
0x57342a: call 00573500h
0x57342f: mov ecx,[edi+4]
0x573432: push ecx
0x573433: call 006516BAh
0x573438: add esp,4
0x57343b: xor eax,eax
0x57343d: mov [edi+4],eax
0x573440: mov [edi+8],eax
0x573443: pop edi
0x573444: mov esp,ebp
0x573446: pop ebp
0x573447: ret
0x77b380: mov byte ptr ds:[8748BCh],1
0x77b387: mov eax,875A50h
0x77b38c: jmp near ptr 00573410h
````

`sub_77b380` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_573500, j_ORDINAL 764 (2 callees).

### sub_77b3c0 at 0x77b3c0 (5 instructions)

````text
0x77b3c0: push ecx
0x77b3c1: mov byte ptr ds:[8748D8h],1
0x77b3c8: call 00580CC0h
0x77b3cd: pop ecx
0x77b3ce: ret
````

`sub_77b3c0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_580cc0 (1 callees).

### sub_77b3d0 at 0x77b3d0 (21 instructions)

````text
0x5c2ea0: push 0FFFFFFFFh
0x5c2ea2: push 750535h
0x5c2ea7: mov eax,fs:[0]
0x5c2ead: push eax
0x5c2eae: mov eax,ds:[858220h]
0x5c2eb3: xor eax,esp
0x5c2eb5: push eax
0x5c2eb6: lea eax,[esp+4]
0x5c2eba: mov fs:[0],eax
0x5c2ec0: mov ecx,8749BCh
0x5c2ec5: mov dword ptr [esp+0Ch],0
0x5c2ecd: call dword ptr ds:[77DF7Ch]
0x5c2ed3: mov dword ptr [esp+0Ch],0FFFFFFFFh
0x5c2edb: call 005C5180h
0x5c2ee0: mov ecx,[esp+4]
0x5c2ee4: mov fs:[0],ecx
0x5c2eeb: pop ecx
0x5c2eec: add esp,0Ch
0x5c2eef: ret
0x77b3d0: mov byte ptr ds:[8748D9h],1
0x77b3d7: jmp near ptr 005C2EA0h
````

`sub_77b3d0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5c5180 (1 callees).

### sub_77b3e0 at 0x77b3e0 (26 instructions)

````text
0x5c5e00: push 0FFFFFFFFh
0x5c5e02: push 7445E1h
0x5c5e07: mov eax,fs:[0]
0x5c5e0d: push eax
0x5c5e0e: push ecx
0x5c5e0f: mov eax,ds:[858220h]
0x5c5e14: xor eax,esp
0x5c5e16: push eax
0x5c5e17: lea eax,[esp+8]
0x5c5e1b: mov fs:[0],eax
0x5c5e21: mov dword ptr [esp+4],874968h
0x5c5e29: mov ecx,874990h
0x5c5e2e: mov dword ptr [esp+10h],1
0x5c5e36: call dword ptr ds:[77CD74h]
0x5c5e3c: mov ecx,87497Ch
0x5c5e41: mov byte ptr [esp+10h],0
0x5c5e46: call dword ptr ds:[77DF7Ch]
0x5c5e4c: mov dword ptr [esp+10h],0FFFFFFFFh
0x5c5e54: call 005C6B00h
0x5c5e59: mov ecx,[esp+8]
0x5c5e5d: mov fs:[0],ecx
0x5c5e64: pop ecx
0x5c5e65: add esp,10h
0x5c5e68: ret
0x77b3e0: mov byte ptr ds:[8748DAh],1
0x77b3e7: jmp near ptr 005C5E00h
````

`sub_77b3e0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5c6b00 (1 callees).

### sub_77b3f0 at 0x77b3f0 (27 instructions)

````text
0x5d1260: push 0FFFFFFFFh
0x5d1262: push 754DD4h
0x5d1267: mov eax,fs:[0]
0x5d126d: push eax
0x5d126e: push ecx
0x5d126f: mov eax,ds:[858220h]
0x5d1274: xor eax,esp
0x5d1276: push eax
0x5d1277: lea eax,[esp+8]
0x5d127b: mov fs:[0],eax
0x5d1281: mov dword ptr [esp+4],875DB4h
0x5d1289: mov ecx,875DCCh
0x5d128e: mov dword ptr [esp+10h],1
0x5d1296: call dword ptr ds:[77CD74h]
0x5d129c: mov eax,875DBCh
0x5d12a1: mov byte ptr [esp+10h],0
0x5d12a6: call 005E4B30h
0x5d12ab: mov ecx,875DB4h
0x5d12b0: mov dword ptr [esp+10h],0FFFFFFFFh
0x5d12b8: call dword ptr ds:[77DF7Ch]
0x5d12be: mov ecx,[esp+8]
0x5d12c2: mov fs:[0],ecx
0x5d12c9: pop ecx
0x5d12ca: add esp,10h
0x5d12cd: ret
0x77b3f0: mov byte ptr ds:[8748DBh],1
0x77b3f7: jmp near ptr 005D1260h
````

`sub_77b3f0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5e4b30 (1 callees).

### sub_77b400 at 0x77b400 (58 instructions)

````text
0x5d76b0: push 0FFFFFFFFh
0x5d76b2: push 761458h
0x5d76b7: mov eax,fs:[0]
0x5d76bd: push eax
0x5d76be: push ecx
0x5d76bf: push ebx
0x5d76c0: push esi
0x5d76c1: push edi
0x5d76c2: mov eax,ds:[858220h]
0x5d76c7: xor eax,esp
0x5d76c9: push eax
0x5d76ca: lea eax,[esp+14h]
0x5d76ce: mov fs:[0],eax
0x5d76d4: mov edi,ecx
0x5d76d6: mov [esp+10h],edi
0x5d76da: mov dword ptr [edi],7F43ECh
0x5d76e0: lea ebx,[edi+4]
0x5d76e3: push ebx
0x5d76e4: mov dword ptr [esp+20h],4
0x5d76ec: call 004DD270h
0x5d76f1: mov ecx,eax
0x5d76f3: call 004DC780h
0x5d76f8: mov esi,[edi+88h]
0x5d76fe: call 00401080h
0x5d7703: mov ecx,[edi+88h]
0x5d7709: test ecx,ecx
0x5d770b: je short 005D7715h
0x5d770d: mov eax,[ecx]
0x5d770f: mov edx,[eax]
0x5d7711: push 1
0x5d7713: call edx
0x5d7715: lea ecx,[edi+60h]
0x5d7718: mov byte ptr [esp+1Ch],3
0x5d771d: call 005D8F50h
0x5d7722: lea eax,[edi+54h]
0x5d7725: mov byte ptr [esp+1Ch],2
0x5d772a: call 005E4B30h
0x5d772f: lea eax,[edi+48h]
0x5d7732: mov byte ptr [esp+1Ch],1
0x5d7737: call 005E4B30h
0x5d773c: lea ecx,[edi+40h]
0x5d773f: mov byte ptr [esp+1Ch],0
0x5d7744: call dword ptr ds:[77DF7Ch]
0x5d774a: mov ecx,ebx
0x5d774c: mov dword ptr [esp+1Ch],0FFFFFFFFh
0x5d7754: call 004DDE10h
0x5d7759: mov ecx,[esp+14h]
0x5d775d: mov fs:[0],ecx
0x5d7764: pop ecx
0x5d7765: pop edi
0x5d7766: pop esi
0x5d7767: pop ebx
0x5d7768: add esp,10h
0x5d776b: ret
0x77b400: mov byte ptr ds:[8748DDh],1
0x77b407: mov dword ptr ds:[876428h],7F4448h
0x77b411: mov ecx,876428h
0x77b416: jmp near ptr 005D76B0h
````

`sub_77b400` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_401080, sub_4dc780, ?get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ (6 callees).

### sub_77b420 at 0x77b420 (58 instructions)

````text
0x5d76b0: push 0FFFFFFFFh
0x5d76b2: push 761458h
0x5d76b7: mov eax,fs:[0]
0x5d76bd: push eax
0x5d76be: push ecx
0x5d76bf: push ebx
0x5d76c0: push esi
0x5d76c1: push edi
0x5d76c2: mov eax,ds:[858220h]
0x5d76c7: xor eax,esp
0x5d76c9: push eax
0x5d76ca: lea eax,[esp+14h]
0x5d76ce: mov fs:[0],eax
0x5d76d4: mov edi,ecx
0x5d76d6: mov [esp+10h],edi
0x5d76da: mov dword ptr [edi],7F43ECh
0x5d76e0: lea ebx,[edi+4]
0x5d76e3: push ebx
0x5d76e4: mov dword ptr [esp+20h],4
0x5d76ec: call 004DD270h
0x5d76f1: mov ecx,eax
0x5d76f3: call 004DC780h
0x5d76f8: mov esi,[edi+88h]
0x5d76fe: call 00401080h
0x5d7703: mov ecx,[edi+88h]
0x5d7709: test ecx,ecx
0x5d770b: je short 005D7715h
0x5d770d: mov eax,[ecx]
0x5d770f: mov edx,[eax]
0x5d7711: push 1
0x5d7713: call edx
0x5d7715: lea ecx,[edi+60h]
0x5d7718: mov byte ptr [esp+1Ch],3
0x5d771d: call 005D8F50h
0x5d7722: lea eax,[edi+54h]
0x5d7725: mov byte ptr [esp+1Ch],2
0x5d772a: call 005E4B30h
0x5d772f: lea eax,[edi+48h]
0x5d7732: mov byte ptr [esp+1Ch],1
0x5d7737: call 005E4B30h
0x5d773c: lea ecx,[edi+40h]
0x5d773f: mov byte ptr [esp+1Ch],0
0x5d7744: call dword ptr ds:[77DF7Ch]
0x5d774a: mov ecx,ebx
0x5d774c: mov dword ptr [esp+1Ch],0FFFFFFFFh
0x5d7754: call 004DDE10h
0x5d7759: mov ecx,[esp+14h]
0x5d775d: mov fs:[0],ecx
0x5d7764: pop ecx
0x5d7765: pop edi
0x5d7766: pop esi
0x5d7767: pop ebx
0x5d7768: add esp,10h
0x5d776b: ret
0x77b420: mov byte ptr ds:[8748DCh],1
0x77b427: mov dword ptr ds:[8764B8h],7F4428h
0x77b431: mov ecx,8764B8h
0x77b436: jmp near ptr 005D76B0h
````

`sub_77b420` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_401080, sub_4dc780, ?get_instance@?$singleton@VCEventMan@@@serialization@boost@@CAAAVCEventMan@@XZ (6 callees).

### sub_77b440 at 0x77b440 (5 instructions)

````text
0x77b440: push ecx
0x77b441: mov byte ptr ds:[8748DEh],1
0x77b448: call 005DFE00h
0x77b44d: pop ecx
0x77b44e: ret
````

`sub_77b440` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5dfe00 (1 callees).

### sub_77b450 at 0x77b450 (41 instructions)

````text
0x5e8840: push 0FFFFFFFFh
0x5e8842: push 74ACD9h
0x5e8847: mov eax,fs:[0]
0x5e884d: push eax
0x5e884e: push ecx
0x5e884f: push ebx
0x5e8850: push esi
0x5e8851: mov eax,ds:[858220h]
0x5e8856: xor eax,esp
0x5e8858: push eax
0x5e8859: lea eax,[esp+10h]
0x5e885d: mov fs:[0],eax
0x5e8863: mov dword ptr [esp+0Ch],875D24h
0x5e886b: xor esi,esi
0x5e886d: mov [esp+18h],esi
0x5e8871: mov eax,ds:[875D30h]
0x5e8876: cmp eax,esi
0x5e8878: je short 005E8899h
0x5e887a: mov ecx,[esp+0Ch]
0x5e887e: mov ebx,ds:[875D34h]
0x5e8884: push ecx
0x5e8885: call 0044D400h
0x5e888a: mov edx,ds:[875D30h]
0x5e8890: push edx
0x5e8891: call 006516BAh
0x5e8896: add esp,8
0x5e8899: mov ecx,875D24h
0x5e889e: mov ds:[875D30h],esi
0x5e88a4: mov ds:[875D34h],esi
0x5e88aa: mov ds:[875D38h],esi
0x5e88b0: mov dword ptr [esp+18h],0FFFFFFFFh
0x5e88b8: call dword ptr ds:[77DF7Ch]
0x5e88be: mov ecx,[esp+10h]
0x5e88c2: mov fs:[0],ecx
0x5e88c9: pop ecx
0x5e88ca: pop esi
0x5e88cb: pop ebx
0x5e88cc: add esp,10h
0x5e88cf: ret
0x77b450: mov byte ptr ds:[8748DFh],1
0x77b457: jmp near ptr 005E8840h
````

`sub_77b450` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_44d400, j_ORDINAL 764 (2 callees).

### sub_77b460 at 0x77b460 (7 instructions)

````text
0x77b460: push ecx
0x77b461: mov ecx,874D80h
0x77b466: mov dword ptr ds:[874D80h],7F4C60h
0x77b470: mov byte ptr ds:[8748F0h],1
0x77b477: call 005EA9C0h
0x77b47c: pop ecx
0x77b47d: ret
````

`sub_77b460` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5ea9c0 (1 callees).

### sub_77b480 at 0x77b480 (32 instructions)

````text
0x5f18f0: push 0FFFFFFFFh
0x5f18f2: push 74202Ch
0x5f18f7: mov eax,fs:[0]
0x5f18fd: push eax
0x5f18fe: push ecx
0x5f18ff: push ebx
0x5f1900: push esi
0x5f1901: mov eax,ds:[858220h]
0x5f1906: xor eax,esp
0x5f1908: push eax
0x5f1909: lea eax,[esp+10h]
0x5f190d: mov fs:[0],eax
0x5f1913: mov esi,ecx
0x5f1915: mov [esp+0Ch],esi
0x5f1919: mov dword ptr [esi],7F4DACh
0x5f191f: lea ebx,[esi+0Ch]
0x5f1922: mov dword ptr [esp+18h],0
0x5f192a: call 004A3A30h
0x5f192f: lea ecx,[esi+4]
0x5f1932: mov dword ptr [esp+18h],0FFFFFFFFh
0x5f193a: call dword ptr ds:[77DF7Ch]
0x5f1940: mov ecx,[esp+10h]
0x5f1944: mov fs:[0],ecx
0x5f194b: pop ecx
0x5f194c: pop esi
0x5f194d: pop ebx
0x5f194e: add esp,10h
0x5f1951: ret
0x77b480: mov dword ptr ds:[875D94h],7F4DB4h
0x77b48a: mov byte ptr ds:[8748F1h],1
0x77b491: mov ecx,875D94h
0x77b496: jmp near ptr 005F18F0h
````

`sub_77b480` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_4a3a30 (1 callees).

### sub_77b4a0 at 0x77b4a0 (30 instructions)

````text
0x5f56a0: push 0FFFFFFFFh
0x5f56a2: push 76857Eh
0x5f56a7: mov eax,fs:[0]
0x5f56ad: push eax
0x5f56ae: push ecx
0x5f56af: mov eax,ds:[858220h]
0x5f56b4: xor eax,esp
0x5f56b6: push eax
0x5f56b7: lea eax,[esp+8]
0x5f56bb: mov fs:[0],eax
0x5f56c1: mov dword ptr [esp+4],875F40h
0x5f56c9: mov eax,875F64h
0x5f56ce: mov dword ptr [esp+10h],2
0x5f56d6: call 005F8930h
0x5f56db: mov eax,875F58h
0x5f56e0: mov byte ptr [esp+10h],1
0x5f56e5: call 005F8930h
0x5f56ea: mov eax,875F4Ch
0x5f56ef: mov byte ptr [esp+10h],0
0x5f56f4: call 005F8930h
0x5f56f9: mov eax,875F40h
0x5f56fe: mov dword ptr [esp+10h],0FFFFFFFFh
0x5f5706: call 005F8930h
0x5f570b: mov ecx,[esp+8]
0x5f570f: mov fs:[0],ecx
0x5f5716: pop ecx
0x5f5717: add esp,10h
0x5f571a: ret
0x77b4a0: mov byte ptr ds:[8748F2h],1
0x77b4a7: jmp near ptr 005F56A0h
````

`sub_77b4a0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_5f8930 (1 callees).

### sub_77b4b0 at 0x77b4b0 (29 instructions)

````text
0x607a20: push 0FFFFFFFFh
0x607a22: push 739029h
0x607a27: mov eax,fs:[0]
0x607a2d: push eax
0x607a2e: push ecx
0x607a2f: mov eax,ds:[858220h]
0x607a34: xor eax,esp
0x607a36: push eax
0x607a37: lea eax,[esp+8]
0x607a3b: mov fs:[0],eax
0x607a41: mov dword ptr [esp+4],874934h
0x607a49: mov dword ptr [esp+10h],0
0x607a51: mov ecx,ds:[87493Ch]
0x607a57: test ecx,ecx
0x607a59: je short 00607A63h
0x607a5b: mov eax,[ecx]
0x607a5d: mov edx,[eax]
0x607a5f: push 1
0x607a61: call edx
0x607a63: mov ecx,874934h
0x607a68: mov dword ptr [esp+10h],0FFFFFFFFh
0x607a70: call dword ptr ds:[77DF7Ch]
0x607a76: mov ecx,[esp+8]
0x607a7a: mov fs:[0],ecx
0x607a81: pop ecx
0x607a82: add esp,10h
0x607a85: ret
0x77b4b0: mov byte ptr ds:[8748F3h],1
0x77b4b7: jmp near ptr 00607A20h
````

`sub_77b4b0` has no recorded callers; it is a leaf stub, likely reached through the vector table. It calls nothing else.

### sub_77b4c0 at 0x77b4c0 (6 instructions)

````text
0x77b4c0: push ecx
0x77b4c1: push 875D50h
0x77b4c6: mov byte ptr ds:[8748F4h],1
0x77b4cd: call 0060D680h
0x77b4d2: pop ecx
0x77b4d3: ret
````

`sub_77b4c0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_60d680 (1 callees).

### sub_77b4e0 at 0x77b4e0 (5 instructions)

````text
0x77b4e0: push ecx
0x77b4e1: mov byte ptr ds:[8748F5h],1
0x77b4e8: call 00610C30h
0x77b4ed: pop ecx
0x77b4ee: ret
````

`sub_77b4e0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_610c30 (1 callees).

### sub_77b4f0 at 0x77b4f0 (7 instructions)

````text
0x77b4f0: push ecx
0x77b4f1: mov ecx,875DF0h
0x77b4f6: mov dword ptr ds:[875DF0h],7F66E4h
0x77b500: mov byte ptr ds:[8748F6h],1
0x77b507: call 006245B0h
0x77b50c: pop ecx
0x77b50d: ret
````

`sub_77b4f0` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_6245b0 (1 callees).

### sub_77b510 at 0x77b510 (29 instructions)

````text
0x63d070: push 0FFFFFFFFh
0x63d072: push 74A1F8h
0x63d077: mov eax,fs:[0]
0x63d07d: push eax
0x63d07e: push ecx
0x63d07f: mov eax,ds:[858220h]
0x63d084: xor eax,esp
0x63d086: push eax
0x63d087: lea eax,[esp+8]
0x63d08b: mov fs:[0],eax
0x63d091: mov dword ptr [esp+4],874D54h
0x63d099: mov dword ptr [esp+10h],0
0x63d0a1: mov ecx,ds:[874D78h]
0x63d0a7: test ecx,ecx
0x63d0a9: je short 0063D0B3h
0x63d0ab: mov eax,[ecx]
0x63d0ad: mov edx,[eax]
0x63d0af: push 1
0x63d0b1: call edx
0x63d0b3: mov ecx,874D54h
0x63d0b8: mov dword ptr [esp+10h],0FFFFFFFFh
0x63d0c0: call 0063D180h
0x63d0c5: mov ecx,[esp+8]
0x63d0c9: mov fs:[0],ecx
0x63d0d0: pop ecx
0x63d0d1: add esp,10h
0x63d0d4: ret
0x77b510: mov byte ptr ds:[8748F7h],1
0x77b517: jmp near ptr 0063D070h
````

`sub_77b510` has no recorded callers; it is likely reached through the vector table or an indirect jump. It delegates to sub_63d180 (1 callees).

### sub_77b520 at 0x77b520 (2 instructions)

````text
0x77b520: mov byte ptr ds:[8748F8h],1
0x77b527: ret
````

`sub_77b520` has no recorded callers; it is a leaf stub, likely reached through the vector table. It calls nothing else.

## Dynamic Analysis (Emulated)

Observed: the entry point was executed in a sandboxed, pure-software p-code interpreter. The target's own instructions ran without any native execution on the host, so this reflects the program's real behavior rather than its static form.

Derived: emulation from 0x65272f executed 18 instructions before stopping at 0x4501d8; an instruction could not be decoded.

## Packing and Obfuscation

Inferred: the target is not packed (score 0; threshold 3).

No packing signals fired.

## Methodology and Limitations

- Identified the format from file signatures and fingerprinted the file with MD5, SHA-1, and SHA-256.
- Parsed PE, ELF, and Mach-O headers, sections, imports, exports, symbols, and build metadata.
- Measured Shannon entropy for the file and every section.
- Extracted ASCII and UTF-16LE strings and classified network, path, registry, and command indicators.
- Classified imported APIs into capability categories and evaluated security mitigations from header fields.
- Disassembled x86/x86-64 with iced-x86 and every other supported architecture through an embedded SLEIGH engine, by recursive descent.
- Ranked functions by the capabilities and indicators they touch and listed the most relevant ones.

### Limitations

- Analysis is static: the target is never executed, so run-time behavior is inferred, not observed.
- Imports show what a program can call, not what it does; dynamically resolved APIs are invisible to import analysis.
- Disassembly covers code reachable from the entry point, exports, and symbols; indirect-only code may be missed.
- A few architectures are parsed but not yet disassembled; for those, code analysis is omitted.

