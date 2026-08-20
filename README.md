# Lydis

id: `com.septillioner.bsi.lydis`  
author: septillioner  
version: 0.1.1

Drop-in [BinarySectorInspector](https://github.com/candestan/BinarySectorInspector) plugin. Linear x86/x64 disassembly from the PE entry point or the hex cursor.

The decoder is [Zydis](https://github.com/zyantific/zydis) 4.1.0 amalgamated (`third_party/amalgamated-dist`). UI name, package id, and DLL are Lydis.

This repo is independent of the host tree. Core does not list plugin ids.

## Features

- Intel-syntax listing of x86 (`IMAGE_FILE_MACHINE_I386`) and x64 (`IMAGE_FILE_MACHINE_AMD64`)
- Start at the PE entry point or at the current hex cursor
- Click a line to select the instruction bytes in the hex view
- Copy the listing to the clipboard
- Settings for instruction count (32–512) and optional raw bytes

Other architectures are rejected. There is no control-flow graph, no recursive descent, and no analysis beyond a linear decode.

## Install

Copy `lydis.dll` into `{BinarySectorInspector.exe}/plugins/` (or a one-level subfolder). Restart the host, or use Settings → Plugins → rescan.

The host loads any DLL that exports `BsiPluginGetInfo`. Optional `tool.json` next to the DLL fills in the Settings card if you want it.

## Build (VS 2022, x64)

Open `Lydis.sln`. Configurations: `Debug|x64`, `Release|x64`.

Output: `lydis.dll`.

A post-build step copies the DLL into the host `{exe}/plugins/` folder when a BinarySectorInspector tree is found:

- sibling `../BinarySectorInspector/`
- `../../Ege/Sources/BinarySectorInspector/` (Desktop\Projects next to Desktop\Ege\Sources)

Otherwise copy `lydis.dll` yourself.

Requires Visual Studio 2022 (toolset v143) and the Windows 10 SDK. No other dependencies: Zydis is compiled from the amalgamated sources in this repo.

```bat
msbuild Lydis.sln /p:Configuration=Release /p:Platform=x64
```

## Usage

Open a PE in BinarySectorInspector. Lydis adds:

| Where | Action |
| --- | --- |
| Tools → Lydis → Disassemble at entry | Decode from `AddressOfEntryPoint` |
| Tools → Lydis → Disassemble at hex | Decode from the hex cursor |
| Inspector → Disassembly | Listing view: **From entry**, **From hex**, **Copy listing** |

Clicking a listing line selects that instruction in the hex view. Opening or closing a job clears the listing.

## Settings

Settings → Plugins → Lydis:

| Key | Default | Range |
| --- | --- | --- |
| `max_insn` | 128 | 32–512 |
| `show_bytes` | on | on/off |

Stored by the host as `plugin.cfg.com.septillioner.bsi.lydis.*`. Changing the plugin id orphans those keys.

## Layout

```
include/bsi_plugin.h          BSI Plugin SDK (copy; keep in lockstep with host sdk/plugin/)
src/plugin.cpp                Host glue, tools, view, settings
src/disasm.cpp                Zydis linear decode
third_party/amalgamated-dist  Zydis 4.1.0 (Zydis.h / Zydis.c)
tool.json                     Optional Settings card metadata
```

Do not include BinarySectorInspector `src/`. Do not link ImGui or the host.

## License

Lydis is under the [Attribution-NonSale License](LICENSE). Zydis remains MIT; see `third_party/amalgamated-dist/NOTICE.txt`.
