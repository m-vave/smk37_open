# SPDX-License-Identifier: GPL-3.0-only WITH GPL-3.0-linking-exception
[CmdletBinding()]
param(
    [switch]$Package,
    [ValidateSet("pro","elite")][string]$Model = "pro",
    [switch]$FirmwareOnly,
    [string]$Toolchain = $env:FM1_PI32_TOOLCHAIN,
    [string]$SourceUrl = $env:FM1_SOURCE_URL
)
$ErrorActionPreference = 'Stop'
if ($FirmwareOnly -and $Package) { throw 'Choose -FirmwareOnly for local hardware tests or -Package for distribution, not both.' }
$Profile = $Model
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sdk = $PSScriptRoot
$build = Join-Path $root "build/$Profile"
$official = Join-Path $root "build/official-web/$Model"
$utf8 = New-Object Text.UTF8Encoding $false
function Write-Text($file, $text) { [IO.File]::WriteAllText($file, $text, $utf8) }
function Run($program, [string[]]$arguments) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $program @arguments; $result = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
    if ($result -ne 0) { throw "$([IO.Path]::GetFileName($program)) failed ($result)" }
}
function Hash($file) { (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
function Hash-Text($text) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { (($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $algorithm.Dispose() }
}
function Test-Firmware {
    # Inspect the linked image. Keep these checks independent of feature flags.
    $elf = Join-Path $build 'sdk.elf'
    $report = Join-Path $build 'firmware-report.json'
    Write-Text $report '{"passed":false}'
    $symbols = & (Join-Path $bin 'llvm-nm.exe') --print-size $elf
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect ELF symbols.' }
    $info = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $heap = [ordered]@{}
    $usbMidi = $false
    foreach ($line in $symbols) {
        if ($line -cmatch '^([0-9a-fA-F]+)[ \t]+(([0-9a-fA-F]+)[ \t]+)?([A-Za-z])[ \t]+([^\r]+)') {
            $name = $Matches[5]
            $address = [Convert]::ToInt64($Matches[1],16)
            $size = if ($Matches[3]) { [Convert]::ToInt64($Matches[3],16) } else { $null }
            $kind = $Matches[4]
            $info[$name] = [pscustomobject]@{address=$address; size=$size; kind=$kind}
            if ($name -cmatch '^(__fat_|fat_sdfile_fat_ops$|jl_fat_vfs_ops$|nor_sdfile_vfs_ops$|sdfile_ext_vfs_ops$)') {
                throw "Unused filesystem entered the fixed Flash runtime: $name"
            }
            if ($name -cmatch 'HEAP' -or ($name -cmatch 'heap' -and $kind -ceq 'A')) { $heap[$name] = $address }
            if ($name -cmatch '^lv_') {
                throw "Unexpected LVGL runtime: $name"
            }
            if ($name -cmatch 'usb.*midi|midi.*usb') { $usbMidi = $true }
        }
    }
    # Table entries are discovered by ranges, so native archives must retain them.
    $registrations = @(
        @('initcall',4,4), @('early_initcall',16,4), @('late_initcall',4,4),
        @('platform_initcall',4,4), @('module_initcall',4,4), @('sys_event_handler',12,12),
        @('syscfg_ops',84,28), @('lp_target',72,8), @('sys_cpu_timer',16,16),
        @('clock_critical_handler',16,8), @('vfs_ops',120,120)
    )
    $registrations += @(@('audio_decoder',56,56), @('audio_hwaccel',32,32))
    foreach ($rule in $registrations) {
        $name = $rule[0]
        $begin = "_${name}_begin"; $end = "_${name}_end"
        if (!$info.ContainsKey($begin) -or !$info.ContainsKey($end)) { $begin = "${name}_begin"; $end = "${name}_end" }
        if (!$info.ContainsKey($begin) -or !$info.ContainsKey($end)) { throw "Runtime registration range missing: $name" }
        $size = $info[$end].address - $info[$begin].address
        if ($size -lt $rule[1] -or $size % $rule[2]) { throw "Runtime registration table invalid: $name" }
        if ($name -ceq 'vfs_ops' -and $size -ne 120) { throw 'Expected only the internal Flash filesystem registration.' }
    }
    $required = @('fm1_r_7919135c9963','fm1_r_1f449c2c7b8f','vSoftwareInterruptISR','fm1_r_e7d3da61dac2','fm1_r_1993f9b103e3','fm1_r_05431712fb7b',
        'fm1_update_init','fm1_update_message','fm1_update_busy','fm1_build_id','fm1_flash_init',
        'sdfile_vfs_ops','sdfile_init','syscfg_vm_init','syscfg_btif_init',
        'wifi_get_xosc','wifi_get_mcs_dgain','wifi_get_pa_trim_data',
        'connectivity_wl82_bluetooth_start','ble_profile_init','att_server_init',
        'fm1_ble_set_role','fm1_ble_scan','fm1_ble_connect','fm1_ble_disconnect','fm1_ble_get_status','fm1_ble_get_device',
        'audio_app_usb_microphone_enable','audio_app_usb_speaker_enable',
        'connectivity_audio_usb_microphone_enable','connectivity_audio_usb_speaker_enable')
    $required += @('audio_app_bluetooth_open','sbc_decoder','sbc_hwaccel','avdtp_packet_handler','bt_get_local_name','bt_get_mac_addr',
        'fm1_bluetooth_configure','fm1_bluetooth_get_status',
        'groove_tuning_capture','groove_tuning_apply','groove_project_apply_edit')
    foreach ($name in $required) { if (!$info.ContainsKey($name)) { throw "Required runtime symbol absent: $name" } }
    # Incoming connections also work with inert client stubs. Require the
    # fixed SDK's real discovery paths for A2DP reconnect and BLE HOST.
    foreach ($name in @('sdp_send_cmd_iotl','sdp_master_packet_handler','gatt_client_discover_primary_services_by_uuid128')) {
        if (!$info.ContainsKey($name) -or $info[$name].kind -cnotin @('T','t','N','n') -or $info[$name].size -le 16) {
            throw "Bluetooth discovery implementation missing or stubbed: $name"
        }
    }
    # The instrument and UI must retain their real callbacks.
    foreach ($name in @('fm1_r_dee1ea411566','fm1_r_d16405f329ed','fm1_r_f03cc16d330d','fm1_r_1993f9b103e3',
            'fm1_io_trs_midi_enabled','fm1_r_05431712fb7b','fm1_r_0aa010fe1de1','fm1_r_33d5e5b63b6b','fm1_app_sysex')) {
        # This vendor nm prints SRAM-section functions as N, Flash text as T.
        if (!$info.ContainsKey($name) -or $info[$name].kind -cnotin @('T','N','t','n') -or !$info[$name].size) {
            throw "Application callback was lost or replaced by a weak default: $name"
        }
    }
    if ($info['fm1_build_id'].size -ne 32) { throw 'Browser update build identity must be exactly 32 bytes.' }
    if ($info['fm1_update_identity'].size -ne 27) { throw 'SMK37 update identity must be exactly 27 bytes.' }
    if (!$usbMidi) { throw 'USB MIDI runtime is missing.' }
    # Check the fixed platform ABI.
    foreach ($name in @('CurrentTCB','highCurrentTCB','xIdleTaskHandle')) {
        if (!$info.ContainsKey($name) -or $info[$name].size -ne 4) { throw "Platform RTOS ABI is invalid: $name" }
    }
    foreach ($name in @('__rt_local_irq_disable','__rt_local_irq_enable','bt_lock_cnt',
        'fm1_r_83b2de623a96','fm1_r_c327ea18da09','cpuSuspend','audio_app_worker','edr_name','ble_name',
        'a2dp_source_event_handler','a2dp_source_sbc_codec','hfp_profile_init','hfp_ag_profile_init',
        'spp_user_send_data','avrcp_player_event','hid_diy_regiest_callback','obex_connection_req',
        'pan_cmd_io_ctrl','gatt_client_discover_primary_services','ancs_client_init','ams_client_init',
        'sdio_host_init','wl30_sdio_claim_irq','wl30_sdio_release_irq','wifi_on','wifi_off',
        'wifi_rx_task','wifi_tx_task','ui_yuv420_to_rgb565_pairs','ui_tiny_ttf_pack_scanline')) {
        if ($info.ContainsKey($name)) { throw "Unsupported platform runtime entered SMK37: $name" }
    }
    $map = [IO.File]::ReadAllText((Join-Path $build 'sdk.map'))
    if (!$map.Contains($variant.frozen + '(')) { throw 'Fixed native SDK archive missing.' }
    if ($map.Contains('libfm1_runtime.a(')) { throw 'Only the fixed music/BLE SDK may be linked.' }
    foreach ($input in @('/system.a(','audio_server.a(','media_app.a(','btstack.a(','lib_ui.a(','libjpeg_decode_only.a(')) {
        if ($map.Contains($input)) { throw "Unsupported SMK37 link input: $input" }
    }
    foreach ($member in @('a2dp_source','ams_client','ancs_client','avctp','avrcp','bip','bnep','bt_audio',
        'client_user','hfp_ag_profile','hfp_profile','hid','iap_profile','obex','opp','pan',
        'pbg_profile','rfcomm','spp_profile','spp_update_profile','spp_user','vCard')) {
        if ($map.Contains(".a(${member}.c.o)")) { throw "Unsupported SMK37 link member: $member" }
    }
    $acl = @{}
    foreach ($direction in @('tx','rx')) {
        $begin = "acl_${direction}_pool"; $end = "${begin}_end"
        if (!$info.ContainsKey($begin) -or !$info.ContainsKey($end)) { throw "Required controller pool missing: $begin" }
        $acl[$direction] = $info[$end].address - $info[$begin].address
    }
    if ($acl.tx -lt 1024 -or $acl.rx -lt 4096) { throw 'Classic ACL pools too small; need 1024/4096 bytes.' }
    if ($map -cnotmatch '0x([0-9a-fA-F]+)[^\r\n]*_MALLOC_SIZE[ ]*=') { throw 'Cannot find runtime heap in link map.' }
    $heapBytes = [Convert]::ToInt64($Matches[1],16)
    if ($heapBytes -lt 49152) { throw "SMK37 runtime heap is $heapBytes bytes; need at least 49152." }
    $callbacks = @('fm1_r_e7d3da61dac2','fm1_r_1993f9b103e3','fm1_r_05431712fb7b','fm1_r_ffe3f82683f6','fm1_audio_irq','fm1_flash_worker_prepare',
        'fm1_r_7e12ed19990d','fm1_r_74310ca1fed9',
        'fm1_engine_render','fm1_engine_output_level','fm1_audio_copy','fm1_output_mix',
        'fm1_usb_audio_read','fm1_bluetooth_audio_read','fm1_usb_audio_write','connectivity_audio_get_speaker_volume','connectivity_audio_get_mic_volume') + @($extra)

    foreach ($name in @($synth.sram_optional) + @($synth.native_sram_optional)) {
        if ($info.ContainsKey($name)) { $callbacks += $name }
    }
    $callbacks += @('cpu_enter_sfc_critical','cpu_exit_sfc_critical','enter_spi_code','exit_spi_code','fm1_r_da3931a5b7a8','sfc_drop_cache')
    # Optional retained transport helpers also have to reside in SRAM.

    # emu2149 helpers can inline into the mandatory psg_* SRAM callbacks.
    foreach ($name in @('audio_app_usb_mix','audio_app_usb_record','audio_app_usb_replace_input',
        'render_stereo','effects_render','effects_sample','sequence_event','clock_publish',
        'groove_arp_event','groove_arp_running','engine_note')) {
        if ($info.ContainsKey($name)) { $callbacks += $name }
    }
    $engineReady = $info.ContainsKey('fm1_r_0aa010fe1de1') -and $info['fm1_r_0aa010fe1de1'].address -gt 0
    if ($engineReady) {
        $callbacks += 'fm1_r_0aa010fe1de1'
        if ($info.ContainsKey('fm1_r_33d5e5b63b6b') -and $info['fm1_r_33d5e5b63b6b'].address -gt 0) { $callbacks += 'fm1_r_33d5e5b63b6b' }
    }
    foreach ($name in $callbacks) {
        if (!$info.ContainsKey($name)) { throw "Audio callback absent: $name" }
        if ($info[$name].address -lt 0x01c00000 -or $info[$name].address -ge 0x01c80000) { throw "Audio callback is outside internal SRAM: $name" }
    }
    foreach ($name in @('scan_isr','scan_soft_isr','smk37_adc_irq','key_scan','encoder_scan','pad_prc','keymap','encodermap','encoder_delta','pad_velocity','smk37_pad_history_step')) {
        if (!$info.ContainsKey($name) -or $info[$name].address -lt 0x01c00000 -or $info[$name].address -ge 0x01c80000) {
            throw "Panel scan code or wiring table is outside internal SRAM: $name"
        }
    }
    $bytes = [IO.File]::ReadAllBytes($elf)
    function Check-Range([long]$offset,[long]$count) {
        if ($offset -lt 0 -or $count -lt 0 -or $offset -gt $bytes.LongLength -or $count -gt $bytes.LongLength - $offset) { throw 'Truncated ELF.' }
    }
    function Read-U16([long]$offset) { Check-Range $offset 2; [BitConverter]::ToUInt16($bytes,$offset) }
    function Read-U32([long]$offset) { Check-Range $offset 4; [BitConverter]::ToUInt32($bytes,$offset) }
    Check-Range 0 52
    if (($bytes[0..5] -join ',') -ne '127,69,76,70,1,1') { throw 'Expected ELF32 little endian.' }
    $entry = Read-U32 24
    if ($entry -ne 0x02000120 -or !$info.ContainsKey('_start') -or
        $info['_start'].address -ne $entry -or !$info.ContainsKey('_text_rodata_begin') -or
        $info['_text_rodata_begin'].address -ne $entry) {
        throw 'Firmware startup must match the fixed ROM entry and the first packaged instruction.'
    }
    $table = Read-U32 32; $stride = Read-U16 46; $count = Read-U16 48; $stringsIndex = Read-U16 50
    if ($stride -lt 40 -or !$count -or $stringsIndex -ge $count) { throw 'Invalid ELF section table.' }
    Check-Range $table ([long]$stride * $count)
    $stringsHeader = $table + [long]$stringsIndex * $stride
    $stringsOffset = Read-U32 ($stringsHeader + 16); $stringsBytes = Read-U32 ($stringsHeader + 20)
    Check-Range $stringsOffset $stringsBytes
    $sections = New-Object 'Collections.Generic.List[object]'
    [long]$payload = 0; [long]$appImage = 0
    for ($i=0; $i -lt $count; ++$i) {
        $header = $table + [long]$i * $stride
        $nameOffset = Read-U32 $header; $type = Read-U32 ($header+4); $flags = Read-U32 ($header+8)
        $address = Read-U32 ($header+12); $offset = Read-U32 ($header+16); $size = Read-U32 ($header+20)
        if ($type -ne 8) { Check-Range $offset $size }
        if (!($flags -band 2) -or !$size) { continue }
        if ($nameOffset -ge $stringsBytes) { throw 'ELF section name is outside string table.' }
        $start = [long]$stringsOffset + $nameOffset; $end = $start
        while ($end -lt [long]$stringsOffset + $stringsBytes -and $bytes[$end]) { ++$end }
        if ($end -ge [long]$stringsOffset + $stringsBytes) { throw 'Unterminated ELF section name.' }
        $name = [Text.Encoding]::ASCII.GetString($bytes,$start,$end-$start)
        if ($name -cnotmatch '^\.(text|data|bss|ram0_data|ram0_bss|boot_info|cache_ram_data|cache_ram_bss)$') {
            throw "Unsupported allocated section: $name"
        }
        $nobits = $type -eq 8
        if (!$nobits) {
            $payload += $size
            if ($name -cmatch '^\.(text|data|ram0_data|cache_ram_data)$') { $appImage += $size }
            elseif ($name -cne '.boot_info') { throw "Allocated section is not covered by SMK37 packaging: $name" }
        }
        $sections.Add([ordered]@{name=$name; address=$address; bytes=$size; nobits=$nobits})
    }
    $result = [ordered]@{passed=$true; elf_sha256=(Hash $elf); allocated_image_bytes=$payload; app_image_bytes=$appImage;
        startup_entry_verified=$true; startup_entry=$entry;
        instrument_ready=$engineReady; image_definition='Sum of ELF allocated non-NOBITS sections; excludes bootloader/filesystem packaging';
        sections=@($sections.ToArray()); heap_symbols=$heap; runtime_heap_bytes=$heapBytes; minimum_runtime_heap_bytes=49152;
        classic_acl_tx_bytes=$acl.tx; classic_acl_rx_bytes=$acl.rx; registration_tables_verified=$true; rtos_abi_verified=$true;
        audio_callbacks_in_sram=$true; extra_audio_symbols_in_sram=@($extra); bluetooth_and_usb_midi_linked=$true;
        usb_audio_playback_and_capture_linked=$true; bluetooth_audio_absent=$false; ble_roles='peripheral/central'; lvgl_absent=$true;
        active_bluetooth_discovery_linked=$true;
        application_callbacks_verified=$true; board_validation='not performed'}
    Write-Text $report ($result | ConvertTo-Json -Depth 6)
    Write-Host "FM1: $appImage bytes app image; SRAM/BLE/USB checks passed"
}

function Package-Firmware {
    $generated = Join-Path $build 'generated'
    $elf = Join-Path $build 'sdk.elf'
    $before = Hash $elf
    $output = Join-Path $generated ('SMK37_'+$Model.ToUpperInvariant()+'_OPEN.fwsc')
    $complete = $false
    Push-Location -LiteralPath $generated
    try {
        if ([BitConverter]::ToUInt32([IO.File]::ReadAllBytes($elf),24) -ne 0x02000120) {
            throw 'Package entry must match the verified SMK37 firmware entry.'
        }
        $image = New-Object IO.MemoryStream
        try {
            foreach ($section in @('text','data','ram0_data','cache_ram_data')) {
                Run (Join-Path $bin 'llvm-objcopy.exe') @('-O','binary','-j',(".$section"),$elf,("$section.bin"))
                $bytes = [IO.File]::ReadAllBytes((Join-Path $generated "$section.bin"))
                $image.Write($bytes,0,$bytes.Length)
            }
            Add-Type -Path (Join-Path $sdk 'Package.cs')
            $layout = [FM1.Package]::Create($image.ToArray(),(Join-Path $sdk 'tools/pack'),$output,$variant.user_bytes,$firmwareProduct)
        } finally { $image.Dispose() }
        if (!(Test-Path -LiteralPath $output) -or (Hash $elf) -ne $before) {
            throw 'Firmware packaging did not produce a matching image.'
        }
        Write-Text (Join-Path $build 'package-report.json') ($layout | ConvertTo-Json)
        Write-Host "Offline package fits 1 MiB: image $($layout.FLASH_BIN_SIZE), VM $($layout.VM_REAL_SIZE), user $($layout.user_bytes) bytes"
        $complete = $true
    } finally {
        foreach ($name in @('text.bin','data.bin','ram0_data.bin','cache_ram_data.bin')) {
            if (Test-Path -LiteralPath $name) { Remove-Item -LiteralPath $name }
        }
        if (!$complete -and (Test-Path -LiteralPath $output)) { Remove-Item -LiteralPath $output }
        Pop-Location
    }
}
# Invalidate stale successful output before validating build inputs.
[IO.Directory]::CreateDirectory($build) | Out-Null
Write-Text (Join-Path $build 'firmware-report.json') '{"passed":false}'
Write-Text (Join-Path $build 'package-report.json') '{"board_access":false,"fits":false}'
Write-Text (Join-Path $build 'web-package-report.json') '{"integrated":false,"board_access":false}'
foreach ($name in @('sdk.elf','sdk.map','build-identity.json',
        'compile_commands.json','link-arguments.json')) {
    $oldWeb = Join-Path $build $name
    if ([IO.File]::Exists($oldWeb)) { [IO.File]::Delete($oldWeb) }
}
$oldChecksum = Join-Path $official 'SHA256SUMS.txt'
if ([IO.File]::Exists($oldChecksum)) { [IO.File]::Delete($oldChecksum) }
$oldWeb = Join-Path $official 'SMK37-Open-Source.html'
if (Test-Path -LiteralPath $oldWeb) {
    Write-Text $oldWeb '<!doctype html><meta charset="utf-8"><title>SMK37 OPEN</title><p>Build incomplete. Run build.bat --package successfully before distributing this page.</p>'
}
foreach ($name in @(('SMK37_'+$Model.ToUpperInvariant()+'_OPEN.fwsc'),('SMK37_'+$Model.ToUpperInvariant()+'_OPEN.fw'))) {
    $oldPackage = Join-Path $build "generated/$name"
    if (Test-Path -LiteralPath $oldPackage) { Remove-Item -LiteralPath $oldPackage }
}
if ($Package) {
    $sourceUri = $null
    if ([string]::IsNullOrWhiteSpace($SourceUrl) -or
        ![Uri]::TryCreate($SourceUrl, [UriKind]::Absolute, [ref]$sourceUri) -or
        $sourceUri.Scheme -cne 'https' -or $sourceUri.UserInfo -or $SourceUrl -match '[\r\n]') {
        throw 'Set FM1_SOURCE_URL or -SourceUrl to the HTTPS URL of the matching source archive, without credentials.'
    }
}
$versionHeader = [IO.File]::ReadAllText((Join-Path $root 'app/version.h'))
$versionMatch = [regex]::Match($versionHeader, '(?m)^#define FM1_RELEASE_VERSION "(V(?:0[1-9]|[1-9][0-9]{1,2}))"\s*$')
if (!$versionMatch.Success) { throw 'Set FM1_RELEASE_VERSION in app/version.h.' }
$releaseVersion = $versionMatch.Groups[1].Value
$productPrefix = if ($Model -eq 'pro') { 'SMK-37 Pro_' } else { 'SMK-37 Elite_' }
$productMacro = 'FM1_UPDATE_PRODUCT_' + $Model.ToUpperInvariant()
$productMatch = [regex]::Match($versionHeader, '(?m)^#define ' + $productMacro + ' "(' + [regex]::Escape($productPrefix) + '8[0-9]{6})"\s*$')
if (!$productMatch.Success) { throw "Set a compatible $productMacro in app/version.h." }
$firmwareProduct = $productMatch.Groups[1].Value
if ($firmwareProduct -cne ($productPrefix + (8000000 + [int]$releaseVersion.Substring(1)))) {
    throw 'The model update identity and FM1_RELEASE_VERSION must name the same release.'
}
Write-Host "Build SMK37 Open $releaseVersion"
if (!$Toolchain) { $Toolchain = Join-Path $sdk 'tools' }
$Toolchain = [IO.Path]::GetFullPath($Toolchain)
if (Test-Path -LiteralPath (Join-Path $Toolchain 'clang.exe')) { $Toolchain = Split-Path -Parent $Toolchain }
$bin = Join-Path $Toolchain 'bin'
if (!(Test-Path -LiteralPath (Join-Path $bin 'clang.exe'))) { throw 'Install JieLi Windows toolchain 2.5.3 (PI32v2 clang 4.0.1, r3 target) and set FM1_PI32_TOOLCHAIN to its pi32 directory containing bin/clang.exe. See README.md for the versioned download.' }
# Verify the matching SDK and toolchain before compiling APP.
$manifest = Get-Content -LiteralPath (Join-Path $sdk 'manifest.json') -Encoding UTF8 -Raw | ConvertFrom-Json
if ($manifest.abi -ne 131072) { throw 'This application requires the matching 128-frame SDK.' }
if ($manifest.external_toolchain) {
    if ($manifest.external_toolchain.schema -ne 1 -or !$manifest.external_toolchain.files) { throw 'Invalid external toolchain manifest.' }
    foreach ($required in @('bin/clang.exe','bin/pi32v2-ld.exe','bin/LLVMgold.dll','bin/llvm-nm.exe','bin/llvm-objcopy.exe')) {
        if (!$manifest.external_toolchain.files.PSObject.Properties[$required]) { throw "Missing toolchain contract: $required" }
    }
    foreach ($entry in $manifest.external_toolchain.files.PSObject.Properties) {
        $name = $entry.Name
        if ($name -cnotmatch '^(bin|lib)/[A-Za-z0-9_./-]+$' -or $name.Split('/') -contains '..' -or $entry.Value -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid external toolchain entry.' }
        $file = Join-Path $Toolchain $name
        if (!(Test-Path -LiteralPath $file) -or (Hash $file) -cne $entry.Value) { throw "External toolchain does not match the SDK: $name. This SDK revision requires JieLi Windows toolchain 2.5.3. Set FM1_PI32_TOOLCHAIN to its pi32 directory. Update the complete source + SDK kit together; see README.md for the versioned download." }
    }
}
$synth = Get-Content -LiteralPath (Join-Path $sdk 'synth.json') -Encoding UTF8 -Raw | ConvertFrom-Json
if ($synth.schema -ne 4 -or $synth.api -ne 8 -or $synth.kernel_abi -ne 3 -or $synth.block_frames -ne 128 -or $synth.sample_rate -ne 44100 -or
    $synth.pi32_compiler_sha256 -cne $manifest.external_toolchain.files.'bin/clang.exe' -or
    $synth.sdk_block_sha256 -cne (Hash (Join-Path $sdk 'include/fm1_block.h')) -or
    $synth.native_sha256 -cne (Hash (Join-Path $sdk 'lib/libfm1_engine.a'))) {
    throw 'Native DSP kernels and SDK audio contracts do not match. Install a matching SDK package.'
}
if ([IO.File]::ReadAllText((Join-Path $root 'app/synth/engine.h')) -cnotmatch '(?m)^#define FM1_DSP_ABI 3U\s*$') { throw 'Unsupported native DSP ABI.' }
foreach ($entry in $synth.portable_contracts.PSObject.Properties) {
    if ($entry.Name -cnotmatch '^[A-Za-z0-9_]+\.inc$' -or $entry.Value -cne (Hash (Join-Path $root ('app/synth/'+$entry.Name)))) {
        throw 'Fixed DSP coefficients differ from the native kernels. Matching kernels are required for this coefficient change.'
    }
}
if (@($synth.sram_required).Count -eq 0 -or @($synth.sram_optional).Count -eq 0) { throw 'Native DSP SRAM contract is missing.' }
foreach ($name in @($synth.sram_required) + @($synth.sram_optional)) {
    if ($name -cnotmatch '^[A-Za-z_][\w.$]*$') { throw 'Invalid DSP SRAM symbol.' }
}
foreach ($file in $manifest.files.PSObject.Properties) {
    $full = [IO.Path]::GetFullPath((Join-Path $root $file.Name))
    if (!$full.StartsWith($sdk + '\', [StringComparison]::OrdinalIgnoreCase) -or
        ((Hash $full) -ne $file.Value -and $file.Name -ne 'sdk/Build.ps1')) { throw "SDK payload changed: $($file.Name)" }
}
$expected = @{}
foreach ($file in $manifest.files.PSObject.Properties) { $expected[$file.Name] = $true }
foreach ($file in Get-ChildItem -LiteralPath $sdk -Recurse -Force -File) {
    $relative = $file.FullName.Substring($root.Length + 1).Replace('\','/')
    if ($relative -ne 'sdk/manifest.json' -and !$expected.ContainsKey($relative)) {
        throw "Unexpected SDK file: $relative"
    }
}
$variantName = 'release'
$variant = [pscustomobject]@{user_bytes=536576; frozen='sdk/lib/libfm1_engine.a'; update_family=$(if ($Model -eq 'pro') { 8 } else { 9 })}
$include = @('sdk/include','sdk/include/libc','app/synth','sdk/config','app','app/board')
$sources = @(Get-ChildItem -LiteralPath (Join-Path $root 'app') -Recurse -File |
    Where-Object { $_.Extension -in @('.c','.S') -and !$_.FullName.StartsWith(([IO.Path]::GetFullPath((Join-Path $root 'app/synth'))+'\'),[StringComparison]::OrdinalIgnoreCase) } | Sort-Object FullName | ForEach-Object { $_.FullName.Substring($root.Length+1).Replace('\','/') })
$extra = @('groove_sequence_render','groove_sequence_clock','groove_sequence_position','groove_sequence_transport','fm1_sea_decode_groups','fm1_codec_sea_mono_s16_run') + @($synth.sram_required) + @(
    'synth_dx7_render','synth_dx7_midi','synth_dx7_key','fm1_dx7_panic','fm_exp2_fixed','bass303_bank_render','bass303_bank_key','bass303_bank_set','drum808_kit_render','drum808_kit_trigger','psg_render','psg_key','psg_midi','psg_panic','psg_set','psg_get','pluck_render','pluck_key','pluck_midi','pluck_panic','pluck_set','pluck_get','fm1_mix128','fm1_mix_mono_stereo128','fm1_bus_output128','fm1_master_mix128','fm1_master_gain','fm1_declick128','fm1_render_begin','fm1_render_end','synth_dx7_active','bass303_bank_active','drum808_kit_active','psg_active','pluck_active','sampledrum_active','synth_dx7_limit','psg_limit','pluck_limit','sampledrum_limit','bass303_advance_idle','fm1_send128','fm1_fx_render','fm1_fx_clear','fm1_fx_active','sampledrum_render','sampledrum_trigger','sampledrum_panic','psg_active_chips')
[IO.Directory]::CreateDirectory((Join-Path $build 'obj')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $build 'generated')) | Out-Null
# All application units are rebuilt. Remove objects for deleted/renamed sources.
$objectDirectory = [IO.Path]::GetFullPath((Join-Path $build 'obj'))
if (!$objectDirectory.StartsWith($root + '\build\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid object directory.' }
foreach ($file in Get-ChildItem -LiteralPath $objectDirectory -File) { Remove-Item -LiteralPath $file.FullName }
$flags = @('-target','pi32v2','-integrated-as','-mcpu=r3','-mfprev1','-Wuninitialized',
    '-Wno-invalid-noreturn','-fno-common','-flto','-fallow-pointer-null','-fprefer-gnu-section',
    '-femulated-tls','-Wno-shift-negative-value','-Wframe-larger-than=2560','-fms-extensions',
    '-fno-unwind-tables','-ffunction-sections','-fdata-sections','-fmessage-length=0',
    '-cl-single-precision-constant','-mllvm','-pi32v2-large-program=true','-D__GCC_PI32V2__','-O2')
$flags += '-DSMK37_MODEL_' + $Model.ToUpperInvariant() + '=1'
foreach ($dir in $include) { $flags += '-I' + (Join-Path $root $dir) }
$objects = @()
$commands = @()
Push-Location -LiteralPath $build
try {
    $objectIndex = 0
    foreach ($source in $sources) {
        $inputFile = Join-Path $root $source
        # The index keeps nested paths and non-ASCII names from colliding after sanitising.
        $output = 'obj/' + ($objectIndex++) + '_' + ($source -replace '[^a-zA-Z0-9._-]', '_') + '.obj'
        $options = @($flags)
        # This PI32 LTO plugin can discard application definitions when a
        # native SDK object has weak defaults. Keep user entry units native.
        if ($source -in @('app/screen.c','app/transfer.c','app/midi_router.c')) {
            $options += '-fno-lto'
        }
        if ($source -in @('app/board/panel.c','app/board/scan.c')) { $options += @('-fno-lto','-fno-pic') }
        $options += @('-fwrapv','-fno-fast-math','-ffp-contract=off')
        # Storage and screen run only from control; keep audio DSP on O2.
        if ($source -in @('app/project.c','app/transfer.c','app/samples.c','app/screen.c','app/presets.c','app/midi_router.c','app/smk37_controls.c','app/fm_library.c','app/fm_factory.c','app/board/panel.c','app/board/scan.c')) { $options += '-Oz' }
        $arguments = @($options) + @('-MMD','-MF',($output + '.d'),'-c',$inputFile,'-o',$output)
        Write-Host "Compile $source"
        Run (Join-Path $bin 'clang.exe') $arguments
        $objects += $output
        $commands += [ordered]@{directory=$build; file=$inputFile; output=(Join-Path $build $output); arguments=@((Join-Path $bin 'clang.exe')) + $arguments}
    }
    # The device reports this source/SDK build identity after a browser update.
    # It is distinct from the final package SHA-256 (which covers every byte).
    $identityInputs = @($Profile, (Hash (Join-Path $sdk 'manifest.json')))
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'app') -Recurse -File | Sort-Object FullName) {
        $identityInputs += $file.FullName.Substring($root.Length+1).Replace('\','/') + ':' + (Hash $file.FullName)
    }
    $buildIdentity = Hash-Text ($identityInputs -join "`n")
    $idBytes = for ($i=0; $i -lt 64; $i+=2) { '0x' + $buildIdentity.Substring($i,2) }
    if ($variant.update_family -notin @(8,9) -or $variant.user_bytes -lt 4096 -or $variant.user_bytes % 4096) {
        throw 'Invalid fixed firmware layout.'
    }
    $identitySource = '#include "layout.h"' + "`n" +
        'const struct fm1_firmware_layout fm1_layout = {' + $variant.user_bytes + 'U,' + $variant.update_family + 'U};' + "`n" +
        'const unsigned char fm1_build_id[32] = {' + ($idBytes -join ',') + '};' + "`n" +
        'const unsigned char fm1_update_identity[27] = "' + $firmwareProduct + '";' + "`n"
    Write-Text (Join-Path $build 'generated/build_identity.c') $identitySource
    Run (Join-Path $bin 'clang.exe') (@($flags) + @('-c','generated/build_identity.c','-o','obj/build_identity.obj'))
    $objects += 'obj/build_identity.obj'
    Write-Text (Join-Path $build 'build-identity.json') (@{profile=$Profile; family=$variantName; release_version=$releaseVersion; build_id=$buildIdentity} | ConvertTo-Json)
    $sbcRoot = 'sbc_decoder' + [char]10
    $aclTx = ' + 1024'
    $aclRx = ' + 4096'
    $linker = [IO.File]::ReadAllText((Join-Path $sdk 'config/linker.ld.in')).Replace('@SBC_DECODER@',$sbcRoot).Replace('@ACL_TX_EXTRA@',$aclTx).Replace('@ACL_RX_EXTRA@',$aclRx)
    Write-Text (Join-Path $build 'generated/linker') $linker
    $link = @('--plugin',(Join-Path $bin 'LLVMgold.dll'),'-o','sdk.elf') + $objects + @(
        '-flto','--plugin-opt=-pi32v2-always-use-itblock=false','--plugin-opt=-enable-ipra=true',
        '--plugin-opt=-pi32v2-merge-max-offset=4096','--plugin-opt=-pi32v2-enable-simd=true','--plugin-opt=mcpu=r3',
        '--plugin-opt=-global-merge-on-const','--plugin-opt=-inline-threshold=5','--plugin-opt=-inline-max-allocated-size=32',
        '--plugin-opt=-inline-normal-into-special-section=true','--plugin-opt=-dont-used-symbol-list=malloc,free,sprintf,printf,puts,putchar',
        '--plugin-opt=-pi32v2-enable-rep-memop','--plugin-opt=-emulated-tls','--sort-common',
        '--plugin-opt=-pi32v2-large-program=true','--plugin-opt=-pi32v2-csync-before-rti=true','--start-group',
        '--whole-archive',('../../' + $variant.frozen),'--no-whole-archive')
    $link += @('../../sdk/lib/libc.a','../../sdk/lib/libcompiler_rt.a')
    $link += @('--end-group','--gc-sections','-Tgenerated/linker','-M=sdk.map','--undefined=connectivity_wl82_bluetooth_start')
    $link += @('--undefined=audio_app_bluetooth_open','--undefined=bt_get_local_name','--undefined=bt_get_mac_addr')
    Write-Text (Join-Path $build 'compile_commands.json') (ConvertTo-Json -InputObject @($commands) -Depth 6)
    Write-Text (Join-Path $build 'link-arguments.json') ($link | ConvertTo-Json)
    Write-Host "Link $Profile using prebuilt SMK37 SDK"
    Run (Join-Path $bin 'pi32v2-ld.exe') $link
    Test-Firmware
    if ($FirmwareOnly) { Package-Firmware }
    if ($Package) {
        Package-Firmware
        $packageFile = Join-Path $build ('generated/SMK37_'+$Model.ToUpperInvariant()+'_OPEN.fwsc')
        $packageBytes = [IO.File]::ReadAllBytes($packageFile)
        $familyNumber = $variant.update_family
        $stockName = if ($Model -eq 'pro') { 'Pro' } else { 'Elite' }
        $stockFile = Join-Path $sdk ('firmware/SMK37-'+$stockName+'-V16.fwsc')
        $stockHash = if ($Model -eq 'pro') { '2d98ce72530e71d617384963423820536f094501299e2cfec0a8d3c3fb6bcfb0' } else { 'b2ee38abfef3ae922e4eecdb8a551e14345300ae6f270265feacd33b6ef99cb6' }
        if ((Hash $stockFile) -cne $stockHash) { throw 'Factory V016 firmware differs from the official M-VAVE download.' }
        $stockBytes = [IO.File]::ReadAllBytes($stockFile)
        $stock = [ordered]@{schema=1;kind='stock';product=('SMK-37 '+$stockName+'_016');model=$Model;
            profile=('SMK37 '+$stockName+' Original V16');family=$familyNumber;release_version='V16';
            build_id=$stockHash;sha256=$stockHash;bytes=$stockBytes.Length;
            loader_sha256='ef1f2db89b011fa53e71df363f0122de0ea896618c53fb53e8da676322004541';
            data=[Convert]::ToBase64String($stockBytes)}
        $webPackage = [ordered]@{schema=1; product=$firmwareProduct; profile=$Profile; family=$familyNumber; release_version=$releaseVersion;
            build_id=$buildIdentity; sha256=(Hash $packageFile); bytes=$packageBytes.Length;
            loader_sha256=(Hash (Join-Path $sdk 'tools/pack/ota.bin')); hardware_validated=$false;
            data=[Convert]::ToBase64String($packageBytes);model=$Model;stock=$stock} | ConvertTo-Json -Depth 4 -Compress
        $web = & (Join-Path $root 'tools/Build-Web.ps1') -PackageJson $webPackage -SourceUrl $SourceUrl
        Write-Text (Join-Path $build 'web-package-report.json') (@{integrated=$true; firmware_sha256=(Hash $packageFile);
            web_sha256=$web.sha256; release_version=$releaseVersion; build_id=$buildIdentity; simulator_sha256=$web.simulator_sha256;
            simulator_source_sha256=$web.simulator_source_sha256; simulator_bytes=$web.simulator_bytes;
            hardware_validated=$false; board_access=$false} | ConvertTo-Json)
    }
    Write-Host "Firmware: $build\sdk.elf"
} finally { Pop-Location }
