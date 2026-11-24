!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Registering vaultpass-cli in user PATH..."
  System::Call 'Kernel32::SetEnvironmentVariable(t "VAULTPASS_INSTDIR", t "$INSTDIR")'
  nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$dir = $$env:VAULTPASS_INSTDIR; if ($$dir) { $$trimmed = $$dir.TrimEnd('\'); $$cur = [Environment]::GetEnvironmentVariable('Path', 'User'); $$parts = @(if ($$cur) { $$cur -split ';' | Where-Object { $$_ -ne '' } }); if (-not ($$parts | Where-Object { $$_.TrimEnd('\') -ieq $$trimmed })) { [Environment]::SetEnvironmentVariable('Path', (($$parts + $$trimmed) -join ';'), 'User') } }"`
  Pop $0
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    DetailPrint "Removing vaultpass-cli from user PATH..."
    System::Call 'Kernel32::SetEnvironmentVariable(t "VAULTPASS_INSTDIR", t "$INSTDIR")'
    nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$dir = $$env:VAULTPASS_INSTDIR; if ($$dir) { $$trimmed = $$dir.TrimEnd('\'); $$cur = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($$cur) { $$next = @($$cur -split ';' | Where-Object { $$_ -ne '' -and $$_.TrimEnd('\') -ine $$trimmed }) -join ';'; [Environment]::SetEnvironmentVariable('Path', $$next, 'User') } }"`
    Pop $0
  ${EndIf}
!macroend
