@echo off
Title Perms && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Perms
for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        takeown /f %%d:\
        icacls %%d:\ /setowner "Administrators"
        icacls %%d:\ /grant:r "Users":RX
        icacls %%d:\ /grant:r "System":F
        icacls %%d:\ /grant:r "Administrators":F
        icacls %%d:\ /grant:r "Authenticated Users":M
        icacls %%d:\ /grant:r "Console Logon":M
        icacls %%d:\ /remove "Everyone"
    )
)
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:d /T /C
icacls "%SystemDrive%\Users\Public\Desktop" /remove "INTERACTIVE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "SERVICE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "BATCH"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "CREATOR OWNER"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "System"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Administrators"
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:d /T /C
icacls "%USERPROFILE%\Desktop" /remove "System"
icacls "%USERPROFILE%\Desktop" /remove "Administrators"
