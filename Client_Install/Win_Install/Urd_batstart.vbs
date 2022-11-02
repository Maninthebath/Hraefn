Dim WinScriptHost
Set WinScriptHost = CreateObject("WScript.shell")
WinScriptHost.Run Chr(34) & "%LocalAppData%\Programs\Urdstart.bat" & Chr(34), 0
Set WinScriptHost = Nothing
