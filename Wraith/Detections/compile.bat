@ECHO OFF

csc.exe /out:PPIDetector.exe /platform:anycpu PPIDetector.cs /target:exe /noconfig /unsafe- /optimize- /nostdlib+ /reference:C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorlib.dll /reference:C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.dll /reference:C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Net.dll /reference:C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Linq.dll /reference:C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Windows.Forms.dll /reference:Microsoft.Diagnostics.Tracing.TraceEvent.dll
