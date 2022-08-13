# Kernel34
Optimization software intended for use with Growtopia

## Why?
Growtopia tends to consume lots of CPU power while idle. Thus, it could to give the CPU some more time by sleeping.

## Usage
You have to patch Growtopia to load kernel34.dll instead of kernel32.dll by using this handy find & replace one-liner in Powershell:
```powershell
[IO.File]::WriteAllText("$Env:localappdata\Growtopia\Growtopia-Kernel34.exe", [IO.File]::ReadAllText("$Env:localappdata\Growtopia\Growtopia.exe",[Text.Encoding]::GetEncoding("iso-8859-1")).Replace("kernel32","kernel34").Replace("Kernel32","Kernel34").Replace("KERNEL32","KERNEL34"),[Text.Encoding]::GetEncoding("iso-8859-1"))
```
The project is maintained as a Visual Studio 2022 project. It should be pretty easy to get up and running.
If any issues arise, please let me know.

## Credits
- pannenkoek2012 on the Growtopia forums for figuring out the cause of the bug.
- Kristoffer Blasiak for automating the process of generating a Proxy DLL

## Sources 
- https://www.growtopiagame.com/forums/forum/problems/bugs-glitches/7136549-how-to-make-growtopia-not-use-so-much-cpu-in-a-few-easy-steps
- https://www.codeproject.com/Articles/1179147/ProxiFy-Automatic-Proxy-DLL-Generation
