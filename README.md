# ASLR_disabler
Disables ASLR flag IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE in IMAGE_OPTIONAL_HEADER on pre-compiled EXE. Works for both 32 and 64 bit Windows EXE/PE images

This software hacks the EXE to disable ASLR for major security breach of the exe by forcing fixed image base
and therefore be used by software engineer to develop e.g. function hijacking. This is part of PE:
WORD                 DllCharacteristics in IMAGE_OPTIONAL_HEADER, flag: IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)
Take a note about ImageBase (line 52 and 60) and debugger to modify the ImageBase if it's set to conflict with Launcher/any other app that is in the same assembly
