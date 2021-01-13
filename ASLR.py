import struct

#By Marcin Gomulak (Maki)
# www.github.com/makipl
#
#	This software hacks the EXE to disable ASLR for major security breach of the exe by forcing fixed image base
#	and therefore be used by software engineer to develop e.g. function hijacking.




#CONFIGURE

filepath = "D3D8.dll"

#END OF CONFIGURE



f = open(filepath, 'rb+')
MZ = f.read(2)
if MZ != 'MZ':
	print('Not MZ/PE executable')
	exit()
f.seek(0x3c,0) # DOS_Header jump to e_lfanew
PEpointer = struct.unpack('=L', f.read(4))[0]
f.seek(PEpointer, 0)
PE = f.read(4)[:2]
if PE != 'PE':
	print('Broken PE pointer 0x3c or broken PE magic')
	exit()
Machine = struct.unpack('=H', f.read(2))[0]
bitMode = -1
if Machine == 0x014c:
	print('PE 32 bit')
	bitMode = 32
if Machine == 0x8664:
	print('PE 64 bit')
	bitMode = 64
f.seek(14, 1)
optHeaderSz = struct.unpack('=H', f.read(2))[0]
f.seek(6,1)
sizeOfCode = struct.unpack('=L', f.read(4))[0]
print('PE::CodeSize: ' + str(sizeOfCode))
#now it's bit system aware
f.seek(8,1)
entryPoint = struct.unpack('=L', f.read(4))[0]
print('entryPoint: ' + str(entryPoint))

if bitMode == 64:
	f.seek(4, 1)
	ImageBase = struct.unpack('=Q', f.read(8))[0]
	defaultImageBase = ' (Default)'
	if ImageBase != 0x140000000L:
		defaultImageBase = ' (NON DEFAULT! DEFAULT IS : 0x140000000)'
	print('ImageBase: ' + str(hex(ImageBase)) + defaultImageBase)
	
if bitMode == 32:
	f.seek(8, 1)
	ImageBase = struct.unpack('=L', f.read(4))[0]
	defaultImageBase = ' (Default)'
	if ImageBase != 0x400000L:
		defaultImageBase = ' (NON DEFAULT! DEFAULT IS : 0x400000)'
	print('ImageBase: ' + str(hex(ImageBase)) + defaultImageBase)

f.seek(38,1)
DLL_CHARACTERISTIC = struct.unpack('=H', f.read(2))[0]
if DLL_CHARACTERISTIC & 0b1000000 == 0:
	print('ASLR is already disabled, writing anyway...')
DLL_CHARACTERISTIC = DLL_CHARACTERISTIC & 0xFFBF #Actual patching
f.seek(-2,1)
f.write(struct.pack('=H', DLL_CHARACTERISTIC & 0xFFBF));
f.close()


print('Patching done!')
