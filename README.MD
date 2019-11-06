# (c#) dll for Array of bytes [AOB] scan with wildcard,Reading process memeory, Writing process memory. 

>A standalone dll library written in c# for for wildcard AOB scan, reading and writing from process, its an old lib that I created and used for my personel use. Maybe this would help new modders, I recently stumbled upon this, so here it is.

# [![latest release][release]][release link] [![license][license badge]][license link]

[license badge]: https://img.shields.io/github/license/gopinath001/MemoryPatternScanner
[license link]: https://github.com/Gopinath001/MemoryPatternScanner/blob/master/LICENSE
[release link]: https://github.com/Gopinath001/MemoryPatternScanner/releases
[release]: https://img.shields.io/github/v/release/gopinath001/MemoryPatternScanner?include_prereleases

## Some insights.

This was developed in visual studio 2013 and was done when I started learning modding so dont expect geat code(although I retouched some of it now.)

### Just wana use the dll?

* download the dll
* add a reference to the dll
* 'using memory' must be added
* check how other stuff is implemented in the source from here.

### Wana Add some modifications?

* clone-fork the repo do as you wish.

## Usage

#### Methods available

The following methods assumes that you have selected the process, set the handle, set the module 
and set the pattern to scan.

ClassName: Scanner.

* bool writeBytes(Process process, ulong address, byte[] bytesToWrite)

* bool writeBytes(Process process, ulong address, String pattern)

* byte[] getBackupBytes()

* ulong FindPattern()

* bool WriteProcessMemory(IntPtr hProcess,IntPtr lpBaseAddress,byte[] lpBuffer,int dwSize,out IntPtr lpNumberOfBytesWritten)

* bool ReadProcessMemory(IntPtr hProcess,IntPtr lpBaseAddress,byte[] lpBuffer,int dwSize,out IntPtr lpNumberOfBytesRead)

## Example

I didn't include all the process memeory stuff below, but those can be used to, its available in the memory class, check source.

```js

Process process = the selected process that you want to use.

below could be set via constructor or set via setters, check the source.

Scanner Obj = new Scanner(process,process.Handle,"80 00 41 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 00");


Obj.setModule(process.MainModule);

Obj.FindPattern()

the below could be done for writing found bytes,

memObj.writeBytes(process, memObj.FindPattern(), "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

you could also do below to get the backup bytes which you wrote for ex, you would get this region
80 00 41 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 00, the placeholder with real values.

memObj.getBackupBytes();
```
## Built With

* c#
* a newbie modder back in the day.

## Authors

* **Gopinath (aka) Bluepie** [Gopinath001](https://github.com/Gopinath001) 

## Meta

Gopinath (aka) bluepie – [@bluepie](https://twitter.com/xbluepie) – gopinath2nr@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
