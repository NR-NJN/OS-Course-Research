# System Calls Tracing for Windows applications running on WINE
This is a rudimentary setup for the purposes of my research work which uses an Extended Berkeley Packet Packet Filter to snap and update each and every WINE application conversion call from
Windows to Linux onto the running terminal shell for the user to then analyze and modify. This only contains the code for the Registry application, which albeit is relatively useless for Linux, but it helps provide a baseline to this research and to test if this code works. For the paper however, different versions of this code specialized for multiple Windows specific applications was used.
## Setup
Need a virtualized Linux distro (preferably ubuntu as the test was done on a preloaded non customized build of ubuntu, although any latest distribution should not pose a serious problem).  

### IMPORTANT
**Please run this in a virtualized environment and not on your host Linux system**

You also need to have these 3 tools running in your environment to do the specified tests
```
sudo apt-get install build-essential clang llvm libelf-dev linux-headers-$(uname -r)
```
```
sudo apt-get install libbpf-dev bpftool
```
```
sudo apt-get install wine winetricks
```

## Procedure
Both files need to be compiled with specific flags and headers too
```
clang -g -O2 -target bpf -D<cpu architecture> -c wine_tracer.bpf.c -o wine_tracer.bpf.o
```
and
```
gcc -g -O2 -Wall wine_tracer.c -o wine_tracer -lbpf -lelf

```
Once you get both of these working run the [wine_tracer.c](src/wine_tracer.c) file and keep it running. In a separate terminal open any Windows application through WINE and then start making whatever modifications/operations on that app. 
You should see the exact process IDs and failure points of each of the syscalls, which is more information than what WINE's commandline interface provides.

**Research paper** -- [Paper](https://drive.google.com/file/d/1iEmdWTe1Sq02hziKgXIeAcCMyLIYS1-E/view)

## Conclusion
What you then do with this information is upto you. For the purposes of my research work I have taken fairly basic and striaght-forward Windows only applications, to collect info about various points of failure in these applications and report them.
