@echo off
del ugo.exe
del *.o*
asmc64.exe sha1ugo.asm 
g++ -march=native -s -O3 -static ugo.c sha1ugo.obj -o ugo.exe	
