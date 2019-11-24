# dynamorio build

build dynamorio for android aarch64

```
cmake -DCMAKE_TOOLCHAIN_FILE=../make/toolchain-android-arm64.cmake -DANDROID_TOOLCHAIN=/home/hac425/workspace/WLAFL-plus-plus/android-ndk-r14b/arm64-toolchain -DDR_COPY_TO_DEVICE=OFF ../
```

# WLAFL 

Android 

插桩模块

```
CFLAGS=" -DAARCH64 -fPIE -pie " cmake .. -DDynamoRIO_DIR=/home/hac425/workspace/WLAFL-plus-plus/dynamorio-package/android-aarch64/DynamoRIO-Linux-7.90.18003-0/cmake -DAARCH64=ON
```


使用方式

demo

```
export DYRUN_PATH=/data/lsl/DynamoRIO-Linux-7.90.18003-0/bin64/drrun
export INSTRUMENT_ARGS="-nargs 2 -target_module demo -target_offset 0xb28 -coverage_module demo"
./afl-fuzz -i q -o xew/ -- ../demo @@
```

whatsapp

```
export LD_LIBRARY_PATH=/data/app/com.whatsapp--5pvwBQWl6Fvyjuvcrsugg==/lib/arm64/
export DYRUN_PATH=/data/local/tmp/DynamoRIO-Linux-7.90.18003-0/bin64/drrun
export INSTRUMENT_ARGS="-target_module standalone -target_offset 0x788 -coverage_module libwhatsapp.so"
./afl-fuzz -i mp4in -M master-app  -o whasapp-out -- ./standalone @@
```