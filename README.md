# dynamorio build

build dynamorio for android aarch64

```
cmake -DCMAKE_TOOLCHAIN_FILE=../make/toolchain-android-arm64.cmake -DANDROID_TOOLCHAIN=/home/hac425/workspace/WLAFL-plus-plus/android-ndk-r14b/arm64-toolchain -DDR_COPY_TO_DEVICE=OFF ../
```

