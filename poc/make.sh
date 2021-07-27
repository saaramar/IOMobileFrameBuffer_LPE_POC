xcrun --sdk iphoneos clang -arch arm64 -framework IOKit iosurface.c exploit.c -O3 -o appleclcd_exploit
codesign -s - appleclcd_exploit --entitlement entitlements.xml  -f
