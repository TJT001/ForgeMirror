# Shield stub classes are loaded from the manifest or by name at runtime.
-keep class dev.forgemirror.shield.** { *; }

# White-box AES tables are serialized with these class names.
-keep class com.risid.wbaes.** { *; }
