// main.cpp - JNI bridge InoAdb (Tahap 1: STUB)
//
// TAHAP INI: hanya memastikan pipeline GitHub Actions jalan dan menghasilkan
// libinoadb.so yang bisa dipanggil dari Java (package ru.inoadb).
//
// TAHAP BERIKUTNYA: ganti stub ini dengan implementasi asli yang memanggil
//   adb/pairing/pairing_connection.h + adb/tls/tls_connection.h dari AOSP ADB.

#include <jni.h>
#include <android/log.h>

#define LOG_TAG "InoAdbNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

// Sesuai InoAdb.java:
//   private static native int nativePair(String host, int port,
//                                        String pairingCode, String keyStoreDir);
JNIEXPORT jint JNICALL
Java_ru_inoadb_InoAdb_nativePair(JNIEnv* env, jclass, jstring jHost, jint jPort,
                                 jstring jCode, jstring jKeyDir) {
    const char* h = env->GetStringUTFChars(jHost, nullptr);
    const char* c = env->GetStringUTFChars(jCode, nullptr);
    const char* k = env->GetStringUTFChars(jKeyDir, nullptr);

    LOGI("[STUB] nativePair host=%s port=%d code=%s keyDir=%s",
         h ? h : "(null)", (int)jPort, c ? c : "(null)", k ? k : "(null)");

    if (h) env->ReleaseStringUTFChars(jHost, h);
    if (c) env->ReleaseStringUTFChars(jCode, c);
    if (k) env->ReleaseStringUTFChars(jKeyDir, k);

    return 0; // 0 = sukses (palsu)
}

// Sesuai InoAdb.java:
//   private static native int nativeConnect(String host, int port, String keyStoreDir);
JNIEXPORT jint JNICALL
Java_ru_inoadb_InoAdb_nativeConnect(JNIEnv* env, jclass, jstring jHost, jint jPort,
                                    jstring jKeyDir) {
    const char* h = env->GetStringUTFChars(jHost, nullptr);
    const char* k = env->GetStringUTFChars(jKeyDir, nullptr);

    LOGI("[STUB] nativeConnect host=%s port=%d keyDir=%s",
         h ? h : "(null)", (int)jPort, k ? k : "(null)");

    if (h) env->ReleaseStringUTFChars(jHost, h);
    if (k) env->ReleaseStringUTFChars(jKeyDir, k);

    return -99; // -99 = belum diimplementasikan
}

} // extern "C"
