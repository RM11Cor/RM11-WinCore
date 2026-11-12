#include "pe64_micro_core.h"
#include <jni.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

JNIEXPORT jstring JNICALL
Java_com_fh5_port_X64Proof_nativeRun(JNIEnv *env, jclass unused, jbyteArray arr) {
  (void)unused;
  char report[768];
  if (!arr) return (*env)->NewStringUTF(env, "{\"stage\":\"micro-pe64\",\"status\":\"empty\"}");
  jsize len = (*env)->GetArrayLength(env, arr);
  if (len <= 0 || len > (jsize)RM11_MICRO_MAX_FILE) {
    return (*env)->NewStringUTF(env,
      "{\"stage\":\"micro-pe64\",\"status\":\"input-too-large\"}");
  }
  jbyte *bytes = (*env)->GetByteArrayElements(env, arr, NULL);
  if (!bytes) return (*env)->NewStringUTF(env,
      "{\"stage\":\"micro-pe64\",\"status\":\"out-of-memory\"}");
  rm11_micro_program prog;
  rm11_micro_status status = rm11_micro_parse_pe64((const uint8_t *)bytes, (size_t)len, &prog);
  (*env)->ReleaseByteArrayElements(env, arr, bytes, JNI_ABORT);
  int returned = 0, code = 0;
  int translated = status == RM11_MICRO_OK;
  int executed = 0;
#if defined(__aarch64__)
  if (translated) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || prog.word_count * sizeof(uint32_t) > (size_t)page) {
      status = RM11_MICRO_JIT_DENIED;
      code = EINVAL;
    } else {
      void *memory = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
      if (memory == MAP_FAILED) { status = RM11_MICRO_JIT_DENIED; code = errno; }
      else {
        size_t bytes_needed = prog.word_count * sizeof(uint32_t);
        memcpy(memory, prog.words, bytes_needed);
        __builtin___clear_cache((char *)memory, (char *)memory + bytes_needed);
        if (mprotect(memory, (size_t)page, PROT_READ | PROT_EXEC) != 0) {
          status = RM11_MICRO_JIT_DENIED; code = errno;
        } else {
          int (*fn)(void) = NULL;
          memcpy(&fn, &memory, sizeof(fn));
          returned = fn();
          executed = 1;
        }
        munmap(memory, (size_t)page);
      }
    }
  }
#else
  if (translated) status = RM11_MICRO_JIT_DENIED;
#endif
  snprintf(report, sizeof(report),
    "{\"stage\":\"pe64-entry-x86-to-arm64\",\"status\":\"%s\","
    "\"peParsed\":%s,\"translated\":%s,\"executed\":%s,"
    "\"result\":%d,\"error\":%d,\"armInstructions\":%zu,"
    "\"x86Bytes\":%zu,\"entryRva\":%u,\"fexCoreIntegrated\":false,"
    "\"wineIntegrated\":false,\"windowsGameReady\":false}",
    rm11_micro_status_name(status), translated ? "true" : "false",
    translated ? "true" : "false", executed ? "true" : "false", returned, code,
    translated ? prog.word_count : 0, translated ? prog.x86_bytes : 0,
    translated ? prog.entry_rva : 0);
  return (*env)->NewStringUTF(env, report);
}

/* P2.3: translation-only probe of a bounded REAL x86-64 game entrypoint
 * excerpt. CRITICAL: no mmap, mprotect, function call, or game execution. */
JNIEXPORT jstring JNICALL
Java_com_fh5_port_X64Proof_nativeInspectBlock(JNIEnv *env, jclass unused,
                                               jbyteArray arr) {
  (void)unused;
  char report[640];
  if (!arr) return (*env)->NewStringUTF(env,
    "{\"status\":\"no-entry-bytes\",\"executed\":false}");
  jsize n = (*env)->GetArrayLength(env, arr);
  if (n < 1 || n > 512) return (*env)->NewStringUTF(env,
    "{\"status\":\"bounded-entry-sample-required\",\"executed\":false}");
  jbyte *bytes = (*env)->GetByteArrayElements(env, arr, NULL);
  if (!bytes) return (*env)->NewStringUTF(env,
    "{\"status\":\"memory-unavailable\",\"executed\":false}");
  rm11_micro_program out;
  rm11_micro_status result=rm11_micro_translate_x86(
    (const uint8_t *)bytes, (size_t)n, &out);
  (*env)->ReleaseByteArrayElements(env, arr, bytes, JNI_ABORT);
  snprintf(report,sizeof(report),
    "{\"status\":\"%s\",\"microTranslatorAccepted\":%s,"
    "\"armWords\":%zu,\"x86BytesTranslated\":%zu,"
    "\"translationOnly\":true,\"executed\":false,"
    "\"originalGameCodeExecuted\":false,\"fullX64RuntimeReady\":false}",
    rm11_micro_status_name(result),
    result==RM11_MICRO_OK ? "true" : "false",
    result==RM11_MICRO_OK ? out.word_count : 0u,
    result==RM11_MICRO_OK ? out.x86_bytes : 0u);
  return (*env)->NewStringUTF(env,report);
}
