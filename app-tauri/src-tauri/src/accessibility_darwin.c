#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>

int osaguard_accessibility_trusted(void) {
  return AXIsProcessTrusted() ? 1 : 0;
}

// Keep the Accessibility request in the Tauri executable. macOS associates the
// resulting TCC prompt and permission entry with the process making this call.
int osaguard_request_accessibility(void) {
  const void *keys[] = {kAXTrustedCheckOptionPrompt};
  const void *values[] = {kCFBooleanTrue};
  CFDictionaryRef options = CFDictionaryCreate(
      kCFAllocatorDefault, keys, values, 1,
      &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  if (options == NULL) {
    return -1;
  }

  Boolean trusted = AXIsProcessTrustedWithOptions(options);
  CFRelease(options);
  return trusted ? 1 : 0;
}
