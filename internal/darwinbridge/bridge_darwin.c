//go:build darwin && cgo

#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int accessibility_trusted;
    int pid;
    long long start_seconds;
    long long start_microseconds;
    int apple_signed;
    int app_frontmost;
    int app_onscreen;
    int focused_enabled;
    int focused_value_length;
    int secure_field_count;
    int is_auth_dialog;
    int auth_context_complete;
    int unsupported_auth_ui;
    char code_identifier[128];
    char executable_path[1024];
    char focused_role[128];
    char focused_subrole[128];
    char window_title[512];
    char auth_context[4096];
} og_auth_snapshot;

typedef struct {
    int pid;
    int ppid;
    unsigned int uid;
    long long start_seconds;
    int parent_code_valid;
    char executable_path[1024];
    char parent_path[1024];
    char parent_code_identifier[128];
    char parent_cdhash[128];
} og_process_info;

static const char *OG_KEYCHAIN_SERVICE = "dev.aiwaki.osaguard.admin-password";
static const char *OG_INTEGRITY_SERVICE = "dev.aiwaki.osaguard.integrity-state";
static const char *OG_INTEGRITY_ACCOUNT = "product";

static void og_set_error(char *err, size_t err_len, const char *message) {
    if (err == NULL || err_len == 0) {
        return;
    }
    if (message == NULL) {
        message = "unknown error";
    }
    snprintf(err, err_len, "%s", message);
}

static void og_set_osstatus_error(char *err, size_t err_len, const char *operation, OSStatus status) {
    CFStringRef detail = SecCopyErrorMessageString(status, NULL);
    char detail_buf[384] = {0};
    if (detail != NULL) {
        CFStringGetCString(detail, detail_buf, sizeof(detail_buf), kCFStringEncodingUTF8);
        CFRelease(detail);
    }
    if (detail_buf[0] == '\0') {
        snprintf(detail_buf, sizeof(detail_buf), "OSStatus %d", (int)status);
    }
    if (err != NULL && err_len > 0) {
        snprintf(err, err_len, "%s: %s", operation, detail_buf);
    }
}

static void og_copy_cfstring(CFStringRef value, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) {
        return;
    }
    CFStringGetCString(value, out, out_len, kCFStringEncodingUTF8);
}

static void og_copy_ax_string(AXUIElementRef element, CFStringRef attribute, char *out, size_t out_len) {
    CFTypeRef value = NULL;
    if (AXUIElementCopyAttributeValue(element, attribute, &value) == kAXErrorSuccess && value != NULL) {
        og_copy_cfstring((CFStringRef)value, out, out_len);
        CFRelease(value);
    }
}

static int og_ax_bool(AXUIElementRef element, CFStringRef attribute) {
    CFTypeRef value = NULL;
    int result = 0;
    if (AXUIElementCopyAttributeValue(element, attribute, &value) == kAXErrorSuccess && value != NULL) {
        if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
            result = CFBooleanGetValue((CFBooleanRef)value) ? 1 : 0;
        }
        CFRelease(value);
    }
    return result;
}

static int og_append_context_value(char *out, size_t out_len, size_t *used, const char *label, CFTypeRef value) {
    if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) return 1;
    if (*used >= out_len) return 0;
    char text[1024] = {0};
    if (!CFStringGetCString((CFStringRef)value, text, sizeof(text), kCFStringEncodingUTF8)) return 0;
    int written = snprintf(out + *used, out_len - *used, "%s=%s\n", label, text);
    if (written < 0 || (size_t)written >= out_len - *used) return 0;
    *used += (size_t)written;
    return 1;
}

static int og_collect_auth_context(AXUIElementRef element, int depth, int *budget,
    char *out, size_t out_len, size_t *used, int *secure_count) {
    if (element == NULL || depth > 12 || budget == NULL || *budget <= 0) return 0;
    (*budget)--;
    CFTypeRef role = NULL;
    CFTypeRef subrole = NULL;
    AXUIElementCopyAttributeValue(element, kAXRoleAttribute, &role);
    AXUIElementCopyAttributeValue(element, kAXSubroleAttribute, &subrole);
    int secure = subrole != NULL && CFGetTypeID(subrole) == CFStringGetTypeID() &&
        CFStringCompare((CFStringRef)subrole, kAXSecureTextFieldSubrole, 0) == kCFCompareEqualTo;
    if (secure) (*secure_count)++;
    int complete = og_append_context_value(out, out_len, used, "role", role) &&
        og_append_context_value(out, out_len, used, "subrole", subrole);
    if (!secure && complete) {
        CFTypeRef title = NULL;
        CFTypeRef description = NULL;
        CFTypeRef value = NULL;
        AXUIElementCopyAttributeValue(element, kAXTitleAttribute, &title);
        AXUIElementCopyAttributeValue(element, kAXDescriptionAttribute, &description);
        AXUIElementCopyAttributeValue(element, kAXValueAttribute, &value);
        complete = og_append_context_value(out, out_len, used, "title", title) &&
            og_append_context_value(out, out_len, used, "description", description) &&
            og_append_context_value(out, out_len, used, "value", value);
        if (title != NULL) CFRelease(title);
        if (description != NULL) CFRelease(description);
        if (value != NULL) CFRelease(value);
    }
    if (role != NULL) CFRelease(role);
    if (subrole != NULL) CFRelease(subrole);
    if (!complete) return 0;

    CFTypeRef children = NULL;
    if (AXUIElementCopyAttributeValue(element, kAXChildrenAttribute, &children) == kAXErrorSuccess && children != NULL) {
        if (CFGetTypeID(children) == CFArrayGetTypeID()) {
            CFArrayRef array = (CFArrayRef)children;
            CFIndex length = CFArrayGetCount(array);
            for (CFIndex i = 0; i < length; i++) {
                CFTypeRef child = CFArrayGetValueAtIndex(array, i);
                if (child != NULL && CFGetTypeID(child) == AXUIElementGetTypeID() &&
                    !og_collect_auth_context((AXUIElementRef)child, depth + 1, budget, out, out_len, used, secure_count)) {
                    CFRelease(children);
                    return 0;
                }
            }
        }
        CFRelease(children);
    }
    return 1;
}

static int og_verify_process(pid_t pid, char *identifier, size_t identifier_len, char *path, size_t path_len) {
    if (proc_pidpath(pid, path, (uint32_t)path_len) <= 0) {
        path[0] = '\0';
        return 0;
    }

    CFNumberRef pid_number = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
    if (pid_number == NULL) {
        return 0;
    }
    const void *keys[] = {kSecGuestAttributePid};
    const void *values[] = {pid_number};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(pid_number);
    if (attributes == NULL) {
        return 0;
    }

    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    CFRelease(attributes);
    if (status != errSecSuccess || code == NULL) {
        return 0;
    }

    SecRequirementRef requirement = NULL;
    status = SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &requirement);
    if (status != errSecSuccess || requirement == NULL) {
        CFRelease(code);
        return 0;
    }
    status = SecCodeCheckValidity(code, kSecCSStrictValidate, requirement);
    CFRelease(requirement);
    if (status != errSecSuccess) {
        CFRelease(code);
        return 0;
    }

    CFDictionaryRef signing_info = NULL;
    status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing_info);
    CFRelease(code);
    if (status != errSecSuccess || signing_info == NULL) {
        return 0;
    }
    CFStringRef code_identifier = CFDictionaryGetValue(signing_info, kSecCodeInfoIdentifier);
    og_copy_cfstring(code_identifier, identifier, identifier_len);
    CFRelease(signing_info);
    return 1;
}

static int og_copy_process_identity(pid_t pid, char *identifier, size_t identifier_len,
    char *cdhash, size_t cdhash_len) {
    CFNumberRef pid_number = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
    if (pid_number == NULL) return 0;
    const void *keys[] = {kSecGuestAttributePid};
    const void *values[] = {pid_number};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(pid_number);
    if (attributes == NULL) return 0;
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    CFRelease(attributes);
    if (status != errSecSuccess || code == NULL) return 0;
    status = SecCodeCheckValidity(code, kSecCSStrictValidate, NULL);
    if (status != errSecSuccess) { CFRelease(code); return 0; }
    CFDictionaryRef signing_info = NULL;
    status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing_info);
    CFRelease(code);
    if (status != errSecSuccess || signing_info == NULL) return 0;
    og_copy_cfstring(CFDictionaryGetValue(signing_info, kSecCodeInfoIdentifier), identifier, identifier_len);
    CFDataRef unique = CFDictionaryGetValue(signing_info, kSecCodeInfoUnique);
    if (unique == NULL || CFGetTypeID(unique) != CFDataGetTypeID()) {
        CFRelease(signing_info);
        return 0;
    }
    const UInt8 *bytes = CFDataGetBytePtr(unique);
    CFIndex length = CFDataGetLength(unique);
    if (length <= 0 || (size_t)(length * 2 + 1) > cdhash_len) {
        CFRelease(signing_info);
        return 0;
    }
    static const char hex[] = "0123456789abcdef";
    for (CFIndex i = 0; i < length; i++) {
        cdhash[i * 2] = hex[bytes[i] >> 4];
        cdhash[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    cdhash[length * 2] = '\0';
    CFRelease(signing_info);
    return identifier[0] != '\0';
}

static int og_supported_auth_process(const og_auth_snapshot *snapshot) {
    return strcmp(snapshot->code_identifier, "com.apple.SecurityAgent") == 0 &&
        strcmp(snapshot->executable_path,
            "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent") == 0;
}

static int og_known_auth_process(const og_auth_snapshot *snapshot) {
    if (og_supported_auth_process(snapshot)) return 1;
    return (strcmp(snapshot->code_identifier, "com.apple.authorizationhost") == 0 &&
        strcmp(snapshot->executable_path,
            "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/authorizationhost.bundle/Contents/MacOS/authorizationhost") == 0) ||
        (strcmp(snapshot->code_identifier, "com.apple.LocalAuthentication.UIAgent") == 0 &&
        strcmp(snapshot->executable_path,
            "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreautha.bundle/Contents/MacOS/coreautha") == 0);
}

static int og_allowed_auth_path(const char *path) {
    return strcmp(path,
        "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent") == 0 ||
        strcmp(path,
        "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/authorizationhost.bundle/Contents/MacOS/authorizationhost") == 0 ||
        strcmp(path,
        "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreautha.bundle/Contents/MacOS/coreautha") == 0;
}

static int og_pid_has_onscreen_window(pid_t pid) {
    CFArrayRef windows = CGWindowListCopyWindowInfo(
        kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
        kCGNullWindowID);
    if (windows == NULL) return 0;
    int found = 0;
    CFIndex count = CFArrayGetCount(windows);
    for (CFIndex i = 0; i < count; i++) {
        CFDictionaryRef info = (CFDictionaryRef)CFArrayGetValueAtIndex(windows, i);
        if (info == NULL || CFGetTypeID(info) != CFDictionaryGetTypeID()) continue;
        CFNumberRef owner = CFDictionaryGetValue(info, kCGWindowOwnerPID);
        int owner_pid = 0;
        if (owner != NULL && CFGetTypeID(owner) == CFNumberGetTypeID() &&
            CFNumberGetValue(owner, kCFNumberIntType, &owner_pid) && owner_pid == pid) {
            found = 1;
            break;
        }
    }
    CFRelease(windows);
    return found;
}

static int og_snapshot_for_pid(pid_t pid, og_auth_snapshot *out) {
    memset(out, 0, sizeof(*out));
    out->accessibility_trusted = 1;
    out->pid = pid;
    struct proc_bsdinfo process_info;
    memset(&process_info, 0, sizeof(process_info));
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &process_info, sizeof(process_info)) != sizeof(process_info)) {
        return 0;
    }
    out->start_seconds = (long long)process_info.pbi_start_tvsec;
    out->start_microseconds = (long long)process_info.pbi_start_tvusec;
    out->apple_signed = og_verify_process(pid, out->code_identifier, sizeof(out->code_identifier),
        out->executable_path, sizeof(out->executable_path));
    if (!out->apple_signed || !og_known_auth_process(out)) {
        return 0;
    }

    AXUIElementRef app = AXUIElementCreateApplication(pid);
    if (app == NULL) {
        return 0;
    }
    out->app_frontmost = og_ax_bool(app, kAXFrontmostAttribute);
    out->app_onscreen = og_pid_has_onscreen_window(pid);
    CFTypeRef focused_value = NULL;
    if (AXUIElementCopyAttributeValue(app, kAXFocusedUIElementAttribute, &focused_value) != kAXErrorSuccess ||
        focused_value == NULL || CFGetTypeID(focused_value) != AXUIElementGetTypeID()) {
        if (focused_value != NULL) CFRelease(focused_value);
        CFRelease(app);
        return 1;
    }
    AXUIElementRef focused = (AXUIElementRef)focused_value;
    og_copy_ax_string(focused, kAXRoleAttribute, out->focused_role, sizeof(out->focused_role));
    og_copy_ax_string(focused, kAXSubroleAttribute, out->focused_subrole, sizeof(out->focused_subrole));
    out->focused_enabled = og_ax_bool(focused, kAXEnabledAttribute);
    CFTypeRef focused_text = NULL;
    if (AXUIElementCopyAttributeValue(focused, kAXValueAttribute, &focused_text) == kAXErrorSuccess &&
        focused_text != NULL && CFGetTypeID(focused_text) == CFStringGetTypeID()) {
        out->focused_value_length = (int)CFStringGetLength((CFStringRef)focused_text);
    }
    if (focused_text != NULL) CFRelease(focused_text);

    CFTypeRef window_value = NULL;
    if (AXUIElementCopyAttributeValue(focused, kAXWindowAttribute, &window_value) != kAXErrorSuccess ||
        window_value == NULL || CFGetTypeID(window_value) != AXUIElementGetTypeID()) {
        if (window_value != NULL) CFRelease(window_value);
        window_value = NULL;
        AXUIElementCopyAttributeValue(app, kAXFocusedWindowAttribute, &window_value);
    }
    if (window_value != NULL && CFGetTypeID(window_value) == AXUIElementGetTypeID()) {
        AXUIElementRef window = (AXUIElementRef)window_value;
        og_copy_ax_string(window, kAXTitleAttribute, out->window_title, sizeof(out->window_title));
        int budget = 256;
        size_t context_used = 0;
        out->secure_field_count = 0;
        out->auth_context_complete = og_collect_auth_context(window, 0, &budget,
            out->auth_context, sizeof(out->auth_context), &context_used, &out->secure_field_count);
        CFRelease(window);
    } else if (window_value != NULL) {
        CFRelease(window_value);
    }
    int secure_auth_shape = out->app_frontmost && out->app_onscreen && out->focused_enabled && out->auth_context_complete &&
        out->auth_context[0] != '\0' &&
        strcmp(out->focused_role, "AXTextField") == 0 &&
        strcmp(out->focused_subrole, "AXSecureTextField") == 0 &&
        out->secure_field_count == 1;
    out->is_auth_dialog = secure_auth_shape && og_supported_auth_process(out);
    out->unsupported_auth_ui = secure_auth_shape && !og_supported_auth_process(out);
    CFRelease(focused);
    CFRelease(app);
    return 1;
}

int og_read_auth_snapshot(og_auth_snapshot *out, char *err, size_t err_len) {
    if (out == NULL) {
        og_set_error(err, err_len, "auth snapshot output is null");
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->accessibility_trusted = AXIsProcessTrusted() ? 1 : 0;
    if (!out->accessibility_trusted) {
        return 0;
    }

    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0) {
        og_set_error(err, err_len, "proc_listpids size query failed while inspecting authorization UI");
        return -1;
    }
    int *pids = calloc((size_t)bytes / sizeof(int) + 32, sizeof(int));
    if (pids == NULL) {
        og_set_error(err, err_len, "cannot allocate authorization process list");
        return -1;
    }
    bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes);
    if (bytes < 0) {
        free(pids);
        og_set_error(err, err_len, "proc_listpids failed while inspecting authorization UI");
        return -1;
    }
    og_auth_snapshot candidate;
    memset(&candidate, 0, sizeof(candidate));
    int candidate_count = 0;
    int unsupported_count = 0;
    int pid_count = bytes / (int)sizeof(int);
    for (int i = 0; i < pid_count; i++) {
        if (pids[i] <= 0) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
        if (proc_pidpath(pids[i], path, sizeof(path)) <= 0 || !og_allowed_auth_path(path)) continue;
        og_auth_snapshot current;
        if (!og_snapshot_for_pid((pid_t)pids[i], &current)) continue;
        if (current.unsupported_auth_ui) {
            unsupported_count++;
            continue;
        }
        if (current.is_auth_dialog) {
            candidate = current;
            candidate_count++;
        } else if (candidate_count == 0) {
            candidate = current;
        }
    }
    free(pids);
    if (unsupported_count > 0) {
        og_set_error(err, err_len, "unsupported or ambiguous Apple authorization UI is visible");
        return -1;
    }
    if (candidate_count > 1) {
        og_set_error(err, err_len, "multiple Apple authorization dialogs passed the secure-field checks");
        return -1;
    }
    if (candidate.pid > 0) {
        *out = candidate;
    }
    return 0;
}

static CFMutableDictionaryRef og_keychain_service_query(const char *service_name) {
    if (service_name == NULL) return NULL;
    CFStringRef service = CFStringCreateWithCString(NULL, service_name, kCFStringEncodingUTF8);
    if (service == NULL) {
        return NULL;
    }
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (query != NULL) {
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, service);
    }
    CFRelease(service);
    return query;
}

static CFMutableDictionaryRef og_keychain_query_for_service(const char *service_name, const char *account) {
    if (account == NULL) return NULL;
    CFMutableDictionaryRef query = og_keychain_service_query(service_name);
    CFStringRef account_string = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    if (query == NULL || account_string == NULL) {
        if (query != NULL) CFRelease(query);
        if (account_string != NULL) CFRelease(account_string);
        return NULL;
    }
    if (query != NULL) {
        CFDictionarySetValue(query, kSecAttrAccount, account_string);
    }
    CFRelease(account_string);
    return query;
}

static CFMutableDictionaryRef og_keychain_query(const char *account) {
    return og_keychain_query_for_service(OG_KEYCHAIN_SERVICE, account);
}

static int og_access_is_caller_only(SecAccessRef access, char *err, size_t err_len) {
    if (access == NULL) {
        og_set_error(err, err_len, "missing Keychain access object");
        return -1;
    }
    SecTrustedApplicationRef expected = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &expected);
#pragma clang diagnostic pop
    if (status != errSecSuccess || expected == NULL) {
        if (expected != NULL) CFRelease(expected);
        og_set_osstatus_error(err, err_len, "identify current Keychain caller", status);
        return -1;
    }
    CFDataRef expected_data = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = SecTrustedApplicationCopyData(expected, &expected_data);
    CFArrayRef acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
#pragma clang diagnostic pop
    CFRelease(expected);
    if (status != errSecSuccess || expected_data == NULL || acls == NULL) {
        if (expected_data != NULL) CFRelease(expected_data);
        if (acls != NULL) CFRelease(acls);
        og_set_osstatus_error(err, err_len, "inspect caller-only Keychain ACL", status);
        return -1;
    }

    int caller_only = 0;
    if (CFArrayGetCount(acls) == 1) {
        CFArrayRef applications = NULL;
        CFStringRef description = NULL;
        SecKeychainPromptSelector prompt = {0};
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        status = SecACLCopyContents((SecACLRef)CFArrayGetValueAtIndex(acls, 0),
            &applications, &description, &prompt);
#pragma clang diagnostic pop
        if (description != NULL) CFRelease(description);
        if (status == errSecSuccess && applications != NULL && CFArrayGetCount(applications) == 1) {
            CFDataRef application_data = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            status = SecTrustedApplicationCopyData(
                (SecTrustedApplicationRef)CFArrayGetValueAtIndex(applications, 0), &application_data);
#pragma clang diagnostic pop
            if (status == errSecSuccess && application_data != NULL && CFEqual(application_data, expected_data)) {
                caller_only = 1;
            }
            if (application_data != NULL) CFRelease(application_data);
        }
        if (applications != NULL) CFRelease(applications);
    }
    CFRelease(expected_data);
    CFRelease(acls);
    if (!caller_only) {
        og_set_error(err, err_len, "Keychain decrypt ACL is not restricted to the current application");
        return 0;
    }
    return 1;
}

static int og_item_has_caller_only_access(SecKeychainItemRef item, char *err, size_t err_len) {
    if (item == NULL) {
        og_set_error(err, err_len, "missing Keychain item for ACL verification");
        return -1;
    }
    SecAccessRef access = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus status = SecKeychainItemCopyAccess(item, &access);
#pragma clang diagnostic pop
    if (status != errSecSuccess || access == NULL) {
        if (access != NULL) CFRelease(access);
        og_set_osstatus_error(err, err_len, "copy stored Keychain ACL", status);
        return -1;
    }
    int caller_only = og_access_is_caller_only(access, err, err_len);
    CFRelease(access);
    return caller_only;
}

static int og_query_item_has_caller_only_access(CFDictionaryRef base_query, char *err, size_t err_len) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutableCopy(NULL, 0, base_query);
    if (query == NULL) {
        og_set_error(err, err_len, "cannot allocate Keychain ACL verification query");
        return -1;
    }
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef raw_item = NULL;
    OSStatus status = SecItemCopyMatching(query, &raw_item);
    CFRelease(query);
    if (status != errSecSuccess || raw_item == NULL) {
        if (raw_item != NULL) CFRelease(raw_item);
        og_set_osstatus_error(err, err_len, "load Keychain item for ACL verification", status);
        return -1;
    }
    int caller_only = og_item_has_caller_only_access((SecKeychainItemRef)raw_item, err, err_len);
    CFRelease(raw_item);
    return caller_only;
}

static int og_keychain_store_for_service(const char *service_name, const char *account,
    const unsigned char *secret, size_t secret_len, const char *label,
    char *err, size_t err_len) {
    if (service_name == NULL || account == NULL || secret == NULL || secret_len == 0 || secret_len > 4096) {
        og_set_error(err, err_len, "invalid keychain store input");
        return -1;
    }
    CFMutableDictionaryRef query = og_keychain_query_for_service(service_name, account);
    CFDataRef data = CFDataCreate(NULL, secret, (CFIndex)secret_len);
    CFMutableDictionaryRef updates = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef label_string = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);
    if (query == NULL || data == NULL || updates == NULL || label_string == NULL) {
        if (query != NULL) CFRelease(query);
        if (data != NULL) CFRelease(data);
        if (updates != NULL) CFRelease(updates);
        if (label_string != NULL) CFRelease(label_string);
        og_set_error(err, err_len, "cannot allocate keychain query");
        return -1;
    }

    // Never inherit the ACL of an existing item. A same-user process could
    // pre-create the service/account pair with an extra trusted application;
    // changing only kSecValueData would preserve that poisoned ACL. Create a
    // fresh default access object for every store and replace the ACL and data
    // in one SecItemUpdate transaction. Per SecAccessCreate, a NULL trusted
    // list means only the application creating this access object.
    SecAccessRef access = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus status = SecAccessCreate(label_string, NULL, &access);
#pragma clang diagnostic pop
    if (status != errSecSuccess || access == NULL) {
        CFRelease(label_string);
        CFRelease(updates);
        CFRelease(data);
        CFRelease(query);
        og_set_osstatus_error(err, err_len, "create caller-only Keychain ACL", status);
        return -1;
    }
    int fresh_access_check = og_access_is_caller_only(access, err, err_len);
    if (fresh_access_check != 1) {
        CFRelease(access);
        CFRelease(label_string);
        CFRelease(updates);
        CFRelease(data);
        CFRelease(query);
        return -1;
    }
    CFMutableDictionaryRef acl_update = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (acl_update == NULL) {
        CFRelease(access);
        CFRelease(label_string);
        CFRelease(updates);
        CFRelease(data);
        CFRelease(query);
        og_set_error(err, err_len, "cannot allocate Keychain ACL update");
        return -1;
    }
    CFDictionarySetValue(acl_update, kSecAttrAccess, access);
    CFDictionarySetValue(updates, kSecValueData, data);
    CFDictionarySetValue(updates, kSecAttrAccess, access);

    // Harden an existing item before exposing the new value to it. Some macOS
    // releases have accepted a combined kSecAttrAccess+kSecValueData update
    // while retaining the old ACL. The ACL-only preflight plus read-back keeps
    // a poisoned pre-seeded item from ever receiving password bytes. The
    // subsequent combined update is the atomic data commit required for
    // prior-value preservation.
    int existing_access = og_query_item_has_caller_only_access(query, err, err_len);
    if (existing_access == 1) {
        status = SecItemUpdate(query, updates);
    } else {
        status = SecItemUpdate(query, acl_update);
        if (status == errSecSuccess && og_query_item_has_caller_only_access(query, err, err_len) == 1) {
            status = SecItemUpdate(query, updates);
        } else if (status == errSecSuccess) {
            status = errSecAuthFailed;
        }
    }
    if (status == errSecItemNotFound) {
        CFMutableDictionaryRef item = CFDictionaryCreateMutableCopy(NULL, 0, query);
        if (item == NULL) {
            CFRelease(acl_update);
            CFRelease(access);
            CFRelease(label_string);
            CFRelease(updates);
            CFRelease(data);
            CFRelease(query);
            og_set_error(err, err_len, "cannot allocate keychain item");
            return -1;
        }
        CFDictionarySetValue(item, kSecAttrLabel, label_string);
        CFDictionarySetValue(item, kSecAttrAccess, access);
        CFDictionarySetValue(item, kSecValueData, data);
        status = SecItemAdd(item, NULL);
        CFRelease(item);
        if (status == errSecDuplicateItem) {
            status = SecItemUpdate(query, acl_update);
            if (status == errSecSuccess && og_query_item_has_caller_only_access(query, err, err_len) == 1) {
                status = SecItemUpdate(query, updates);
            } else if (status == errSecSuccess) {
                status = errSecAuthFailed;
            }
        }
    }
    if (status == errSecSuccess && og_query_item_has_caller_only_access(query, err, err_len) != 1) {
        status = errSecAuthFailed;
    }
    CFRelease(acl_update);
    CFRelease(access);
    CFRelease(label_string);
    CFRelease(updates);
    CFRelease(data);
    CFRelease(query);
    if (status != errSecSuccess) {
        og_set_osstatus_error(err, err_len, "store protected value in Keychain", status);
        return -1;
    }
    return 0;
}

int og_keychain_store(const char *account, const unsigned char *secret, size_t secret_len, char *err, size_t err_len) {
    return og_keychain_store_for_service(OG_KEYCHAIN_SERVICE, account, secret, secret_len,
        "OsaGuard administrator password", err, err_len);
}

int og_keychain_load(const char *account, unsigned char **secret, size_t *secret_len, char *err, size_t err_len) {
    if (account == NULL || secret == NULL || secret_len == NULL) {
        og_set_error(err, err_len, "invalid keychain load input");
        return -1;
    }
    *secret = NULL;
    *secret_len = 0;
    CFMutableDictionaryRef query = og_keychain_query(account);
    if (query == NULL) {
        og_set_error(err, err_len, "cannot allocate keychain query");
        return -1;
    }
    if (og_query_item_has_caller_only_access(query, err, err_len) != 1) {
        CFRelease(query);
        return -1;
    }
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status != errSecSuccess || result == NULL) {
        if (result != NULL) CFRelease(result);
        og_set_osstatus_error(err, err_len, "load password from Keychain", status);
        return -1;
    }
    if (CFGetTypeID(result) != CFDataGetTypeID()) {
        CFRelease(result);
        og_set_error(err, err_len, "Keychain result is not data");
        return -1;
    }
    CFDataRef data = (CFDataRef)result;
    CFIndex length = CFDataGetLength(data);
    if (length <= 0 || length > 4096) {
        CFRelease(result);
        og_set_error(err, err_len, "Keychain password has invalid length");
        return -1;
    }
    unsigned char *copy = calloc((size_t)length, 1);
    if (copy == NULL) {
        CFRelease(result);
        og_set_error(err, err_len, "cannot allocate password buffer");
        return -1;
    }
    memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
    CFRelease(result);
    *secret = copy;
    *secret_len = (size_t)length;
    return 0;
}

int og_keychain_exists(const char *account, char *err, size_t err_len) {
    if (account == NULL) {
        og_set_error(err, err_len, "invalid keychain existence query");
        return -1;
    }
    CFMutableDictionaryRef query = og_keychain_query(account);
    if (query == NULL) {
        og_set_error(err, err_len, "cannot allocate keychain existence query");
        return -1;
    }
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    if (result != NULL) CFRelease(result);
    if (status == errSecSuccess) {
        CFDictionaryRemoveValue(query, kSecReturnAttributes);
        CFDictionaryRemoveValue(query, kSecMatchLimit);
        int caller_only = og_query_item_has_caller_only_access(query, err, err_len);
        CFRelease(query);
        return caller_only == 1 ? 1 : -1;
    }
    CFRelease(query);
    if (status == errSecItemNotFound) return 0;
    og_set_osstatus_error(err, err_len, "query OsaGuard Keychain item metadata", status);
    return -1;
}

int og_keychain_delete(const char *account, char *err, size_t err_len) {
    if (account == NULL) {
        og_set_error(err, err_len, "invalid keychain delete input");
        return -1;
    }
    CFMutableDictionaryRef query = og_keychain_query(account);
    if (query == NULL) {
        og_set_error(err, err_len, "cannot allocate keychain query");
        return -1;
    }
    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    if (status != errSecSuccess && status != errSecItemNotFound) {
        og_set_osstatus_error(err, err_len, "delete password from Keychain", status);
        return -1;
    }
    return 0;
}

int og_keychain_delete_all(char *err, size_t err_len) {
    // The account is intentionally omitted while discovering candidates. Early
    // CLI builds permitted users to choose an account label, but every password
    // record uses this product-only generic-password service. Do not delete the
    // resulting service query directly: another process could plant a same-
    // service item with a different ACL. First require every candidate to have
    // OsaGuard's caller-only ACL, then delete exactly those stable item refs.
    // This never mutates the user's Keychain search list or default Keychain.
    CFMutableDictionaryRef query = og_keychain_service_query(OG_KEYCHAIN_SERVICE);
    if (query == NULL) {
        og_set_error(err, err_len, "cannot allocate keychain deletion query");
        return -1;
    }
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFTypeRef raw_items = NULL;
    OSStatus status = SecItemCopyMatching(query, &raw_items);
    CFRelease(query);
    if (status == errSecItemNotFound) return 0;
    if (status != errSecSuccess || raw_items == NULL) {
        if (raw_items != NULL) CFRelease(raw_items);
        og_set_osstatus_error(err, err_len, "list OsaGuard passwords for deletion", status);
        return -1;
    }
    if (CFGetTypeID(raw_items) != CFArrayGetTypeID() || CFArrayGetCount((CFArrayRef)raw_items) == 0) {
        CFRelease(raw_items);
        og_set_error(err, err_len, "Keychain deletion query returned an invalid item list");
        return -1;
    }
    CFArrayRef items = (CFArrayRef)raw_items;
    for (CFIndex index = 0; index < CFArrayGetCount(items); index++) {
        CFTypeRef item = CFArrayGetValueAtIndex(items, index);
        int caller_only = og_item_has_caller_only_access((SecKeychainItemRef)item, err, err_len);
        if (caller_only == 1) continue;
        if (caller_only == 0) {
            og_set_error(err, err_len, "refusing to delete an OsaGuard-service Keychain item with an unrecognized ACL");
        }
        CFRelease(raw_items);
        return -1;
    }
    CFMutableDictionaryRef delete_query = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (delete_query == NULL) {
        CFRelease(raw_items);
        og_set_error(err, err_len, "cannot allocate exact Keychain deletion query");
        return -1;
    }
    CFDictionarySetValue(delete_query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(delete_query, kSecMatchItemList, items);
    status = SecItemDelete(delete_query);
    CFRelease(delete_query);
    CFRelease(raw_items);
    if (status != errSecSuccess && status != errSecItemNotFound) {
        og_set_osstatus_error(err, err_len, "delete verified OsaGuard passwords from Keychain", status);
        return -1;
    }
    return 0;
}

int og_integrity_state_store(const unsigned char *state, size_t state_len, char *err, size_t err_len) {
    return og_keychain_store_for_service(OG_INTEGRITY_SERVICE, OG_INTEGRITY_ACCOUNT,
        state, state_len, "OsaGuard protected product state", err, err_len);
}

// Returns 1 when a state item exists, 0 when absent, and -1 on error. The
// caller owns the returned buffer and must erase it with og_secure_free.
int og_integrity_state_load(unsigned char **state, size_t *state_len, char *err, size_t err_len) {
    if (state == NULL || state_len == NULL) {
        og_set_error(err, err_len, "invalid integrity state output");
        return -1;
    }
    *state = NULL;
    *state_len = 0;
    CFMutableDictionaryRef query = og_keychain_query_for_service(OG_INTEGRITY_SERVICE, OG_INTEGRITY_ACCOUNT);
    if (query == NULL) {
        og_set_error(err, err_len, "cannot allocate integrity state query");
        return -1;
    }
    CFMutableDictionaryRef existence_query = CFDictionaryCreateMutableCopy(NULL, 0, query);
    if (existence_query == NULL) {
        CFRelease(query);
        og_set_error(err, err_len, "cannot allocate integrity state existence query");
        return -1;
    }
    CFDictionarySetValue(existence_query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(existence_query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef existence_result = NULL;
    OSStatus existence_status = SecItemCopyMatching(existence_query, &existence_result);
    CFRelease(existence_query);
    if (existence_result != NULL) CFRelease(existence_result);
    if (existence_status == errSecItemNotFound) {
        CFRelease(query);
        return 0;
    }
    if (existence_status != errSecSuccess) {
        CFRelease(query);
        og_set_osstatus_error(err, err_len, "query protected product state", existence_status);
        return -1;
    }
    if (og_query_item_has_caller_only_access(query, err, err_len) != 1) {
        CFRelease(query);
        return -1;
    }
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status == errSecItemNotFound) return 0;
    if (status != errSecSuccess || result == NULL) {
        if (result != NULL) CFRelease(result);
        og_set_osstatus_error(err, err_len, "load protected product state", status);
        return -1;
    }
    if (CFGetTypeID(result) != CFDataGetTypeID()) {
        CFRelease(result);
        og_set_error(err, err_len, "protected product state is not data");
        return -1;
    }
    CFDataRef data = (CFDataRef)result;
    CFIndex length = CFDataGetLength(data);
    if (length <= 0 || length > 64) {
        CFRelease(result);
        og_set_error(err, err_len, "protected product state has invalid length");
        return -1;
    }
    unsigned char *copy = calloc((size_t)length, 1);
    if (copy == NULL) {
        CFRelease(result);
        og_set_error(err, err_len, "cannot allocate protected state buffer");
        return -1;
    }
    memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
    CFRelease(result);
    *state = copy;
    *state_len = (size_t)length;
    return 1;
}

int og_integrity_state_delete(char *err, size_t err_len) {
    CFMutableDictionaryRef query = og_keychain_query_for_service(OG_INTEGRITY_SERVICE, OG_INTEGRITY_ACCOUNT);
    if (query == NULL) {
        og_set_error(err, err_len, "cannot allocate integrity state delete query");
        return -1;
    }
    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    if (status != errSecSuccess && status != errSecItemNotFound) {
        og_set_osstatus_error(err, err_len, "delete protected product state", status);
        return -1;
    }
    return 0;
}

// Test-only ACL introspection used by the opt-in Keychain integration test.
// Returns 1 if the decrypt ACL trusts the supplied application, 0 if it does
// not, and -1 on an API/query failure.
int og_integrity_state_acl_trusts_path_for_testing(const char *path, char *err, size_t err_len) {
    if (path == NULL) {
        og_set_error(err, err_len, "invalid trusted application path");
        return -1;
    }
    CFMutableDictionaryRef query = og_keychain_query_for_service(OG_INTEGRITY_SERVICE, OG_INTEGRITY_ACCOUNT);
    if (query == NULL) {
        og_set_error(err, err_len, "cannot allocate ACL inspection query");
        return -1;
    }
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef raw_item = NULL;
    OSStatus status = SecItemCopyMatching(query, &raw_item);
    CFRelease(query);
    if (status != errSecSuccess || raw_item == NULL) {
        if (raw_item != NULL) CFRelease(raw_item);
        og_set_osstatus_error(err, err_len, "load protected state Keychain reference", status);
        return -1;
    }
    SecAccessRef access = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = SecKeychainItemCopyAccess((SecKeychainItemRef)raw_item, &access);
#pragma clang diagnostic pop
    CFRelease(raw_item);
    if (status != errSecSuccess || access == NULL) {
        if (access != NULL) CFRelease(access);
        og_set_osstatus_error(err, err_len, "copy protected state ACL", status);
        return -1;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CFArrayRef acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
#pragma clang diagnostic pop
    CFRelease(access);
    if (acls == NULL) {
        og_set_error(err, err_len, "protected state has no decrypt ACL");
        return -1;
    }
    SecTrustedApplicationRef expected = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = SecTrustedApplicationCreateFromPath(path, &expected);
#pragma clang diagnostic pop
    if (status != errSecSuccess || expected == NULL) {
        CFRelease(acls);
        if (expected != NULL) CFRelease(expected);
        og_set_osstatus_error(err, err_len, "create expected trusted application", status);
        return -1;
    }
    CFDataRef expected_data = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = SecTrustedApplicationCopyData(expected, &expected_data);
#pragma clang diagnostic pop
    CFRelease(expected);
    if (status != errSecSuccess || expected_data == NULL) {
        CFRelease(acls);
        if (expected_data != NULL) CFRelease(expected_data);
        og_set_osstatus_error(err, err_len, "copy expected trusted application identity", status);
        return -1;
    }
    int found = 0;
    CFIndex acl_count = CFArrayGetCount(acls);
    for (CFIndex i = 0; i < acl_count && !found; i++) {
        CFArrayRef applications = NULL;
        CFStringRef description = NULL;
        SecKeychainPromptSelector prompt = {0};
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        status = SecACLCopyContents((SecACLRef)CFArrayGetValueAtIndex(acls, i),
            &applications, &description, &prompt);
#pragma clang diagnostic pop
        if (description != NULL) CFRelease(description);
        if (status != errSecSuccess) {
            if (applications != NULL) CFRelease(applications);
            CFRelease(expected_data);
            CFRelease(acls);
            og_set_osstatus_error(err, err_len, "inspect protected state decrypt ACL", status);
            return -1;
        }
        if (applications != NULL) {
            CFIndex app_count = CFArrayGetCount(applications);
            for (CFIndex j = 0; j < app_count; j++) {
                CFDataRef application_data = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
                status = SecTrustedApplicationCopyData(
                    (SecTrustedApplicationRef)CFArrayGetValueAtIndex(applications, j), &application_data);
#pragma clang diagnostic pop
                if (status == errSecSuccess && application_data != NULL && CFEqual(application_data, expected_data)) {
                    found = 1;
                }
                if (application_data != NULL) CFRelease(application_data);
                if (found) break;
            }
            CFRelease(applications);
        }
    }
    CFRelease(expected_data);
    CFRelease(acls);
    return found;
}

int og_list_osascript(unsigned int uid, og_process_info *out, int capacity, char *err, size_t err_len) {
    if (out == NULL || capacity <= 0) {
        og_set_error(err, err_len, "invalid process output buffer");
        return -1;
    }
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0) {
        og_set_error(err, err_len, "proc_listpids size query failed");
        return -1;
    }
    int *pids = calloc((size_t)bytes / sizeof(int) + 32, sizeof(int));
    if (pids == NULL) {
        og_set_error(err, err_len, "cannot allocate process list");
        return -1;
    }
    bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes);
    if (bytes < 0) {
        free(pids);
        og_set_error(err, err_len, "proc_listpids failed");
        return -1;
    }

    int count = 0;
    int pid_count = bytes / (int)sizeof(int);
    for (int i = 0; i < pid_count; i++) {
        int pid = pids[i];
        if (pid <= 0) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
        if (proc_pidpath(pid, path, sizeof(path)) <= 0 || strcmp(path, "/usr/bin/osascript") != 0) {
            continue;
        }
        struct proc_bsdinfo info;
        memset(&info, 0, sizeof(info));
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info) || info.pbi_uid != uid) {
            continue;
        }
        if (count >= capacity) {
            count++;
            continue;
        }
        out[count].pid = pid;
        out[count].ppid = (int)info.pbi_ppid;
        out[count].uid = info.pbi_uid;
        out[count].start_seconds = (long long)info.pbi_start_tvsec;
        snprintf(out[count].executable_path, sizeof(out[count].executable_path), "%s", path);
        if (proc_pidpath((int)info.pbi_ppid, out[count].parent_path, sizeof(out[count].parent_path)) <= 0) {
            out[count].parent_path[0] = '\0';
        }
        out[count].parent_code_valid = og_copy_process_identity((pid_t)info.pbi_ppid,
            out[count].parent_code_identifier, sizeof(out[count].parent_code_identifier),
            out[count].parent_cdhash, sizeof(out[count].parent_cdhash));
        count++;
    }
    free(pids);
    return count;
}

int og_copy_process_args(int pid, unsigned char **data, size_t *data_len, char *err, size_t err_len) {
    if (pid <= 0 || data == NULL || data_len == NULL) {
        og_set_error(err, err_len, "invalid process argument request");
        return -1;
    }
    *data = NULL;
    *data_len = 0;
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t size = 0;
    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 || size == 0 || size > (1U << 20)) {
        og_set_error(err, err_len, "sysctl process argument size query failed");
        return -1;
    }
    unsigned char *buffer = calloc(size, 1);
    if (buffer == NULL) {
        og_set_error(err, err_len, "cannot allocate process argument buffer");
        return -1;
    }
    if (sysctl(mib, 3, buffer, &size, NULL, 0) != 0) {
        free(buffer);
        og_set_error(err, err_len, "sysctl process argument query failed");
        return -1;
    }
    *data = buffer;
    *data_len = size;
    return 0;
}

void og_free(void *ptr) {
    if (ptr != NULL) {
        free(ptr);
    }
}

void og_secure_free(void *ptr, size_t len) {
    if (ptr == NULL) return;
    volatile unsigned char *bytes = (volatile unsigned char *)ptr;
    while (len > 0) {
        *bytes++ = 0;
        len--;
    }
    free(ptr);
}

int og_inject_text_to_pid(int pid, const unsigned short *units, size_t unit_count, char *err, size_t err_len) {
    if (pid <= 0 || units == NULL || unit_count == 0 || unit_count > 4096) {
        og_set_error(err, err_len, "invalid targeted text injection request");
        return -1;
    }
    if (!AXIsProcessTrusted()) {
        og_set_error(err, err_len, "macOS Accessibility permission is required");
        return -1;
    }
    og_auth_snapshot snapshot;
    if (!og_snapshot_for_pid((pid_t)pid, &snapshot) || !og_supported_auth_process(&snapshot) ||
        !snapshot.is_auth_dialog || snapshot.focused_value_length != 0) {
        og_set_error(err, err_len, "target PID is no longer an approved empty Apple authorization field");
        return -1;
    }
    CGEventSourceRef source = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
    if (source == NULL) {
        og_set_error(err, err_len, "CGEventSourceCreate failed");
        return -1;
    }
    CGEventRef down = CGEventCreateKeyboardEvent(source, 0, true);
    CGEventRef up = CGEventCreateKeyboardEvent(source, 0, false);
    if (down == NULL || up == NULL) {
        if (down != NULL) CFRelease(down);
        if (up != NULL) CFRelease(up);
        CFRelease(source);
        og_set_error(err, err_len, "CGEventCreateKeyboardEvent failed");
        return -1;
    }
    CGEventKeyboardSetUnicodeString(down, (UniCharCount)unit_count, (const UniChar *)units);
    CGEventKeyboardSetUnicodeString(up, (UniCharCount)unit_count, (const UniChar *)units);
    CGEventPostToPid((pid_t)pid, down);
    CGEventPostToPid((pid_t)pid, up);
    CFRelease(down);
    CFRelease(up);
    CFRelease(source);
    return 0;
}

int og_inject_return_to_pid(int pid, int expected_length, char *err, size_t err_len) {
    if (pid <= 0 || expected_length <= 0) {
        og_set_error(err, err_len, "invalid targeted Return injection request");
        return -1;
    }
    if (!AXIsProcessTrusted()) {
        og_set_error(err, err_len, "macOS Accessibility permission is required");
        return -1;
    }
    og_auth_snapshot snapshot;
    if (!og_snapshot_for_pid((pid_t)pid, &snapshot) || !og_supported_auth_process(&snapshot) || !snapshot.is_auth_dialog ||
        snapshot.focused_value_length != expected_length) {
        og_set_error(err, err_len, "target PID is no longer the approved populated Apple authorization field");
        return -1;
    }
    CGEventSourceRef source = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
    if (source == NULL) {
        og_set_error(err, err_len, "CGEventSourceCreate failed");
        return -1;
    }
    CGEventRef down = CGEventCreateKeyboardEvent(source, 36, true);
    CGEventRef up = CGEventCreateKeyboardEvent(source, 36, false);
    if (down == NULL || up == NULL) {
        if (down != NULL) CFRelease(down);
        if (up != NULL) CFRelease(up);
        CFRelease(source);
        og_set_error(err, err_len, "CGEventCreateKeyboardEvent(Return) failed");
        return -1;
    }
    CGEventPostToPid((pid_t)pid, down);
    CGEventPostToPid((pid_t)pid, up);
    CFRelease(down);
    CFRelease(up);
    CFRelease(source);
    return 0;
}

int og_session_unlocked(void) {
    CFDictionaryRef session = CGSessionCopyCurrentDictionary();
    if (session == NULL) {
        return 0;
    }
    int unlocked = 1;
    CFBooleanRef on_console = CFDictionaryGetValue(session, CFSTR("kCGSessionOnConsoleKey"));
    if (on_console != NULL && CFGetTypeID(on_console) == CFBooleanGetTypeID() && !CFBooleanGetValue(on_console)) {
        unlocked = 0;
    }
    CFBooleanRef locked = CFDictionaryGetValue(session, CFSTR("CGSSessionScreenIsLocked"));
    if (locked != NULL && CFGetTypeID(locked) == CFBooleanGetTypeID() && CFBooleanGetValue(locked)) {
        unlocked = 0;
    }
    CFRelease(session);
    return unlocked;
}

int og_accessibility_trusted(void) {
    return AXIsProcessTrusted() ? 1 : 0;
}

int og_request_accessibility(void) {
    const void *keys[] = {kAXTrustedCheckOptionPrompt};
    const void *values[] = {kCFBooleanTrue};
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (options == NULL) {
        return 0;
    }
    Boolean trusted = AXIsProcessTrustedWithOptions(options);
    CFRelease(options);
    return trusted ? 1 : 0;
}
