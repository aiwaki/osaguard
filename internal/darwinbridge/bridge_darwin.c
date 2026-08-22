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

// v2 deliberately starts with fresh items. Preview builds before 0.1.3 used
// unversioned services whose ACLs are bound to their changing ad-hoc identity.
// Never query or mutate those legacy records from the new signing identity.
static const char *OG_KEYCHAIN_SERVICE = "dev.aiwaki.osaguard.admin-password.v2";
static const char *OG_INTEGRITY_SERVICE = "dev.aiwaki.osaguard.integrity-state.v2";
static const char *OG_INTEGRITY_ACCOUNT = "product";
static const char *OG_KEYCHAIN_LABEL = "OsaGuard administrator password";
static const char *OG_INTEGRITY_LABEL = "OsaGuard protected product state";

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

static void og_set_keychain_osstatus_error(char *err, size_t err_len,
    const char *operation, OSStatus status) {
    if (status == errSecInteractionNotAllowed || status == errSecInteractionRequired) {
        if (err != NULL && err_len > 0) {
            snprintf(err, err_len, "keychain_interaction_not_allowed: %s", operation);
        }
        return;
    }
    og_set_osstatus_error(err, err_len, operation, status);
}

static OSStatus og_keychain_require_noninteractive(void) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return SecKeychainSetUserInteractionAllowed(false);
#pragma clang diagnostic pop
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

static void og_keychain_suppress_authentication_ui(CFMutableDictionaryRef query) {
    if (query == NULL) return;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
#pragma clang diagnostic pop
}

// All production SecItem operations go through these wrappers. Legacy file
// Keychain records must return errSecInteractionNotAllowed instead of opening
// SecurityAgent when their ACL or lock state requires user interaction.
static OSStatus og_sec_item_copy_matching(CFMutableDictionaryRef query, CFTypeRef *result) {
    OSStatus status = og_keychain_require_noninteractive();
    if (status != errSecSuccess) return status;
    og_keychain_suppress_authentication_ui(query);
    return SecItemCopyMatching(query, result);
}

static OSStatus og_sec_item_update(CFMutableDictionaryRef query, CFDictionaryRef updates) {
    OSStatus status = og_keychain_require_noninteractive();
    if (status != errSecSuccess) return status;
    og_keychain_suppress_authentication_ui(query);
    return SecItemUpdate(query, updates);
}

static OSStatus og_sec_item_add(CFMutableDictionaryRef attributes, CFTypeRef *result) {
    OSStatus status = og_keychain_require_noninteractive();
    if (status != errSecSuccess) return status;
    og_keychain_suppress_authentication_ui(attributes);
    return SecItemAdd(attributes, result);
}

static OSStatus og_sec_item_delete(CFMutableDictionaryRef query) {
    OSStatus status = og_keychain_require_noninteractive();
    if (status != errSecSuccess) return status;
    og_keychain_suppress_authentication_ui(query);
    return SecItemDelete(query);
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
        og_keychain_suppress_authentication_ui(query);
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

static int og_cfarray_equal_unordered_unique(CFArrayRef left, CFArrayRef right) {
    if (left == NULL || right == NULL) return left == right;
    CFIndex count = CFArrayGetCount(left);
    if (count != CFArrayGetCount(right)) return 0;
    for (CFIndex index = 0; index < count; index++) {
        CFTypeRef value = CFArrayGetValueAtIndex(left, index);
        CFRange whole = CFRangeMake(0, count);
        if (CFArrayGetCountOfValue(left, whole, value) != 1 ||
            CFArrayGetCountOfValue(right, whole, value) != 1) {
            return 0;
        }
    }
    return 1;
}

static CFMutableArrayRef og_copy_trusted_application_data(
    CFArrayRef applications, OSStatus *status) {
    if (status == NULL) return NULL;
    *status = errSecSuccess;
    if (applications == NULL) return NULL;
    CFMutableArrayRef data_values = CFArrayCreateMutable(
        NULL, 0, &kCFTypeArrayCallBacks);
    if (data_values == NULL) {
        *status = errSecAllocate;
        return NULL;
    }
    CFIndex count = CFArrayGetCount(applications);
    for (CFIndex index = 0; index < count; index++) {
        CFDataRef data = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        *status = SecTrustedApplicationCopyData(
            (SecTrustedApplicationRef)CFArrayGetValueAtIndex(applications, index), &data);
#pragma clang diagnostic pop
        if (*status != errSecSuccess || data == NULL) {
            if (data != NULL) CFRelease(data);
            CFRelease(data_values);
            return NULL;
        }
        CFArrayAppendValue(data_values, data);
        CFRelease(data);
    }
    return data_values;
}

// Compare every authorization, trusted application, prompt selector and
// descriptor on an ACL. The runtime template is created by SecAccessCreate for
// the current executable, so this rejects a pre-seeded item that grants only
// decrypt access to OsaGuard while retaining a separate ChangeACL/ChangeOwner
// path for another application.
static int og_acl_matches_template(SecACLRef actual, SecACLRef expected,
    char *err, size_t err_len) {
    if (actual == NULL || expected == NULL) return 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CFArrayRef actual_authorizations = SecACLCopyAuthorizations(actual);
    CFArrayRef expected_authorizations = SecACLCopyAuthorizations(expected);
#pragma clang diagnostic pop
    if (actual_authorizations == NULL || expected_authorizations == NULL) {
        if (actual_authorizations != NULL) CFRelease(actual_authorizations);
        if (expected_authorizations != NULL) CFRelease(expected_authorizations);
        og_set_error(err, err_len, "cannot inspect complete Keychain ACL authorizations");
        return -1;
    }
    int authorizations_match = og_cfarray_equal_unordered_unique(
        actual_authorizations, expected_authorizations);
    CFRelease(actual_authorizations);
    CFRelease(expected_authorizations);
    if (!authorizations_match) return 0;

    CFArrayRef actual_applications = NULL;
    CFArrayRef expected_applications = NULL;
    CFStringRef actual_description = NULL;
    CFStringRef expected_description = NULL;
    SecKeychainPromptSelector actual_prompt = 0;
    SecKeychainPromptSelector expected_prompt = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus actual_status = SecACLCopyContents(actual, &actual_applications,
        &actual_description, &actual_prompt);
    OSStatus expected_status = SecACLCopyContents(expected, &expected_applications,
        &expected_description, &expected_prompt);
#pragma clang diagnostic pop
    if (actual_status != errSecSuccess || expected_status != errSecSuccess) {
        if (actual_applications != NULL) CFRelease(actual_applications);
        if (expected_applications != NULL) CFRelease(expected_applications);
        if (actual_description != NULL) CFRelease(actual_description);
        if (expected_description != NULL) CFRelease(expected_description);
        og_set_keychain_osstatus_error(err, err_len,
            "inspect complete Keychain ACL contents",
            actual_status != errSecSuccess ? actual_status : expected_status);
        return -1;
    }

    int descriptions_match =
        (actual_description == NULL && expected_description == NULL) ||
        (actual_description != NULL && expected_description != NULL &&
            CFEqual(actual_description, expected_description));
    OSStatus actual_data_status = errSecSuccess;
    OSStatus expected_data_status = errSecSuccess;
    CFMutableArrayRef actual_data = og_copy_trusted_application_data(
        actual_applications, &actual_data_status);
    CFMutableArrayRef expected_data = og_copy_trusted_application_data(
        expected_applications, &expected_data_status);
    int application_nullness_matches =
        (actual_applications == NULL) == (expected_applications == NULL);
    int applications_match = application_nullness_matches &&
        actual_data_status == errSecSuccess && expected_data_status == errSecSuccess &&
        og_cfarray_equal_unordered_unique(actual_data, expected_data);
    if (actual_applications != NULL) CFRelease(actual_applications);
    if (expected_applications != NULL) CFRelease(expected_applications);
    if (actual_description != NULL) CFRelease(actual_description);
    if (expected_description != NULL) CFRelease(expected_description);
    if (actual_data != NULL) CFRelease(actual_data);
    if (expected_data != NULL) CFRelease(expected_data);
    if (actual_data_status != errSecSuccess || expected_data_status != errSecSuccess) {
        og_set_keychain_osstatus_error(err, err_len,
            "inspect complete Keychain trusted applications",
            actual_data_status != errSecSuccess ? actual_data_status : expected_data_status);
        return -1;
    }
    // A trusted application already provides the no-prompt path. Prompt flags
    // make status/save/load behavior depend on SecurityAgent and are rejected.
    if (actual_prompt != 0 || expected_prompt != 0) return 0;
    return descriptions_match && applications_match ? 1 : 0;
}

static int og_access_matches_template(SecAccessRef actual, SecAccessRef expected,
    char *err, size_t err_len) {
    if (actual == NULL || expected == NULL) {
        og_set_error(err, err_len, "missing Keychain access template");
        return -1;
    }
    OSStatus status = og_keychain_require_noninteractive();
    if (status != errSecSuccess) {
        og_set_keychain_osstatus_error(err, err_len,
            "disable Keychain interaction before full ACL inspection", status);
        return -1;
    }
    uid_t actual_uid = 0;
    uid_t expected_uid = 0;
    gid_t actual_gid = 0;
    gid_t expected_gid = 0;
    SecAccessOwnerType actual_owner = 0;
    SecAccessOwnerType expected_owner = 0;
    CFArrayRef actual_acls = NULL;
    CFArrayRef expected_acls = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus actual_status = SecAccessCopyOwnerAndACL(actual, &actual_uid,
        &actual_gid, &actual_owner, &actual_acls);
    OSStatus expected_status = SecAccessCopyOwnerAndACL(expected, &expected_uid,
        &expected_gid, &expected_owner, &expected_acls);
#pragma clang diagnostic pop
    if (actual_status != errSecSuccess || expected_status != errSecSuccess ||
        actual_acls == NULL || expected_acls == NULL) {
        if (actual_acls != NULL) CFRelease(actual_acls);
        if (expected_acls != NULL) CFRelease(expected_acls);
        og_set_keychain_osstatus_error(err, err_len,
            "inspect complete Keychain access template",
            actual_status != errSecSuccess ? actual_status : expected_status);
        return -1;
    }

    CFIndex expected_count = CFArrayGetCount(expected_acls);
    CFIndex actual_count = CFArrayGetCount(actual_acls);
    int matches = actual_uid == expected_uid && actual_gid == expected_gid &&
        actual_owner == expected_owner && expected_count > 0 &&
        actual_count == expected_count;
    if (!matches) {
        CFRelease(actual_acls);
        CFRelease(expected_acls);
        og_set_error(err, err_len,
            "keychain_access_conflict: complete access template does not match the current application");
        return 0;
    }
    int *used = calloc((size_t)expected_count, sizeof(*used));
    if (used == NULL) {
        CFRelease(actual_acls);
        CFRelease(expected_acls);
        og_set_error(err, err_len, "cannot allocate complete Keychain ACL comparison state");
        return -1;
    }
    for (CFIndex actual_index = 0; matches && actual_index < expected_count; actual_index++) {
        int found = 0;
        for (CFIndex expected_index = 0; expected_index < expected_count; expected_index++) {
            if (used[expected_index]) continue;
            int acl_match = og_acl_matches_template(
                (SecACLRef)CFArrayGetValueAtIndex(actual_acls, actual_index),
                (SecACLRef)CFArrayGetValueAtIndex(expected_acls, expected_index),
                err, err_len);
            if (acl_match < 0) {
                free(used);
                CFRelease(actual_acls);
                CFRelease(expected_acls);
                return -1;
            }
            if (acl_match == 1) {
                used[expected_index] = 1;
                found = 1;
                break;
            }
        }
        if (!found) matches = 0;
    }
    free(used);
    CFRelease(actual_acls);
    CFRelease(expected_acls);
    if (!matches) {
        og_set_error(err, err_len,
            "keychain_access_conflict: complete access template does not match the current application");
        return 0;
    }
    return 1;
}

static int og_access_is_caller_only(SecAccessRef access, const char *label,
    char *err, size_t err_len) {
    if (access == NULL || label == NULL) {
        og_set_error(err, err_len, "missing Keychain access object or label");
        return -1;
    }
    OSStatus status = og_keychain_require_noninteractive();
    if (status != errSecSuccess) {
        og_set_keychain_osstatus_error(err, err_len,
            "disable Keychain interaction before template creation", status);
        return -1;
    }
    CFStringRef label_string = CFStringCreateWithCString(
        NULL, label, kCFStringEncodingUTF8);
    if (label_string == NULL) {
        og_set_error(err, err_len, "cannot allocate caller-only Keychain access label");
        return -1;
    }
    SecAccessRef expected = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = SecAccessCreate(label_string, NULL, &expected);
#pragma clang diagnostic pop
    CFRelease(label_string);
    if (status != errSecSuccess || expected == NULL) {
        if (expected != NULL) CFRelease(expected);
        og_set_keychain_osstatus_error(err, err_len,
            "create caller-only Keychain access template", status);
        return -1;
    }
    int matches = og_access_matches_template(access, expected, err, err_len);
    CFRelease(expected);
    return matches;
}

static OSStatus og_keychain_item_copy_access_noninteractive(
    SecKeychainItemRef item, SecAccessRef *access) {
    OSStatus status = og_keychain_require_noninteractive();
    if (status != errSecSuccess) return status;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return SecKeychainItemCopyAccess(item, access);
#pragma clang diagnostic pop
}

static int og_item_has_caller_only_access(SecKeychainItemRef item,
    const char *label, char *err, size_t err_len) {
    if (item == NULL) {
        og_set_error(err, err_len, "missing Keychain item for ACL verification");
        return -1;
    }
    SecAccessRef access = NULL;
    OSStatus status = og_keychain_item_copy_access_noninteractive(item, &access);
    if (status != errSecSuccess || access == NULL) {
        if (access != NULL) CFRelease(access);
        og_set_keychain_osstatus_error(err, err_len, "copy stored Keychain ACL", status);
        return -1;
    }
    int caller_only = og_access_is_caller_only(access, label, err, err_len);
    CFRelease(access);
    return caller_only;
}

// Return 1 and a retained exact item reference after complete access-template
// verification, 0 when absent, 2 for a typed access conflict, and -1 for an
// inspection failure. Callers must use the returned reference for any later
// data access or mutation instead of repeating the broad service/account query.
static int og_keychain_copy_verified_item(CFDictionaryRef base_query,
    const char *label, SecKeychainItemRef *item_out, char *err, size_t err_len) {
    if (base_query == NULL || label == NULL || item_out == NULL) {
        og_set_error(err, err_len, "invalid verified Keychain item lookup");
        return -1;
    }
    *item_out = NULL;
    CFMutableDictionaryRef query = CFDictionaryCreateMutableCopy(NULL, 0, base_query);
    if (query == NULL) {
        og_set_error(err, err_len, "cannot allocate Keychain ACL verification query");
        return -1;
    }
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef raw_item = NULL;
    OSStatus status = og_sec_item_copy_matching(query, &raw_item);
    CFRelease(query);
    if (status == errSecItemNotFound) return 0;
    if (status != errSecSuccess || raw_item == NULL) {
        if (raw_item != NULL) CFRelease(raw_item);
        if (status == errSecSuccess) {
            og_set_error(err, err_len,
                "Keychain ACL verification query returned no item reference");
        } else {
            og_set_keychain_osstatus_error(err, err_len,
                "load Keychain item for ACL verification", status);
        }
        return -1;
    }
    int caller_only = og_item_has_caller_only_access(
        (SecKeychainItemRef)raw_item, label, err, err_len);
    if (caller_only == 1) {
        *item_out = (SecKeychainItemRef)raw_item;
        return 1;
    }
    CFRelease(raw_item);
    return caller_only == 0 ? 2 : -1;
}

// Read data only through a previously verified stable item reference. If that
// item disappears after verification, return 0; a same-service replacement is
// deliberately not considered and therefore cannot win a check/use race.
static int og_keychain_copy_verified_item_data(SecKeychainItemRef item,
    CFDataRef *data_out, const char *operation, char *err, size_t err_len) {
    if (item == NULL || data_out == NULL || operation == NULL) {
        og_set_error(err, err_len, "invalid exact Keychain data lookup");
        return -1;
    }
    *data_out = NULL;
    const void *item_values[] = {item};
    CFArrayRef item_list = CFArrayCreate(
        NULL, item_values, 1, &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (item_list == NULL || query == NULL) {
        if (item_list != NULL) CFRelease(item_list);
        if (query != NULL) CFRelease(query);
        og_set_error(err, err_len, "cannot allocate exact Keychain data query");
        return -1;
    }
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecMatchItemList, item_list);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = og_sec_item_copy_matching(query, &result);
    CFRelease(query);
    CFRelease(item_list);
    if (status == errSecItemNotFound) return 0;
    if (status != errSecSuccess || result == NULL) {
        if (result != NULL) CFRelease(result);
        if (status == errSecSuccess) {
            og_set_error(err, err_len,
                "exact Keychain data query returned no data");
        } else {
            og_set_keychain_osstatus_error(err, err_len, operation, status);
        }
        return -1;
    }
    if (CFGetTypeID(result) != CFDataGetTypeID()) {
        CFRelease(result);
        og_set_error(err, err_len, "exact Keychain result is not data");
        return -1;
    }
    *data_out = (CFDataRef)result;
    return 1;
}

// Delete exactly the item reference returned by the service/account lookup,
// and only after its complete runtime access template has been verified. A
// colliding record with a prompt-enabled, additional, or otherwise unknown ACL
// is left untouched and reported as a typed re-enrolment conflict.
static int og_keychain_delete_verified_item(CFDictionaryRef base_query,
    const char *label, const char *delete_operation,
    char *err, size_t err_len) {
    SecKeychainItemRef item = NULL;
    int item_state = og_keychain_copy_verified_item(
        base_query, label, &item, err, err_len);
    if (item_state == 0) return 0;
    if (item_state != 1) return -1;
    const void *item_values[] = {item};
    CFArrayRef item_list = CFArrayCreate(
        NULL, item_values, 1, &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef delete_query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (item_list == NULL || delete_query == NULL) {
        if (item_list != NULL) CFRelease(item_list);
        if (delete_query != NULL) CFRelease(delete_query);
        CFRelease(item);
        og_set_error(err, err_len, "cannot allocate exact Keychain deletion query");
        return -1;
    }
    CFDictionarySetValue(delete_query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(delete_query, kSecMatchItemList, item_list);
    OSStatus status = og_sec_item_delete(delete_query);
    CFRelease(delete_query);
    CFRelease(item_list);
    CFRelease(item);
    if (status != errSecSuccess && status != errSecItemNotFound) {
        og_set_keychain_osstatus_error(err, err_len, delete_operation, status);
        return -1;
    }
    return 0;
}

// Return 0 after updating an existing item, 1 when no item exists, and -1 on
// failure. The exact item reference is retained in kSecMatchItemList so a
// delete-and-recreate race cannot redirect password bytes to another record.
static int og_keychain_update_existing_item(CFDictionaryRef base_query, CFDataRef data,
    const char *label, char *err, size_t err_len) {
    CFMutableDictionaryRef lookup_query = CFDictionaryCreateMutableCopy(NULL, 0, base_query);
    if (lookup_query == NULL) {
        og_set_error(err, err_len, "cannot allocate Keychain item lookup");
        return -1;
    }
    CFDictionarySetValue(lookup_query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(lookup_query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef raw_item = NULL;
    OSStatus status = og_sec_item_copy_matching(lookup_query, &raw_item);
    CFRelease(lookup_query);
    if (status == errSecItemNotFound) return 1;
    if (status != errSecSuccess || raw_item == NULL) {
        if (raw_item != NULL) CFRelease(raw_item);
        og_set_keychain_osstatus_error(err, err_len, "load the existing Keychain item", status);
        return -1;
    }

    SecKeychainItemRef item = (SecKeychainItemRef)raw_item;
    if (og_item_has_caller_only_access(item, label, err, err_len) != 1) {
        // A mismatched v2 ACL is treated as a conflicting item, never as a
        // migration opportunity. In particular, do not call SecItemUpdate or
        // SecKeychainItemSetAccess for an item that this build does not own.
        CFRelease(raw_item);
        return -1;
    }

    const void *item_values[] = {item};
    CFArrayRef item_list = CFArrayCreate(NULL, item_values, 1, &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef update_query = CFDictionaryCreateMutableCopy(NULL, 0, base_query);
    CFMutableDictionaryRef updates = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (item_list == NULL || update_query == NULL || updates == NULL) {
        if (item_list != NULL) CFRelease(item_list);
        if (update_query != NULL) CFRelease(update_query);
        if (updates != NULL) CFRelease(updates);
        CFRelease(raw_item);
        og_set_error(err, err_len, "cannot allocate the Keychain value update");
        return -1;
    }
    CFDictionarySetValue(update_query, kSecMatchItemList, item_list);
    CFDictionarySetValue(updates, kSecValueData, data);
    status = og_sec_item_update(update_query, updates);
    CFRelease(updates);
    CFRelease(update_query);
    CFRelease(item_list);
    CFRelease(raw_item);
    if (status != errSecSuccess) {
        // SecItemUpdate commits the new bytes atomically. A failure therefore
        // leaves the previous password value intact.
        og_set_keychain_osstatus_error(err, err_len, "update the protected Keychain value", status);
        return -1;
    }
    return 0;
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
    CFStringRef label_string = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);
    if (query == NULL || data == NULL || label_string == NULL) {
        if (query != NULL) CFRelease(query);
        if (data != NULL) CFRelease(data);
        if (label_string != NULL) CFRelease(label_string);
        og_set_error(err, err_len, "cannot allocate keychain query");
        return -1;
    }

    int existing_result = og_keychain_update_existing_item(
        query, data, label, err, err_len);
    if (existing_result == 0) {
        CFRelease(label_string);
        CFRelease(data);
        CFRelease(query);
        return 0;
    }
    if (existing_result < 0) {
        CFRelease(label_string);
        CFRelease(data);
        CFRelease(query);
        return -1;
    }

    // Per SecAccessCreate, a NULL trusted list restricts a new item to the
    // application creating it. Existing v2 items take the separate path above:
    // their caller-only ACL is verified without modification, then only their
    // password bytes are atomically updated.
    SecAccessRef access = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus status = SecAccessCreate(label_string, NULL, &access);
#pragma clang diagnostic pop
    if (status != errSecSuccess || access == NULL) {
        CFRelease(label_string);
        CFRelease(data);
        CFRelease(query);
        og_set_osstatus_error(err, err_len, "create caller-only Keychain ACL", status);
        return -1;
    }
    int fresh_access_check = og_access_is_caller_only(
        access, label, err, err_len);
    if (fresh_access_check != 1) {
        CFRelease(access);
        CFRelease(label_string);
        CFRelease(data);
        CFRelease(query);
        return -1;
    }

    CFMutableDictionaryRef item = CFDictionaryCreateMutableCopy(NULL, 0, query);
    if (item == NULL) {
        CFRelease(access);
        CFRelease(label_string);
        CFRelease(data);
        CFRelease(query);
        og_set_error(err, err_len, "cannot allocate keychain item");
        return -1;
    }
    CFDictionarySetValue(item, kSecAttrLabel, label_string);
    CFDictionarySetValue(item, kSecAttrAccess, access);
    CFDictionarySetValue(item, kSecValueData, data);
    status = og_sec_item_add(item, NULL);
    CFRelease(item);
    if (status == errSecDuplicateItem) {
        // Another process won the add race. Re-run the exact-reference update;
        // it applies the same ACL proof and never falls back to a broad query.
        existing_result = og_keychain_update_existing_item(
            query, data, label, err, err_len);
        if (existing_result == 0) status = errSecSuccess;
        else if (existing_result > 0) {
            og_set_error(err, err_len, "the duplicate Keychain item disappeared before it could be updated");
            status = errSecItemNotFound;
        } else {
            status = errSecAuthFailed;
        }
    }
    CFRelease(access);
    CFRelease(label_string);
    CFRelease(data);
    CFRelease(query);
    if (status != errSecSuccess) {
        if (existing_result >= 0) {
            og_set_keychain_osstatus_error(err, err_len, "store protected value in Keychain", status);
        }
        return -1;
    }
    return 0;
}

int og_keychain_store(const char *account, const unsigned char *secret, size_t secret_len, char *err, size_t err_len) {
    return og_keychain_store_for_service(OG_KEYCHAIN_SERVICE, account, secret, secret_len,
        OG_KEYCHAIN_LABEL, err, err_len);
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
    SecKeychainItemRef item = NULL;
    int item_state = og_keychain_copy_verified_item(
        query, OG_KEYCHAIN_LABEL, &item, err, err_len);
    CFRelease(query);
    if (item_state != 1) {
        if (item_state == 0) {
            og_set_keychain_osstatus_error(err, err_len,
                "load password from Keychain", errSecItemNotFound);
        }
        return -1;
    }
    CFDataRef data = NULL;
    int data_state = og_keychain_copy_verified_item_data(
        item, &data, "load password from Keychain", err, err_len);
    CFRelease(item);
    if (data_state != 1) {
        if (data_state == 0) {
            og_set_keychain_osstatus_error(err, err_len,
                "load password from Keychain", errSecItemNotFound);
        }
        return -1;
    }
    CFIndex length = CFDataGetLength(data);
    if (length <= 0 || length > 4096) {
        CFRelease(data);
        og_set_error(err, err_len, "Keychain password has invalid length");
        return -1;
    }
    unsigned char *copy = calloc((size_t)length, 1);
    if (copy == NULL) {
        CFRelease(data);
        og_set_error(err, err_len, "cannot allocate password buffer");
        return -1;
    }
    memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
    CFRelease(data);
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
    SecKeychainItemRef item = NULL;
    int item_state = og_keychain_copy_verified_item(
        query, OG_KEYCHAIN_LABEL, &item, err, err_len);
    CFRelease(query);
    if (item != NULL) CFRelease(item);
    // A metadata match with a different complete access template is not a
    // transport failure. Report it separately so a newly signed/ad-hoc
    // application can stay fail-closed and ask the user to re-enrol.
    return item_state;
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
    int result = og_keychain_delete_verified_item(
        query, OG_KEYCHAIN_LABEL,
        "delete verified password from Keychain", err, err_len);
    CFRelease(query);
    return result;
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
    OSStatus status = og_sec_item_copy_matching(query, &raw_items);
    CFRelease(query);
    if (status == errSecItemNotFound) return 0;
    if (status != errSecSuccess || raw_items == NULL) {
        if (raw_items != NULL) CFRelease(raw_items);
        og_set_keychain_osstatus_error(err, err_len, "list OsaGuard passwords for deletion", status);
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
        int caller_only = og_item_has_caller_only_access(
            (SecKeychainItemRef)item, OG_KEYCHAIN_LABEL, err, err_len);
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
    status = og_sec_item_delete(delete_query);
    CFRelease(delete_query);
    CFRelease(raw_items);
    if (status != errSecSuccess && status != errSecItemNotFound) {
        og_set_keychain_osstatus_error(err, err_len, "delete verified OsaGuard passwords from Keychain", status);
        return -1;
    }
    return 0;
}

int og_integrity_state_store(const unsigned char *state, size_t state_len, char *err, size_t err_len) {
    return og_keychain_store_for_service(OG_INTEGRITY_SERVICE, OG_INTEGRITY_ACCOUNT,
        state, state_len, OG_INTEGRITY_LABEL, err, err_len);
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
    SecKeychainItemRef item = NULL;
    int item_state = og_keychain_copy_verified_item(
        query, OG_INTEGRITY_LABEL, &item, err, err_len);
    CFRelease(query);
    if (item_state != 1) {
        // Keep the protected state unread and distinguish an old/foreign ACL
        // from an actual Keychain failure. Callers must never treat 2 as an
        // acknowledged or enabled state.
        return item_state;
    }
    CFDataRef data = NULL;
    int data_state = og_keychain_copy_verified_item_data(
        item, &data, "load protected product state", err, err_len);
    CFRelease(item);
    if (data_state != 1) return data_state;
    CFIndex length = CFDataGetLength(data);
    if (length <= 0 || length > 64) {
        CFRelease(data);
        og_set_error(err, err_len, "protected product state has invalid length");
        return -1;
    }
    unsigned char *copy = calloc((size_t)length, 1);
    if (copy == NULL) {
        CFRelease(data);
        og_set_error(err, err_len, "cannot allocate protected state buffer");
        return -1;
    }
    memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
    CFRelease(data);
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
    int result = og_keychain_delete_verified_item(
        query, OG_INTEGRITY_LABEL,
        "delete verified protected product state", err, err_len);
    CFRelease(query);
    return result;
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
    OSStatus status = og_sec_item_copy_matching(query, &raw_item);
    CFRelease(query);
    if (status != errSecSuccess || raw_item == NULL) {
        if (raw_item != NULL) CFRelease(raw_item);
        og_set_keychain_osstatus_error(err, err_len, "load protected state Keychain reference", status);
        return -1;
    }
    SecAccessRef access = NULL;
    status = og_keychain_item_copy_access_noninteractive((SecKeychainItemRef)raw_item, &access);
    CFRelease(raw_item);
    if (status != errSecSuccess || access == NULL) {
        if (access != NULL) CFRelease(access);
        og_set_keychain_osstatus_error(err, err_len, "copy protected state ACL", status);
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
            og_set_keychain_osstatus_error(err, err_len, "inspect protected state decrypt ACL", status);
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
