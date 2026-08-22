//go:build darwin && cgo

#import <AppKit/AppKit.h>
#import <dispatch/dispatch.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void og_dialog_set_error(char *err, size_t err_len, const char *message) {
    if (err == NULL || err_len == 0) return;
    snprintf(err, err_len, "%s", message == NULL ? "password dialog failed" : message);
}

static BOOL og_dialog_uses_russian(const char *locale) {
    if (locale != NULL && strcmp(locale, "ru") == 0) return YES;
    if (locale != NULL && strcmp(locale, "en") == 0) return NO;
    NSString *preferred = [[NSLocale preferredLanguages] firstObject];
    return preferred != nil && [preferred hasPrefix:@"ru"];
}

static NSTextField *og_dialog_label(NSString *text, NSRect frame) {
    NSTextField *label = [[NSTextField alloc] initWithFrame:frame];
    [label setStringValue:text];
    [label setEditable:NO];
    [label setSelectable:NO];
    [label setBezeled:NO];
    [label setDrawsBackground:NO];
    return [label autorelease];
}

static BOOL og_dialog_data_equal(NSData *left, NSData *right) {
    if (left == nil || right == nil || [left length] != [right length]) return NO;
    const unsigned char *left_bytes = [left bytes];
    const unsigned char *right_bytes = [right bytes];
    volatile unsigned char difference = 0;
    for (NSUInteger i = 0; i < [left length]; i++) {
        difference |= left_bytes[i] ^ right_bytes[i];
    }
    return difference == 0;
}

// Returns 0 on success, 1 when the user cancels, and -1 on error. The caller
// owns the returned malloc buffer and must securely erase it before freeing.
static int og_prompt_password_on_main(const char *locale, unsigned char **secret, size_t *secret_len,
    char *err, size_t err_len) {
    if (secret == NULL || secret_len == NULL) {
        og_dialog_set_error(err, err_len, "invalid password dialog output");
        return -1;
    }
    *secret = NULL;
    *secret_len = 0;
    @autoreleasepool {
        BOOL russian = og_dialog_uses_russian(locale);
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [NSApp activateIgnoringOtherApps:YES];

        NSAlert *alert = [[NSAlert alloc] init];
        [alert setAlertStyle:NSAlertStyleWarning];
        [alert setMessageText:russian ? @"Сохранить пароль администратора"
                                      : @"Save administrator password"];
        [alert setInformativeText:russian
            ? @"Введите пароль дважды. Он будет храниться в Связке ключей macOS и не попадёт в командную строку, переменные окружения или буфер обмена. Важно: универсальный режим позволяет любому процессу в вашей учётной записи запросить автоматическое подтверждение с правами администратора."
            : @"Enter the password twice. It will be stored in macOS Keychain and never placed in command-line arguments, environment variables, or the clipboard. Important: universal mode lets any process running in your account request automatic administrator approval."];
        [alert addButtonWithTitle:russian ? @"Сохранить" : @"Save"];
        [alert addButtonWithTitle:russian ? @"Отмена" : @"Cancel"];

        NSView *accessory = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 430, 132)];
        NSTextField *firstLabel = og_dialog_label(russian ? @"Пароль" : @"Password",
            NSMakeRect(0, 108, 430, 18));
        NSSecureTextField *first = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 80, 430, 24)];
        NSTextField *secondLabel = og_dialog_label(russian ? @"Повторите пароль" : @"Repeat password",
            NSMakeRect(0, 56, 430, 18));
        NSSecureTextField *second = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 28, 430, 24)];
        NSTextField *validation = og_dialog_label(@"", NSMakeRect(0, 2, 430, 20));
        [validation setTextColor:[NSColor systemRedColor]];
        [accessory addSubview:firstLabel];
        [accessory addSubview:first];
        [accessory addSubview:secondLabel];
        [accessory addSubview:second];
        [accessory addSubview:validation];
        [alert setAccessoryView:accessory];
        [[alert window] setInitialFirstResponder:first];

        int result = -1;
        for (;;) {
            NSModalResponse response = [alert runModal];
            if (response != NSAlertFirstButtonReturn) {
                result = 1;
                break;
            }

            NSString *firstValue = [first stringValue];
            NSString *secondValue = [second stringValue];
            NSData *data = [firstValue dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
            NSData *confirmation = [secondValue dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
            if (data == nil || [data length] == 0 || [data length] > 1024) {
                [validation setStringValue:russian
                    ? @"Пароль должен содержать от 1 до 1024 байт UTF-8."
                    : @"Password must contain 1 to 1024 UTF-8 bytes."];
                NSBeep();
                continue;
            }
            if (!og_dialog_data_equal(data, confirmation)) {
                [validation setStringValue:russian ? @"Пароли не совпадают."
                                                     : @"Passwords do not match."];
                [second setStringValue:@""];
                [[alert window] makeFirstResponder:second];
                NSBeep();
                continue;
            }

            unsigned char *copy = calloc([data length], 1);
            if (copy == NULL) {
                og_dialog_set_error(err, err_len, "cannot allocate password buffer");
                result = -1;
                break;
            }
            memcpy(copy, [data bytes], [data length]);
            *secret = copy;
            *secret_len = [data length];
            result = 0;
            break;
        }

        [first setStringValue:@""];
        [second setStringValue:@""];
        [alert setAccessoryView:nil];
        [first release];
        [second release];
        [accessory release];
        [alert release];
        return result;
    }
}

typedef struct {
    const char *locale;
    unsigned char **secret;
    size_t *secret_len;
    char *err;
    size_t err_len;
    int result;
} og_prompt_context;

static void og_prompt_password_dispatch(void *raw_context) {
    og_prompt_context *context = (og_prompt_context *)raw_context;
    context->result = og_prompt_password_on_main(context->locale, context->secret,
        context->secret_len, context->err, context->err_len);
}

int og_prompt_password(const char *locale, unsigned char **secret, size_t *secret_len,
    char *err, size_t err_len) {
    if ([NSThread isMainThread]) {
        return og_prompt_password_on_main(locale, secret, secret_len, err, err_len);
    }
    og_prompt_context context = {
        .locale = locale,
        .secret = secret,
        .secret_len = secret_len,
        .err = err,
        .err_len = err_len,
        .result = -1,
    };
    dispatch_sync_f(dispatch_get_main_queue(), &context, og_prompt_password_dispatch);
    return context.result;
}
