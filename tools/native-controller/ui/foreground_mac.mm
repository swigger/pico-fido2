#include "foreground.h"
#include <QWidget>
#import <AppKit/AppKit.h>

void activateForApproval(QWidget *window) {
    // Qt's activateWindow() selects a window within the application; an
    // approval arriving while Safari is active also needs app activation.
    NSView *view = reinterpret_cast<NSView *>(window->winId());
    NSWindow *native = view.window;
    native.collectionBehavior = (native.collectionBehavior & ~NSWindowCollectionBehaviorCanJoinAllSpaces)
        | NSWindowCollectionBehaviorMoveToActiveSpace | NSWindowCollectionBehaviorFullScreenAuxiliary;
    [NSApp unhideWithoutActivation];
    if (@available(macOS 14.0, *)) [NSApp activate];
    else [NSApp activateIgnoringOtherApps:YES];
    window->raise();
    window->activateWindow();
    [native makeKeyAndOrderFront:nil];
}

intptr_t otherForeground() {
    NSRunningApplication *front = NSWorkspace.sharedWorkspace.frontmostApplication;
    if (!front || front.processIdentifier == NSRunningApplication.currentApplication.processIdentifier) return 0;
    return front.processIdentifier;
}
void restoreForeground(intptr_t previous) {
    if (!previous || !NSApp.isActive) return; // the user already moved elsewhere
    NSRunningApplication *app = [NSRunningApplication runningApplicationWithProcessIdentifier:static_cast<pid_t>(previous)];
    if (app && !app.terminated) {
        if (@available(macOS 14.0, *)) [NSApp yieldActivationToApplication:app];
        [app activateWithOptions:0];
    }
}
