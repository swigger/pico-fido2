#pragma once
#include <cstdint>

class QWidget;

// Present a pending approval, including application activation on macOS.
void activateForApproval(QWidget *window);

// The application the user was working in when a popup brought this one to the
// front, so closing the popup can hand the focus back instead of leaving the
// main window in front. 0 when that was this application or is unknown.
intptr_t otherForeground();
// Activates it again, only while this application is still the active one.
void restoreForeground(intptr_t previous);
