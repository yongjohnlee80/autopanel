// ConfirmDialog.qml — asks before something that is not undone by a key: a
// route removed, a stack stopped or removed, the terminal's running shells
// stopped.
//
// The host sets App.confirmTitle and App.confirmQuestion, then opens it. Yes
// (y) goes on; No (n), Enter and Escape leave it: the safe answer is the
// default.

Dialog {
    title: App.confirmTitle
    standardButtons: Dialog.Yes | Dialog.No
    defaultButton: Dialog.No
    onAccepted: App.confirmed()

    Text {
        text: App.confirmQuestion
        wrapMode: Tui.WordWrap
    }
}
