// ConfirmDialog.qml — asks before a route is removed.
//
// The host names the route in App.confirmQuestion, then opens it. Yes (y)
// removes it; No (n), Enter and Escape leave it: the safe answer is the
// default, since the other cannot be undone.

Dialog {
    title: qsTrId("autopanel.confirm.title")
    standardButtons: Dialog.Yes | Dialog.No
    defaultButton: Dialog.No
    onAccepted: App.removeConfirmed()

    Text {
        text: App.confirmQuestion
        wrapMode: Tui.WordWrap
    }
}
