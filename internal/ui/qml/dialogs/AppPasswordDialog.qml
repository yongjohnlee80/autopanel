// AppPasswordDialog.qml — a new app password, shown once: its secret, a QR
// code of it for a phone's camera (beside it, in the one text), and the settings a mail app needs. Done
// keeps it once the device signs in; Cancel or Escape revokes it. The host
// clears the secret from its source as the dialog closes, either way.

Dialog {
    title: App.appPwTitle
    width: 110
    maxWidthPercent: 98
    Flex {
        direction: Tui.Vertical
        Text { text: App.appPwIntro; wrapMode: Tui.WordWrap }
        Text { text: " " }
        Text { text: App.appPwText; wrapMode: Tui.WordWrap }
        Text { text: App.appPwNote; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
    }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.mail.appDone"); toolTipText: App.tipAppPwDone; DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole }
        Button { text: qsTrId("autopanel.button.dialog.cancel"); toolTipText: App.tipDialogCancel; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
    onAccepted: App.appPasswordDone()
    onRejected: App.appPasswordCancelled()
}
