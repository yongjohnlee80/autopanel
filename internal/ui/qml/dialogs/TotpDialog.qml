// TotpDialog.qml — two-factor enrolment: the secret and its otpauth line,
// shown once, for an authenticator app; then a code from the app confirms it.
// The host clears the secret from its source once the dialog closes.

Dialog {
    title: qsTrId("autopanel.title.dialog.totp")
    width: 96
    maxWidthPercent: 95
    Flex {
        direction: Tui.Vertical
        Text { text: App.totpText; wrapMode: Tui.WordWrap }
        Text { text: qsTrId("autopanel.label.account.totpCode") }
        TextField { id: totpCode; text: App.totpCode; onAccepted: App.totpConfirmed(totpCode.text) }
        Text { text: App.totpError; visible: App.totpErrorShown; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
    }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.account.confirm"); toolTipText: App.tipTotpConfirm; DialogButtonBox.buttonRole: DialogButtonBox.ActionRole
                 onClicked: App.totpConfirmed(totpCode.text) }
        Button { text: qsTrId("autopanel.button.dialog.cancel"); toolTipText: App.tipDialogCancel; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
    onOpened: totpCode.forceActiveFocus()
    onRejected: App.totpClosed()
}
