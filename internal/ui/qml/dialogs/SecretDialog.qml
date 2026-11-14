// SecretDialog.qml — one secret, typed unseen: a mail account's password.
//
// The host sets the title and the label, then opens it. OK (or Enter in the
// field) gives the host the text, and the dialog stays: a refused answer is
// said in the line under the field (App.secretError). The text is in no
// source: it goes from the field to the host's command, and from there to the
// daemon; App.secretText is only ever set empty, to clear the field before
// each opening. Escape and Cancel close it.

Dialog {
    title: App.secretTitle
    width: 60
    maxWidthPercent: 90
    Flex {
        direction: Tui.Vertical
        Text { text: App.secretLabel; wrapMode: Tui.WordWrap }
        TextField { id: secretField; text: App.secretText; echoMode: TextInput.Password; onAccepted: App.secretEntered(secretField.text) }
        Text { text: App.secretError; visible: App.secretErrorShown; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
    }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.dialog.ok"); toolTipText: App.tipPromptOK; DialogButtonBox.buttonRole: DialogButtonBox.ActionRole
                 onClicked: App.secretEntered(secretField.text) }
        Button { text: qsTrId("autopanel.button.dialog.cancel"); toolTipText: App.tipDialogCancel; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
    onOpened: secretField.forceActiveFocus()
}
