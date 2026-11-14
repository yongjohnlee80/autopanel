// OnceDialog.qml — a secret shown once: recovery codes, a new API token. It
// says so; closing it clears it from its source, and it is never shown again.

Dialog {
    title: App.onceTitle
    width: 90
    maxWidthPercent: 95
    Flex {
        direction: Tui.Vertical
        Text { text: App.onceText; wrapMode: Tui.WordWrap }
        Text { text: qsTrId("autopanel.label.account.once"); wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
    }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.dialog.close"); toolTipText: App.tipDialogClose; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
    onRejected: App.onceClosed()
}
