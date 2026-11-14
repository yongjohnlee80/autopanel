// Keys.qml — Help › Keys: every key of the screen, by where it works, as
// text (keys.go composes it in the UI's language). It is the one place keys
// are listed: no line of the screen, of a panel or of a dialog lists them.

Dialog {
    title: qsTrId("autopanel.title.dialog.keys")
    closeOnQ: true
    width: 100
    maxWidthPercent: 90
    maxHeightPercent: 90
    dim: false
    Editor { cursorColor: Theme.document.cursor; readOnly: true; wrap: true; text: App.keysText }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.dialog.close"); toolTipText: App.tipDialogClose; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
}
