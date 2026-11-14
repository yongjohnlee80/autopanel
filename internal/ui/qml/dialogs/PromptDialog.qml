// PromptDialog.qml — one question with a typed answer: a domain's name, a
// stack's name.
//
// The host sets the title, the label and the field's text, then
// opens it. OK (or Enter in the field) gives the host the text, and the
// dialog stays: a refused answer is said in the line under the field
// (App.promptError), as typed. The host closes it once the answer is taken.
// Escape and Cancel close it.

Dialog {
    title: App.promptTitle
    width: 60
    maxWidthPercent: 90
    Flex {
        direction: Tui.Vertical
        Text { text: App.promptLabel; wrapMode: Tui.WordWrap }
        TextField { id: promptField; text: App.promptText; onAccepted: App.promptAnswered(promptField.text) }
        Text { text: App.promptError; visible: App.promptErrorShown; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
    }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.dialog.ok"); toolTipText: App.tipPromptOK; DialogButtonBox.buttonRole: DialogButtonBox.ActionRole
                 onClicked: App.promptAnswered(promptField.text) }
        Button { text: qsTrId("autopanel.button.dialog.cancel"); toolTipText: App.tipDialogCancel; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
    onOpened: promptField.forceActiveFocus()
}
