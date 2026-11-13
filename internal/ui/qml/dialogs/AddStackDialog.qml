// AddStackDialog.qml — the definition folders a stack can be added from.
//
// The host fills App.available and opens it. Enter on a row, or Review, has
// the host close it and review that folder (App.pickStack): nothing is added
// here. With no folder, the table is hidden and the note says where a compose
// file goes (App.availableNote). Escape and Cancel close it.

Dialog {
    title: qsTrId("autopanel.stacks.available.title")
    width: 72
    maxWidthPercent: 90
    maxHeightPercent: 60

    Flex {
        direction: Tui.Vertical
        TableView {
            id: availableTable
            visible: App.availableAny
            Layout.fillHeight: true   // the note under it keeps its lines
            palette.highlight: Theme.document.highlight
            palette.highlightedText: Theme.document.highlightedText
            model: App.available
            onActivated: App.pickStack(index)
            TableViewColumn { role: "name"; title: "FOLDER" }
        }
        Text { text: App.availableNote; wrapMode: Tui.WordWrap }
    }

    DialogButtonBox {
        Button {
            text: qsTrId("autopanel.stacks.available.review")
            enabled: App.availableAny
            DialogButtonBox.buttonRole: DialogButtonBox.ActionRole
            onClicked: App.pickStack(availableTable.currentIndex)
        }
        Button {
            text: qsTrId("autopanel.form.cancel")
            DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
        }
    }
}
