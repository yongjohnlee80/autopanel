// BrowseDialog.qml — Services › Add a stack: the host's folders, in the
// pickers' layout (AutoDoc's Picker). On the left the folder's path, a field
// to type another, over its entries: folders first, a folder that holds a
// compose.yaml marked ◆. On the right the entry under the cursor: a file's
// text, its secrets masked, highlighted as YAML or Markdown; a folder's
// summary. A one-line note over the preview says what it hides, or why it
// shows nothing.
//
// Enter on a folder goes into it, Enter on ".." or Backspace goes up, Enter
// in the field goes to the path typed (browse.go). Import takes the folder
// under the cursor, or the one shown, when it holds a compose.yaml.

Dialog {
    title: qsTrId("autopanel.title.dialog.browse")
    maxWidthPercent: 92
    maxHeightPercent: 90
    Flex {
        direction: Tui.Vertical
        Split {
            Layout.fillHeight: true
            orientation: Tui.Horizontal
            ratio: 0.42
            Flex {
                direction: Tui.Vertical
                Text { text: qsTrId("autopanel.label.browse.folder") }
                TextField { id: browsePath; text: App.browsePath; onAccepted: App.browseGo(browsePath.text) }
                Frame {
                    title: App.browseTitle
                    Layout.fillHeight: true
                    TableView {
                        id: browseList
                        palette.highlight: Theme.document.highlight
                        palette.highlightedText: Theme.document.highlightedText
                        model: App.browseEntries
                        currentIndex: App.browseAt
                        onCurrentIndexChanged: App.browseMove(index)
                        onActivated: App.browseEnter(index)
                        TableViewColumn { role: "mark"; title: ""; width: 2 }
                        TableViewColumn { role: "name"; title: "NAME"; width: 0; elideMode: Tui.ElidePath }
                        TableViewColumn { role: "size"; title: "SIZE"; width: 10 }
                    }
                }
            }
            Frame {
                title: App.browsePreviewTitle
                Flex {
                    direction: Tui.Vertical
                    Text { text: App.browseNote; visible: App.browseNoteShown; wrapMode: Tui.WordWrap; color: Theme.syntax.comment }
                    Editor {
                        id: browsePreview
                        Layout.fillHeight: true
                        readOnly: true
                        cursorColor: Theme.document.cursor
                        text: App.browsePreview
                        SyntaxHighlighter { definition: App.browseSyntax }
                    }
                }
            }
        }
    }
    Shortcut { sequence: "Backspace"; onActivated: App.browseUp() }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.browse.import"); toolTipText: App.tipBrowseImport; enabled: App.browseCanImport
                 DialogButtonBox.buttonRole: DialogButtonBox.ActionRole; onClicked: App.browseImport() }
        Button { text: qsTrId("autopanel.button.browse.up"); toolTipText: App.tipBrowseUp
                 DialogButtonBox.buttonRole: DialogButtonBox.ActionRole; onClicked: App.browseUp() }
        Button { text: qsTrId("autopanel.button.dialog.close"); toolTipText: App.tipDialogClose; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
    onOpened: browseList.forceActiveFocus()
}
