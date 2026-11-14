// ReviewDialog.qml — a stack's review, before it is added, applied or started.
//
// The host fills the App.review* sources from the daemon's check, then opens
// it. Over the panes, the definition's hash, how many files and containers it
// has, and the services an apply would remove; then, when there is one, what
// stops it (a refusal) or why it is shown again (the definition changed).
// On the left each container it would run, then each finding, refusals
// first; on the right the selected one whole.
//
// The first button's text is the host's (App.reviewGo): Add and start, Apply
// or Start. A new stack has Prepare only as well. A refused stack's are
// disabled. An answer closes the dialog; when the definition changed in
// between, the host opens it again on the new one.

Dialog {
    title: App.reviewTitle
    width: 116
    maxWidthPercent: 96
    maxHeightPercent: 94
    Flex {
        direction: Tui.Vertical
        Text { text: App.reviewSummary }
        Text { text: App.reviewRemoves; visible: App.reviewRemovesAny; wrapMode: Tui.WordWrap }
        Text { text: App.reviewNotice; visible: App.reviewNoticeShown; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
        Split {
            Layout.fillHeight: true
            orientation: Tui.Horizontal
            ratio: 0.5
            Frame {
                title: qsTrId("autopanel.title.pane.review")
                TableView {
                    id: reviewTable
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.reviewRows
                    onCurrentIndexChanged: App.reviewMoved(index)
                    TableViewColumn { role: "kind"; title: ""; width: 10 }
                    TableViewColumn { role: "name"; title: "SERVICE"; width: 10 }
                    TableViewColumn { role: "text"; title: "WHAT" }
                }
            }
            Frame {
                title: qsTrId("autopanel.title.pane.details")
                Text { text: App.reviewDetail; wrapMode: Tui.WordWrap }
            }
        }
    }
    DialogButtonBox {
        Button {
            text: App.reviewGo
            toolTipText: App.tipReviewGo
            enabled: App.reviewAllowed
            DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            onClicked: App.reviewAccept()
        }
        Button {
            text: qsTrId("autopanel.button.review.prepare")
            toolTipText: App.tipReviewPrepare
            visible: App.reviewNew
            enabled: App.reviewMayPrepare
            DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            onClicked: App.reviewPrepare()
        }
        Button { text: qsTrId("autopanel.button.dialog.close"); toolTipText: App.tipDialogClose; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
}
