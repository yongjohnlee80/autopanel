// ReviewDialog.qml — a stack's review, before it is added, applied or started.
//
// The host fills the App.review* sources from the daemon's check, then opens
// it: the definition's hash and its files, each container it would run, the
// services an apply would remove, and the findings, refusals first. A row of
// the findings has room for the start of a long one, so the line under the
// table shows the selected one whole.
//
// The first button's text is the host's (App.reviewGo): Add and start, Apply
// or Start. A new stack has Prepare only as well. A refused stack's are
// disabled, and the help line says so. An answer closes the dialog; when the
// definition changed since the review, the host opens it again on the new one.

Dialog {
    title: App.reviewTitle
    helpText: App.reviewHelp
    width: 116
    maxWidthPercent: 96
    maxHeightPercent: 94

    Flex {
        direction: Tui.Vertical
        Text { text: App.reviewSummary }
        TableView {
            Layout.preferredHeight: 6   // its heading and five containers; more scroll
            palette.highlight: Theme.document.highlight
            palette.highlightedText: Theme.document.highlightedText
            model: App.reviewContainers
            TableViewColumn { role: "service"; title: "SERVICE"; width: 12 }
            TableViewColumn { role: "image"; title: "IMAGE"; width: 24 }
            TableViewColumn { role: "user"; title: "USER"; width: 12 }
            TableViewColumn { role: "network"; title: "NETWORK"; width: 7 }
            TableViewColumn { role: "ports"; title: "PORTS"; width: 22 }
            TableViewColumn { role: "memory"; title: "MEMORY"; width: 10 }
            TableViewColumn { role: "mounts"; title: "MOUNTS" }
        }
        Text { text: App.reviewRemoves; visible: App.reviewRemovesAny; wrapMode: Tui.WordWrap }
        TableView {
            Layout.fillHeight: true     // what the rest leaves
            palette.highlight: Theme.document.highlight
            palette.highlightedText: Theme.document.highlightedText
            model: App.reviewFindings
            onCurrentIndexChanged: App.showFinding(index)
            TableViewColumn { role: "level"; title: "LEVEL"; width: 10 }
            TableViewColumn { role: "text"; title: "FINDING" }
        }
        Text { text: App.reviewFinding; wrapMode: Tui.WordWrap }
    }

    DialogButtonBox {
        Button {
            text: App.reviewGo
            enabled: App.reviewAllowed
            DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            onClicked: App.reviewAccept()
        }
        Button {
            text: qsTrId("autopanel.review.prepare")
            visible: App.reviewNew
            enabled: App.reviewMayPrepare
            DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
            onClicked: App.reviewPrepare()
        }
        Button {
            text: qsTrId("autopanel.form.cancel")
            DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
        }
    }
}
