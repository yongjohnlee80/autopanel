// DnsDialog.qml — the DNS records mail needs, as a DNS provider asks for them:
// for a domain whose DNS AutoPanel cannot write (no Cloudflare token), each
// record to enter by hand; with a token, the same list to check.
//
// The host fills App.dnsRows (type, host relative to its zone, value), the
// intro line, and the selected record whole (App.dnsDetail), then opens it.
// Copy value puts the selected value on the clipboard through the terminal.

Dialog {
    title: qsTrId("autopanel.title.dialog.mailDns")
    width: 110
    maxWidthPercent: 95
    Flex {
        direction: Tui.Vertical
        Text { text: App.dnsIntro; wrapMode: Tui.WordWrap }
        Text { text: App.dnsNote; visible: App.dnsNoteShown; wrapMode: Tui.WordWrap; color: Theme.syntax.alert }
        Split {
            orientation: Tui.Vertical
            ratio: 0.55
            Frame {
                TableView {
                    id: dnsTable
                    palette.highlight: Theme.document.highlight
                    palette.highlightedText: Theme.document.highlightedText
                    model: App.dnsRows
                    onCurrentIndexChanged: App.dnsMoved(index)
                    TableViewColumn { role: "type"; title: "TYPE"; width: 6 }
                    TableViewColumn { role: "host"; title: "HOST"; width: 34 }
                    TableViewColumn { role: "value"; title: "VALUE"; width: 0 }
                }
            }
            Frame {
                title: qsTrId("autopanel.title.pane.details")
                Text { text: App.dnsDetail; wrapMode: Tui.WordWrap }
            }
        }
    }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.mail.copy"); toolTipText: App.tipMailCopy; DialogButtonBox.buttonRole: DialogButtonBox.ActionRole
                 onClicked: App.dnsCopy(dnsTable.currentIndex) }
        Button { text: qsTrId("autopanel.button.dialog.close"); toolTipText: App.tipDialogClose; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
    onOpened: dnsTable.forceActiveFocus()
}
