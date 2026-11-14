// About.qml — what AutoPanel is, the panel's version and the running
// daemon's, the licence and where the source is. Each label is bold, its
// value beside it after a gap (the labels differ in width by language).
// Close, q and Escape close it.

Dialog {
    title: qsTrId("autopanel.title.dialog.about")
    closeOnQ: true
    width: 64
    Flex {
        direction: Tui.Vertical
        Text { text: App.aboutHeadline; font.bold: true }
        Text { text: qsTrId("autopanel.value.about.what"); wrapMode: Tui.WordWrap }
        Text { text: "" }
        Flex { direction: Tui.Horizontal; Text { text: qsTrId("autopanel.label.about.panel"); font.bold: true } Text { text: "  " } Text { text: App.aboutPanel } }
        Flex { direction: Tui.Horizontal; Text { text: qsTrId("autopanel.label.about.daemon"); font.bold: true } Text { text: "  " } Text { text: App.aboutDaemon } }
        Flex { direction: Tui.Horizontal; Text { text: qsTrId("autopanel.label.about.licence"); font.bold: true } Text { text: "  " } Text { text: "Apache-2.0" } }
        Flex { direction: Tui.Horizontal; Text { text: qsTrId("autopanel.label.about.source"); font.bold: true } Text { text: "  " } Text { text: "https://github.com/yongjohnlee80/autopanel" } }
    }
    DialogButtonBox {
        Button { text: qsTrId("autopanel.button.dialog.close"); toolTipText: App.tipDialogClose; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
    }
}
