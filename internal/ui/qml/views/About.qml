// About.qml — what AutoPanel is, the panel's version and the running
// daemon's, the licence and where the source is. Each label is bold, its
// value beside it after a gap (the labels differ in width by language). Close, q, Enter and Escape close it.

Dialog {
    title: qsTrId("autopanel.about.title")
    closeOnQ: true
    width: 64
    standardButtons: Dialog.Close
    defaultButton: Dialog.Close

    Flex {
        direction: Tui.Vertical
        Text { text: App.aboutHeadline; font.bold: true }
        Text { text: qsTrId("autopanel.about.what"); wrapMode: Tui.WordWrap }
        Text { text: "" }
        Flex { direction: Tui.Horizontal; Text { text: qsTrId("autopanel.about.panel"); font.bold: true } Text { text: "  " } Text { text: App.aboutPanel } }
        Flex { direction: Tui.Horizontal; Text { text: qsTrId("autopanel.about.daemon"); font.bold: true } Text { text: "  " } Text { text: App.aboutDaemon } }
        Flex { direction: Tui.Horizontal; Text { text: qsTrId("autopanel.about.licence"); font.bold: true } Text { text: "  " } Text { text: "Apache-2.0" } }
        Flex { direction: Tui.Horizontal; Text { text: qsTrId("autopanel.about.source"); font.bold: true } Text { text: "  " } Text { text: "https://github.com/yongjohnlee80/autopanel" } }
    }
}
