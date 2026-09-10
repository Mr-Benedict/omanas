import QtQuick
import qs.Commons

// A labelled fill bar for one volume.
Item {
  id: root

  property string label: ""
  property string detail: ""
  property real percent: 0
  property color foreground: Color.foreground
  property string fontFamily: Style.font.family
  property bool alarming: false

  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property color fillColor: alarming || percent >= 90 ? Color.urgent
                                   : percent >= 75 ? Qt.lighter(Color.urgent, 1.4)
                                   : Color.accent

  implicitHeight: column.implicitHeight

  Column {
    id: column
    width: parent.width
    spacing: Style.spacing.labelGap

    Item {
      width: parent.width
      implicitHeight: Math.max(labelText.implicitHeight, detailText.implicitHeight)

      Text {
        id: labelText
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
        text: root.label
        textFormat: Text.PlainText
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        elide: Text.ElideRight
        width: Math.max(0, parent.width - detailText.width - Style.space(8))
      }

      Text {
        id: detailText
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        text: root.detail
        textFormat: Text.PlainText
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
    }

    Rectangle {
      width: parent.width
      height: Style.space(6)
      radius: height / 2
      color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.12)

      Rectangle {
        width: Math.max(height, parent.width * Math.min(100, Math.max(0, root.percent)) / 100)
        height: parent.height
        radius: height / 2
        color: root.fillColor
        Behavior on width { NumberAnimation { duration: 260; easing.type: Easing.OutQuad } }
      }
    }
  }
}
