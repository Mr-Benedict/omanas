import QtQuick
import qs.Commons

// A NAS chassis drawn rather than shipped as an SVG: two drive bays and a
// status light. Drawing it keeps it crisp at bar sizes and lets the status
// light carry colour while the body follows the theme.
Item {
  id: root

  property real iconSize: Style.font.icon
  property color color: Color.foreground
  // "ok" | "warning" | "critical" | "offline"
  property string health: "offline"

  implicitWidth: iconSize
  implicitHeight: iconSize

  readonly property color lightColor: {
    if (health === "critical") return Color.urgent
    if (health === "warning") return Qt.lighter(Color.urgent, 1.35)
    if (health === "ok") return Color.accent
    return Qt.darker(root.color, 1.8)
  }

  Rectangle {
    id: chassis
    anchors.centerIn: parent
    width: root.iconSize * 0.82
    height: root.iconSize * 0.94
    radius: Math.max(1, root.iconSize * 0.1)
    color: "transparent"
    border.color: root.color
    border.width: Math.max(1, root.iconSize * 0.075)

    Column {
      anchors.centerIn: parent
      spacing: chassis.height * 0.12

      Repeater {
        model: 2
        Rectangle {
          width: chassis.width * 0.52
          height: chassis.height * 0.17
          radius: height / 2
          color: root.color
          opacity: 0.85
        }
      }
    }

    Rectangle {
      width: chassis.width * 0.16
      height: width
      radius: width / 2
      color: root.lightColor
      anchors.right: parent.right
      anchors.bottom: parent.bottom
      anchors.rightMargin: chassis.width * 0.14
      anchors.bottomMargin: chassis.height * 0.13

      // A failing NAS should catch the eye without being noisy about it.
      SequentialAnimation on opacity {
        running: root.health === "critical"
        loops: Animation.Infinite
        NumberAnimation { to: 0.25; duration: 900; easing.type: Easing.InOutQuad }
        NumberAnimation { to: 1.0; duration: 900; easing.type: Easing.InOutQuad }
      }
    }
  }
}
