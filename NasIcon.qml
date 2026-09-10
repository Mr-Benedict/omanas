import QtQuick
import QtQuick.Shapes
import qs.Commons

// A two-bay desktop NAS, drawn rather than shipped as an asset.
//
// Deliberately not Synology's own mark: theirs is the DSM wordmark, which is
// an unreadable smudge by the time it is 13px tall in the bar, and shipping
// a trademarked logo with a plugin anyone can redistribute is not a licence
// this project has. A device silhouette carries neither problem.
//
// Solid with cut-out bays, because at bar size an outline of this shape
// collapses into a grey blob while a solid one keeps its edges. The cut-outs
// are real holes -- an odd-even fill rather than slots painted in a
// background colour -- so the icon sits correctly on the bar and on a panel.
Item {
  id: root

  property real iconSize: Style.font.icon
  property color color: Color.foreground
  // "ok" | "warning" | "critical" | "offline"
  property string health: "offline"

  implicitWidth: iconSize
  implicitHeight: iconSize

  // State is carried by the whole silhouette rather than a status dot. A dot
  // would be about two pixels in the bar, too small to read and too small to
  // colour convincingly.
  readonly property color tint: {
    if (health === "critical") return Color.urgent
    if (health === "warning") return Qt.lighter(Color.urgent, 1.3)
    if (health === "offline") return Qt.darker(root.color, 1.6)
    return root.color
  }

  // Geometry is rounded to whole pixels so the bays stay crisp instead of
  // landing on half a pixel and blurring at the size that matters most.
  readonly property real _w: Math.round(iconSize * 0.72)
  readonly property real _h: Math.round(iconSize * 0.94)
  readonly property real _x: Math.round((iconSize - _w) / 2)
  readonly property real _y: Math.round((iconSize - _h) / 2)
  readonly property real _r: Math.max(1, Math.round(iconSize * 0.13))
  readonly property real _bayW: Math.max(1, Math.round(iconSize * 0.12))
  readonly property real _bayH: Math.round(_h * 0.56)
  readonly property real _bayY: _y + Math.round((_h - _bayH) / 2)
  readonly property real _bay1: _x + Math.round(_w * 0.22)
  readonly property real _bay2: _x + _w - Math.round(_w * 0.22) - _bayW

  function _roundedBody() {
    var x = _x, y = _y, w = _w, h = _h, r = _r
    return "M " + (x + r) + " " + y
         + " H " + (x + w - r)
         + " A " + r + " " + r + " 0 0 1 " + (x + w) + " " + (y + r)
         + " V " + (y + h - r)
         + " A " + r + " " + r + " 0 0 1 " + (x + w - r) + " " + (y + h)
         + " H " + (x + r)
         + " A " + r + " " + r + " 0 0 1 " + x + " " + (y + h - r)
         + " V " + (y + r)
         + " A " + r + " " + r + " 0 0 1 " + (x + r) + " " + y + " Z"
  }

  function _bay(bx) {
    return " M " + bx + " " + _bayY
         + " h " + _bayW + " v " + _bayH + " h " + (-_bayW) + " Z"
  }

  Shape {
    anchors.fill: parent
    preferredRendererType: Shape.CurveRenderer

    ShapePath {
      fillRule: ShapePath.OddEvenFill
      fillColor: root.tint
      strokeWidth: 0
      strokeColor: "transparent"
      PathSvg { path: root._roundedBody() + root._bay(root._bay1) + root._bay(root._bay2) }
    }
  }

  // A NAS in trouble should catch the eye without being noisy about it.
  SequentialAnimation on opacity {
    running: root.health === "critical"
    loops: Animation.Infinite
    NumberAnimation { to: 0.35; duration: 900; easing.type: Easing.InOutQuad }
    NumberAnimation { to: 1.0; duration: 900; easing.type: Easing.InOutQuad }
  }
}
