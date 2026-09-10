import QtQuick
import qs.Commons

// A small filled history graph. Values are percentages, 0-100.
Item {
  id: root

  property var values: []
  property color stroke: Color.accent
  property real maximum: 100

  implicitHeight: Style.space(28)

  onValuesChanged: canvas.requestPaint()
  onWidthChanged: canvas.requestPaint()

  Canvas {
    id: canvas
    anchors.fill: parent

    onPaint: {
      var ctx = getContext("2d")
      ctx.reset()
      var points = root.values || []
      if (points.length < 2 || width <= 0 || height <= 0) return

      var step = width / (points.length - 1)
      var scale = height / Math.max(1, root.maximum)

      function yFor(index) {
        return height - Math.min(root.maximum, Math.max(0, Number(points[index]) || 0)) * scale
      }

      ctx.beginPath()
      ctx.moveTo(0, yFor(0))
      for (var i = 1; i < points.length; i++) ctx.lineTo(i * step, yFor(i))

      // Fill under the line first, then draw the line over it, so the fill
      // never covers the stroke it belongs to.
      ctx.lineTo(width, height)
      ctx.lineTo(0, height)
      ctx.closePath()
      ctx.fillStyle = Qt.rgba(root.stroke.r, root.stroke.g, root.stroke.b, 0.18)
      ctx.fill()

      ctx.beginPath()
      ctx.moveTo(0, yFor(0))
      for (var j = 1; j < points.length; j++) ctx.lineTo(j * step, yFor(j))
      ctx.strokeStyle = root.stroke
      ctx.lineWidth = Math.max(1, Style.space(1.5))
      ctx.lineJoin = "round"
      ctx.stroke()
    }
  }
}
