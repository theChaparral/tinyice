const BAR_COUNT = 48
const BAR_WIDTH = 3
const MIN_HEIGHT = 4
const MAX_HEIGHT = 36
const ROTATION_SPEED = (2 * Math.PI) / 30 // 30 seconds per revolution

export function createVisualizer(canvas: HTMLCanvasElement, getFreqData: () => Uint8Array | null) {
  const ctx = canvas.getContext('2d')!
  let rotation = 0
  let lastTime = 0
  let animId = 0

  function draw(time: number) {
    if (document.hidden) { animId = requestAnimationFrame(draw); return }

    const dt = lastTime ? (time - lastTime) / 1000 : 0
    lastTime = time
    rotation += ROTATION_SPEED * dt

    const w = canvas.width
    const h = canvas.height
    const cx = w / 2
    const cy = h / 2
    const radius = Math.min(cx, cy) * 0.72

    ctx.clearRect(0, 0, w, h)

    const data = getFreqData()
    const step = (2 * Math.PI) / BAR_COUNT

    for (let i = 0; i < BAR_COUNT; i++) {
      const angle = rotation + i * step
      const freqIndex = data ? Math.floor((i / BAR_COUNT) * data.length) : 0
      const value = data ? data[freqIndex] / 255 : 0.2 + Math.random() * 0.1
      const barHeight = MIN_HEIGHT + value * (MAX_HEIGHT - MIN_HEIGHT)
      const opacity = 0.15 + value * 0.75

      ctx.save()
      ctx.translate(cx, cy)
      ctx.rotate(angle)
      ctx.beginPath()
      ctx.roundRect(-BAR_WIDTH / 2, -(radius + barHeight), BAR_WIDTH, barHeight, BAR_WIDTH / 2)
      ctx.fillStyle = `rgba(255, 102, 0, ${opacity})`
      ctx.fill()
      ctx.restore()
    }

    // Inner circle border
    ctx.beginPath()
    ctx.arc(cx, cy, radius * 0.68, 0, Math.PI * 2)
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)'
    ctx.lineWidth = 1
    ctx.stroke()

    animId = requestAnimationFrame(draw)
  }

  animId = requestAnimationFrame(draw)

  return {
    destroy() { cancelAnimationFrame(animId) },
    setSize(w: number, h: number) {
      canvas.width = w * devicePixelRatio
      canvas.height = h * devicePixelRatio
      ctx.scale(devicePixelRatio, devicePixelRatio)
    }
  }
}
