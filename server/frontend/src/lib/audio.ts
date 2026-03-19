let ctx: AudioContext | null = null
let analyser: AnalyserNode | null = null
let source: MediaElementAudioSourceNode | null = null

export function connectAudio(el: HTMLAudioElement) {
  if (!ctx) ctx = new AudioContext()
  if (source) return analyser!
  source = ctx.createMediaElementSource(el)
  analyser = ctx.createAnalyser()
  analyser.fftSize = 128 // gives 64 frequency bins
  analyser.smoothingTimeConstant = 0.8
  source.connect(analyser)
  analyser.connect(ctx.destination)
  return analyser
}

export function getFrequencyData(analyserNode: AnalyserNode): Uint8Array {
  const data = new Uint8Array(analyserNode.frequencyBinCount)
  analyserNode.getByteFrequencyData(data)
  return data
}

export function resumeAudio() {
  ctx?.resume()
}
