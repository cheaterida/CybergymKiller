import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Identify a file format from its header bytes. Give the first bytes of an input as continuous hex (e.g. 49492A00 for TIFF). Returns ranked candidate formats with confidence, magic reasons, extensions, and a compact structure summary. Use this early when you have a seed/corpus input or need to know what parser structure you are dealing with.",
  args: {
    hex_text: tool.schema.string().describe("Header bytes as continuous hex, e.g. 49492A00"),
  },
  async execute(args) {
    const proc = Bun.spawnSync({
      cmd: ["python3", "opencode_bridge.py", "format_identify", args.hex_text],
      cwd: process.cwd(),
      stdout: "pipe",
      stderr: "pipe",
    })
    const out = proc.stdout?.toString() ?? ""
    const err = proc.stderr?.toString() ?? ""
    if (proc.exitCode !== 0) {
      return `ERROR (exit ${proc.exitCode}): ${err || out}`
    }
    return out
  },
})
