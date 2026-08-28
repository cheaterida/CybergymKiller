import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Export a verified valid template for a file format as raw hex bytes. Use this as a construction base to mutate (e.g. write the hex to research/<task>/inputs/ then modify risk-relevant fields). The template is parser-valid, so mutations that keep the structure intact are more likely to reach deep parser logic.",
  args: {
    format_id: tool.schema.string().describe("Format id, e.g. tiff-le, png"),
  },
  async execute(args) {
    const proc = Bun.spawnSync({
      cmd: ["python3", "opencode_bridge.py", "format_template", args.format_id],
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
