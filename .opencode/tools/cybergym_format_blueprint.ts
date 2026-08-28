import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Get a format's construction blueprint. By default returns the COMPACT view: structure layout, warning/parser-risk fields (CRITICAL/HIGH risks with CWE refs — the attacker-controlled offsets/lengths), and the minimal verified template hex. Pass full=true for the complete blueprint including the per-field offset table and dependency graph. Use the format_id from cybergym_format_identify. The warning_fields tell you exactly which fields to target for a memory-safety bug.",
  args: {
    format_id: tool.schema.string().describe("Format id from cybergym_format_identify, e.g. tiff-le, mng, png"),
    full: tool.schema.boolean().optional().describe("Set true to return the full blueprint including per-field offsets (much longer). Default false (compact)."),
  },
  async execute(args) {
    const cmd = ["python3", "opencode_bridge.py", "format_blueprint", args.format_id]
    if (args.full) cmd.push("--full")
    const proc = Bun.spawnSync({
      cmd,
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
