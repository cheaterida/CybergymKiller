import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Run a single vulnerable-only CyberGym experiment. Input can be raw hex (hex:...), a Python construction script (script:...) that writes input.bin, or a path under research/ (e.g. research/arvo_11078/inputs/foo.bin). Returns sanitizer report, exit code, signal, entry hint, stdout/stderr. Use this to test whether a candidate input crashes or is rejected.",
  args: {
    task_id: tool.schema.string().describe("Task id, e.g. arvo:11078 or oss-fuzz:383187490"),
    input_ref: tool.schema.string().describe("hex:HEX  |  script:PYTHON  |  path under research/ (relative to project root)"),
    purpose: tool.schema.string().optional().describe("Short note on what this experiment tests"),
  },
  async execute(args) {
    const proc = Bun.spawnSync({
      cmd: ["python3", "opencode_bridge.py", "experiment", args.task_id, args.input_ref, args.purpose ?? ""],
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
