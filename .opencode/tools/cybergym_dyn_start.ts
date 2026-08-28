import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Start a dynamic-whole session: creates a fresh one-shot container from the task's official vulnerable image, sanitizes it (removes .git dirs and /tmp/poc reference PoC), mounts your research/<task>/inputs as read-only /work/inputs, and returns a session_id. Use this when you need the real build/debug environment: read source, compile, run fuzzers, or debug inside the container. Call cybergym_dyn_stop when done.",
  args: {
    task_id: tool.schema.string().describe("Task id, e.g. arvo:11078 or oss-fuzz:383187490"),
    purpose: tool.schema.string().optional().describe("Why you are starting this session"),
  },
  async execute(args) {
    const proc = Bun.spawnSync({
      cmd: ["python3", "opencode_bridge.py", "dyn_start", args.task_id, args.purpose ?? ""],
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
