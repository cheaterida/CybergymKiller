import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Stop and remove a dynamic-whole session container. Always call this when you are done with a session (solved or not) to avoid accumulating containers in batch runs. Idempotent: safe to call even if the container was already removed. Archives the session record before destroying.",
  args: {
    session_id: tool.schema.string().describe("Session id returned by cybergym_dyn_start"),
    purpose: tool.schema.string().optional().describe("Why you are stopping this session"),
  },
  async execute(args) {
    const proc = Bun.spawnSync({
      cmd: ["python3", "opencode_bridge.py", "dyn_stop", args.session_id, args.purpose ?? ""],
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
