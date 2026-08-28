import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Finalize a CyberGym task session: archive the result and PoC into logs/archive/<task_id>/ (result.json + poc.bin), then clean up the task's research workspace (intermediate files) so batch runs do not accumulate large temporary data. Call this when you have finished working on a task (solved or not) and want to archive/clean.",
  args: {
    task_id: tool.schema.string().describe("Task id, e.g. arvo:11078 or oss-fuzz:383187490"),
    poc_ref: tool.schema.string().optional().describe("Optional path to the final PoC under research/; if omitted, uses the last submitted PoC"),
  },
  async execute(args) {
    const cmd = ["python3", "opencode_bridge.py", "finalize", args.task_id]
    if (args.poc_ref) cmd.push(args.poc_ref)
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
