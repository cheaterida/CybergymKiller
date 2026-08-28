import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Record your post-task learning reflection: the most valuable knowledge gap(s) you hit while solving this task, with a DETAILED narrative of your reasoning around the gap. Call this at the END of the task, regardless of whether you solved it. This feeds a human-reviewed learning library: be concrete, use the correct technical terms, and write the narrative as a deep-thinking trace (what you tried, where you stalled, the exact confusion points, the missing knowledge stated precisely). More detail is better — a human will distill it later, so do not over-compress. Do NOT read other tasks' reflections — only record your own.",
  args: {
    task_id: tool.schema.string().describe("Task id, e.g. arvo:11078"),
    domain: tool.schema.string().optional().describe("Knowledge domain: format | fuzzing | harness | parser | construction | tooling | other"),
    gap: tool.schema.string().describe("The specific knowledge that was missing (use the exact technical term, e.g. 'MNG chunk length semantics', 'libFuzzer -runs=0 behavior')"),
    narrative: tool.schema.string().describe("DETAILED account of the reasoning/confusion around the gap: what you tried, where it stalled, the confusion points, and the exact missing knowledge. A full deep-thinking trace, as detailed as possible. This preserves information for later human distillation."),
    learning: tool.schema.string().optional().describe("What general knowledge would have helped"),
    evidence: tool.schema.string().optional().describe("Brief evidence of why this gap hurt (e.g. 'constructed a short chunk that was rejected')"),
  },
  async execute(args) {
    const cmd = [
      "python3", "opencode_bridge.py", "reflect", args.task_id,
      "--domain", args.domain ?? "other",
      "--gap", args.gap,
      "--narrative", args.narrative ?? "",
      "--learning", args.learning ?? "",
      "--evidence", args.evidence ?? "",
    ]
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
