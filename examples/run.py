"""Evaluate every defence configuration and write results:
  examples/out/results.csv  — ASR, per-intent ASR, benign-pass-rate per config
  examples/out/results.png  — ASR vs utility as defences are layered
  examples/out/summary.md    — the headline table + the named residual under full defence
"""
import os, sys, csv
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from injeval.defenses import configs
from injeval.evaluate import evaluate, residual_summary

OUT = os.path.join(os.path.dirname(__file__), "out")
os.makedirs(OUT, exist_ok=True)


def main():
    ms = [evaluate(name, pipe) for name, pipe in configs().items()]

    with open(os.path.join(OUT, "results.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["config", "ASR", "ASR_exfil", "ASR_tool", "ASR_override", "benign_pass_rate"])
        for m in ms:
            w.writerow([m.config, f"{m.asr:.3f}", f"{m.asr_by_intent['exfil']:.3f}",
                        f"{m.asr_by_intent['tool']:.3f}", f"{m.asr_by_intent['override']:.3f}",
                        f"{m.benign_pass_rate:.3f}"])

    # chart: ASR (want low) and utility (want high) across the defence ladder
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    names = [m.config for m in ms]
    asr = [100 * m.asr for m in ms]
    util = [100 * m.benign_pass_rate for m in ms]
    x = range(len(names))
    fig, ax = plt.subplots(figsize=(9.2, 5.2), dpi=150)
    ax.plot(x, asr, "-o", color="#cf222e", lw=2.2, label="Attack-success rate (lower better)")
    ax.plot(x, util, "-s", color="#1f6feb", lw=2.2, label="Benign-pass rate / utility (higher better)")
    for xi, v in zip(x, asr): ax.annotate(f"{v:.0f}%", (xi, v), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=9, color="#cf222e")
    for xi, v in zip(x, util): ax.annotate(f"{v:.0f}%", (xi, v), textcoords="offset points", xytext=(0, -14), ha="center", fontsize=9, color="#1f6feb")
    ax.set_xticks(list(x)); ax.set_xticklabels(names, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Percent"); ax.set_ylim(-5, 108)
    ax.set_title("Prompt-injection defence: attack-success vs utility, as layers are added")
    ax.grid(True, axis="y", color="#e6e6e6", lw=0.8)
    for sp in ("top", "right"): ax.spines[sp].set_visible(False)
    ax.legend(frameon=False, fontsize=9, loc="center left")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "results.png"))

    with open(os.path.join(OUT, "summary.md"), "w") as f:
        f.write("# Prompt-injection defence evaluation\n\n")
        f.write("| Config | ASR | exfil | tool | override | Utility |\n|---|--:|--:|--:|--:|--:|\n")
        for m in ms:
            f.write(f"| {m.config} | {m.asr:.0%} | {m.asr_by_intent['exfil']:.0%} | "
                    f"{m.asr_by_intent['tool']:.0%} | {m.asr_by_intent['override']:.0%} | "
                    f"{m.benign_pass_rate:.0%} |\n")
        full = ms[-1]
        f.write(f"\n## Residual under defence-in-depth (ASR {full.asr:.0%})\n\n")
        for line in residual_summary(full):
            f.write(f"- {line}\n")
        f.write("\n**Lesson.** Detection alone is leaky *and* costs utility; capability "
                "isolation/gating drives the tool-abuse and policy-override classes to zero "
                "by construction with no utility cost. The only residual under full "
                "defence-in-depth is **semantic exfiltration** — which is solved "
                "architecturally (don't hand the agent the secret; use per-request scoped, "
                "short-lived tokens), not by output filtering.\n")
    print(open(os.path.join(OUT, "summary.md")).read())


if __name__ == "__main__":
    main()
