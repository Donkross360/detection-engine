import re
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

log_path = "/home/ubuntu/detection-engine/detector/audit.log"
out_path = "/home/ubuntu/detection-engine/screenshots/Baseline-graph.png"

pattern = re.compile(
    r"^\[(?P<ts>[^]]+)\]\s+BASELINE_RECALC\s+-\s+\|\s+scheduled\s+\|\s+(?P<mean>[0-9.]+)\s+\|\s+(?P<stddev>[0-9.]+)\s+\|"
)

times = []
means = []
hours = []

with open(log_path, "r", encoding="utf-8") as f:
    for line in f:
        m = pattern.match(line.strip())
        if not m:
            continue
        ts = datetime.fromisoformat(m.group("ts"))
        mean = float(m.group("mean"))
        times.append(ts)
        means.append(mean)
        hours.append(ts.strftime("%Y-%m-%d %H:00"))

if len(times) < 2:
    raise SystemExit("Not enough baseline points yet.")

unique_hours = sorted(set(hours))
if len(unique_hours) < 2:
    raise SystemExit("Need at least two hourly slots in audit log.")

fig, ax = plt.subplots(figsize=(12, 5))
ax.plot(times, means, marker="o", linewidth=1.6, label="effective_mean")

# Shade alternating hour blocks for visual slot separation
hour_starts = sorted({dt.replace(minute=0, second=0, microsecond=0) for dt in times})
for i, start in enumerate(hour_starts):
    end = start.replace(minute=59, second=59, microsecond=999999)
    if i % 2 == 0:
        ax.axvspan(start, end, alpha=0.08, color="tab:blue")

# Annotate mean per hour near the last point of each hour
for hour in unique_hours:
    idxs = [i for i, h in enumerate(hours) if h == hour]
    hour_mean = sum(means[i] for i in idxs) / len(idxs)
    last_i = idxs[-1]
    ax.annotate(
        f"{hour.split()[1]} mean={hour_mean:.3f}",
        (times[last_i], means[last_i]),
        textcoords="offset points",
        xytext=(0, 8),
        ha="center",
        fontsize=8,
    )

ax.set_title("Baseline Effective Mean Over Time (Hourly Slots Highlighted)")
ax.set_xlabel("Time")
ax.set_ylabel("effective_mean")
ax.grid(True, alpha=0.3)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.legend()
fig.tight_layout()
fig.savefig(out_path, dpi=160)

print(f"Saved: {out_path}")
print(f"Hourly slots found: {len(unique_hours)} -> {unique_hours}")
