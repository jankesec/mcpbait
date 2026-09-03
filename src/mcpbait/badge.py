"""Dynamic SVG badge generator for mcpbait resilience scores.

Produces self-contained SVG badges offline (zero network/external dependency)
for embedding in GitHub READMEs, PR comments, and CI dashboards.
"""

from __future__ import annotations


def generate_badge(score: float, label: str = "mcpbait resilience") -> str:
    """Generate clean Shields.io-style SVG badge for a resilience score."""
    clamped_score = max(0.0, min(10.0, score))
    formatted_score = f"{clamped_score:.1f}/10"

    # Color grading based on score
    if clamped_score >= 8.5:
        color = "#10b981"  # Emerald / Green
    elif clamped_score >= 7.0:
        color = "#34d399"  # Light Green
    elif clamped_score >= 5.0:
        color = "#f59e0b"  # Amber / Yellow
    elif clamped_score >= 3.0:
        color = "#f97316"  # Orange
    else:
        color = "#ef4444"  # Red

    # Width heuristics
    label_width = len(label) * 7 + 14
    value_width = len(formatted_score) * 7 + 16
    total_width = label_width + value_width

    label_x = label_width / 2
    value_x = label_width + (value_width / 2)

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {formatted_score}">
  <title>{label}: {formatted_score}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#24292e"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{int(label_x * 10)}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{int((label_width - 12) * 10)}">{label}</text>
    <text x="{int(label_x * 10)}" y="140" transform="scale(.1)" fill="#fff" textLength="{int((label_width - 12) * 10)}">{label}</text>
    <text aria-hidden="true" x="{int(value_x * 10)}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{int((value_width - 12) * 10)}">{formatted_score}</text>
    <text x="{int(value_x * 10)}" y="140" transform="scale(.1)" fill="#fff" textLength="{int((value_width - 12) * 10)}">{formatted_score}</text>
  </g>
</svg>"""
