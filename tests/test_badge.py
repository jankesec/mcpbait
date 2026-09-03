from mcpbait.badge import generate_badge


def test_generate_badge():
    svg_high = generate_badge(9.2)
    assert "<svg" in svg_high
    assert "9.2/10" in svg_high
    assert "#10b981" in svg_high  # Green color

    svg_low = generate_badge(2.1)
    assert "2.1/10" in svg_low
    assert "#ef4444" in svg_low  # Red color
