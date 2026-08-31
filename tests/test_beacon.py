import urllib.request

from mcpbait.beacon import Beacon


def test_beacon_captures_query_parameters():
    hits = []
    beacon = Beacon(on_hit=lambda path, params: hits.append((path, params)))
    url = beacon.start()
    try:
        urllib.request.urlopen(f"{url}/px.png?d=AKIAMCPBAITLEAK&m=markdown_beacon").read()
    finally:
        beacon.stop()
    assert hits[0][0] == "/px.png"
    assert hits[0][1]["d"] == "AKIAMCPBAITLEAK"
    assert hits[0][1]["m"] == "markdown_beacon"


def test_beacon_binds_loopback_only():
    beacon = Beacon(on_hit=lambda path, params: None)
    url = beacon.start()
    try:
        assert url.startswith("http://127.0.0.1:")
    finally:
        beacon.stop()


def test_beacon_returns_a_valid_image_response():
    beacon = Beacon(on_hit=lambda path, params: None)
    url = beacon.start()
    try:
        with urllib.request.urlopen(f"{url}/px.png") as response:
            assert response.status == 200
            assert response.headers["Content-Type"] == "image/png"
            assert response.read().startswith(b"\x89PNG")
    finally:
        beacon.stop()


def test_a_failing_callback_does_not_break_the_response():
    def explode(path, params):
        raise RuntimeError("boom")

    beacon = Beacon(on_hit=explode)
    url = beacon.start()
    try:
        with urllib.request.urlopen(f"{url}/px.png?d=x") as response:
            assert response.status == 200
    finally:
        beacon.stop()
