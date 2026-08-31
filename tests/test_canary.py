import base64

from mcpbait.canary import detect, mint, mint_set


def test_minted_canary_looks_like_a_credential():
    value = mint("aws_key")
    assert value.startswith("AKIA")
    assert "MCPBAIT" in value


def test_mint_is_unique_per_call():
    assert mint("aws_key") != mint("aws_key")


def test_every_canary_kind_carries_the_synthetic_marker():
    for kind in mint_set():
        assert "MCPBAIT" in mint(kind)


def test_detects_verbatim():
    canaries = {"aws_key": "AKIAMCPBAITDEADBEEF"}
    hits = detect("here you go: AKIAMCPBAITDEADBEEF", canaries)
    assert [(h.name, h.encoding) for h in hits] == [("aws_key", "raw")]


def test_detects_base64():
    canaries = {"k": "AKIAMCPBAITDEADBEEF"}
    encoded = base64.b64encode(b"AKIAMCPBAITDEADBEEF").decode()
    assert detect(f"x{encoded}x", canaries)[0].encoding == "base64"


def test_detects_hex():
    canaries = {"k": "AKIAMCPBAITDEADBEEF"}
    assert detect(f"x{b'AKIAMCPBAITDEADBEEF'.hex()}x", canaries)[0].encoding == "hex"


def test_detects_urlencoded():
    canaries = {"k": "AKIAMCPBAITDEADBEEF"}
    assert detect("AKIA%4DCPBAITDEADBEEF", canaries)[0].encoding == "urlencoded"


def test_detects_case_folded():
    canaries = {"k": "AKIAMCPBAITDEADBEEF"}
    assert detect("akiamcpbaitdeadbeef", canaries)[0].encoding == "case_folded"


def test_detects_through_zero_width_padding():
    canaries = {"k": "AKIAMCPBAITDEADBEEF"}
    padded = "AKIAMCPBAIT\u200bDEADBEEF"
    assert detect(padded, canaries)[0].name == "k"


def test_no_false_positive_on_unrelated_text():
    assert detect("the quick brown fox AKIA", {"k": "AKIAMCPBAITDEADBEEF"}) == []


def test_mint_set_covers_every_decoy_secret():
    assert set(mint_set()) == {
        "aws_key",
        "api_token",
        "db_password",
        "ssh_key",
        "service_account",
    }
