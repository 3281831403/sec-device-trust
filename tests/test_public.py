from datetime import datetime, timedelta

from devtrust.score import MAX_SCORE, add_signal, decay, device_batch, new_device, score

NOW = datetime(2026, 11, 19, 9, 0)
POLICY = {"threshold": 70}


def test_new_device_has_zero_trust():
    state = new_device("d-1", NOW)

    assert state["device_id"] == "d-1"
    assert state["score"] == 0


def test_signal_adds_to_trust_score():
    state = new_device("d-1", NOW)

    add_signal(state, "mfa", 20, NOW)
    add_signal(state, "history", 15, NOW + timedelta(minutes=5))

    assert score(state) == 35


def test_score_does_not_exceed_maximum():
    state = new_device("d-1", NOW)

    add_signal(state, "mfa", MAX_SCORE * 4, NOW)

    assert score(state) <= MAX_SCORE


def test_decay_reduces_score():
    state = new_device("d-1", NOW)
    add_signal(state, "history", 80, NOW)

    decayed = decay(state, NOW + timedelta(hours=1), 3600)

    assert 0 < decayed < 80
    assert score(state) == decayed


def test_batch_scores_devices_independently():
    devices = [
        {"device_id": "d-1", "signals": [("mfa", 30)]},
        {"device_id": "d-2", "signals": []},
    ]

    result = device_batch(devices, POLICY, NOW)

    assert result["d-1"]["score"] == 30
    assert result["d-2"]["score"] == 0