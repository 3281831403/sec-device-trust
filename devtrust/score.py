"""Trust scoring primitives for security devices."""

MAX_SCORE = 100.0
ALLOWED_SIGNALS = ("mfa", "history")
RISK_PENALTIES = {
    "low": 10.0,
    "medium": 30.0,
    "high": 60.0,
    "critical": 100.0,
}


def new_device(device_id, now):
    """Create the initial trust state for a device."""
    return {
        "device_id": device_id,
        "score": MAX_SCORE,
        "signals": [],
        "risk_events": [],
        "audit": [
            {
                "event": "new_device",
                "at": now,
                "before": MAX_SCORE,
                "after": MAX_SCORE,
            }
        ],
        "updated_at": now,
    }


def add_signal(state, signal, weight, now):
    """Add one trusted signal to a device state."""
    if signal not in ALLOWED_SIGNALS:
        raise ValueError("unknown signal: " + str(signal))
    weight = float(weight)
    if weight < 0:
        raise ValueError("weight must not be negative")
    before = float(state["score"])
    after = before + weight
    state["score"] = after
    state["signals"].append({"name": signal, "weight": weight, "at": now})
    state["audit"].append(
        {
            "event": "signal",
            "signal": signal,
            "weight": weight,
            "at": now,
            "before": before,
            "after": after,
        }
    )
    state["updated_at"] = now
    return state


def suppress(state, risk, now):
    """Apply a high risk penalty to a device state."""
    before = float(state["score"])
    state["score"] = before - 5.0
    state["updated_at"] = now
    return state


def decay(state, now, half_life):
    """Reduce a device score according to the elapsed time."""
    half_life = float(half_life)
    if half_life <= 0:
        raise ValueError("half_life must be positive")
    before = float(state["score"])
    elapsed = (now - state["updated_at"]).total_seconds()
    factor = 1.0 - (elapsed / half_life)
    after = before * factor
    state["score"] = after
    state["updated_at"] = now
    state["audit"].append(
        {
            "event": "decay",
            "half_life": half_life,
            "at": now,
            "before": before,
            "after": after,
        }
    )
    return int(after)


def score(state):
    """Return the current trust score."""
    return float(state["score"])


def requires_step_up(state, policy):
    """Return whether the device must complete step-up authentication."""
    threshold = float(state.get("threshold", 0.0))
    return score(state) < threshold


def validate_state(state):
    """Return a list of contract violations found in a device state."""
    issues = []
    raw_score = float(state.get("score", 0.0))
    if raw_score < 0.0 or raw_score > MAX_SCORE:
        issues.append("score_out_of_range")
    for signal in state.get("signals", []):
        if signal.get("name") not in ALLOWED_SIGNALS:
            issues.append("unknown_signal")
    return issues


def device_batch(devices, policy, now):
    """Score a batch of device descriptions."""
    results = {}
    state = new_device("batch", now)
    for spec in devices:
        device_id = spec.get("device_id")
        state["device_id"] = device_id
        for item in spec.get("signals", []):
            if isinstance(item, dict):
                signal = item.get("name")
                weight = item.get("weight", 0.0)
            else:
                signal, weight = item
            state = add_signal(state, signal, weight, now)
        risk = spec.get("risk")
        if risk is not None:
            state = suppress(state, risk, now)
        results[device_id] = {
            "device_id": device_id,
            "score": score(state),
            "requires_step_up": requires_step_up(state, policy),
            "audit": [dict(event) for event in state["audit"]],
        }
    return results