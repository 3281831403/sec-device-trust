"""Trust scoring primitives for security devices.

Contract:
- A brand-new device starts at zero trust.
- Trust can only be accumulated through the allowed multi-factor / history
  signals.
- The score is capped at :data:`MAX_SCORE` and decays exponentially over time.
- Every score mutation is recorded in the audit trail.
- Risk events immediately suppress the score according to their level.
- Batch scoring is independent per device and fully deterministic.
- The score is always kept inside ``[0, MAX_SCORE]``.
"""

import math

MAX_SCORE = 100.0
ALLOWED_SIGNALS = ("mfa", "history")
RISK_PENALTIES = {
    "low": 10.0,
    "medium": 30.0,
    "high": 60.0,
    "critical": 100.0,
}


def _clamp(value):
    """Clamp ``value`` into the valid trust-score range."""
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("score must be finite")
    return max(0.0, min(MAX_SCORE, value))


def _normalize_risk(risk):
    """Return the canonical risk level or raise for an unknown level."""
    if isinstance(risk, dict):
        risk = risk.get("level", risk.get("risk", risk.get("name")))
    if not isinstance(risk, str):
        raise ValueError("unknown risk level: " + str(risk))
    level = risk.strip().lower()
    if level not in RISK_PENALTIES:
        raise ValueError("unknown risk level: " + str(risk))
    return level


def new_device(device_id, now):
    """Create the initial trust state for a device.

    A device that has never been seen carries no trust at all, so the initial
    score is zero.  The audit trail starts with the creation event.
    """
    return {
        "device_id": device_id,
        "score": 0.0,
        "signals": [],
        "risk_events": [],
        "audit": [
            {
                "event": "new_device",
                "at": now,
                "before": 0.0,
                "after": 0.0,
            }
        ],
        "updated_at": now,
    }


def add_signal(state, signal, weight, now):
    """Add one trusted signal to a device state.

    Only multi-factor ("mfa") and historical-behaviour ("history") signals may
    accumulate trust.  The resulting score is capped at :data:`MAX_SCORE`.
    """
    if signal not in ALLOWED_SIGNALS:
        raise ValueError("unknown signal: " + str(signal))
    weight = float(weight)
    if not math.isfinite(weight):
        raise ValueError("weight must be finite")
    if weight < 0:
        raise ValueError("weight must not be negative")
    before = float(state["score"])
    after = _clamp(before + weight)
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
    """Apply a risk penalty to a device state immediately.

    The penalty is determined by the risk level and the score can never fall
    below zero.  The event is recorded both as a risk event and in the audit
    trail.
    """
    level = _normalize_risk(risk)
    penalty = RISK_PENALTIES[level]
    before = float(state["score"])
    after = _clamp(before - penalty)
    state["score"] = after
    state["risk_events"].append({"risk": level, "penalty": penalty, "at": now})
    state["audit"].append(
        {
            "event": "suppress",
            "risk": level,
            "penalty": penalty,
            "at": now,
            "before": before,
            "after": after,
        }
    )
    state["updated_at"] = now
    return state


def decay(state, now, half_life):
    """Reduce a device score according to the elapsed time.

    ``half_life`` is expressed in seconds and the decay is exponential: after
    one half-life the score is halved, after two it is quartered, and so on.
    """
    half_life = float(half_life)
    if not math.isfinite(half_life):
        raise ValueError("half_life must be finite")
    if half_life <= 0:
        raise ValueError("half_life must be positive")
    before = float(state["score"])
    elapsed = (now - state["updated_at"]).total_seconds()
    if elapsed < 0:
        elapsed = 0.0
    factor = 0.5 ** (elapsed / half_life)
    after = _clamp(before * factor)
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
    return after


def score(state):
    """Return the current trust score."""
    return float(state["score"])


def requires_step_up(state, policy):
    """Return whether the device must complete step-up authentication.

    ``policy`` is normally a mapping with a ``threshold`` key, but a bare
    numeric threshold is also accepted.
    """
    if isinstance(policy, (int, float)):
        threshold = float(policy)
    else:
        threshold = float((policy or {}).get("threshold", 0.0))
    return score(state) < threshold


def validate_state(state):
    """Return a list of contract violations found in a device state."""
    issues = []
    raw_score = state.get("score")
    try:
        numeric_score = float(raw_score)
    except (TypeError, ValueError, AttributeError):
        issues.append("score_not_numeric")
        numeric_score = None
    if numeric_score is not None:
        if not math.isfinite(numeric_score):
            issues.append("score_not_finite")
            numeric_score = None
        elif numeric_score < 0.0 or numeric_score > MAX_SCORE:
            issues.append("score_out_of_range")
            numeric_score = None
    for signal in state.get("signals", []):
        if not isinstance(signal, dict):
            issues.append("signal_malformed")
            continue
        if signal.get("name") not in ALLOWED_SIGNALS:
            issues.append("unknown_signal")
        try:
            weight = float(signal.get("weight", 0.0))
        except (TypeError, ValueError, AttributeError):
            issues.append("signal_weight_invalid")
        else:
            if not math.isfinite(weight) or weight < 0:
                issues.append("signal_weight_invalid")
    for event in state.get("risk_events", []):
        if not isinstance(event, dict):
            issues.append("risk_event_malformed")
            continue
        try:
            _normalize_risk(event.get("risk"))
        except ValueError:
            issues.append("unknown_risk_level")
    audit = state.get("audit") or []
    if not audit:
        issues.append("audit_missing")
    elif numeric_score is not None and isinstance(audit[-1], dict):
        try:
            last_after = float(audit[-1].get("after"))
        except (TypeError, ValueError, AttributeError):
            issues.append("audit_malformed")
        else:
            if last_after != numeric_score:
                issues.append("audit_score_mismatch")
    return issues


def _apply_risk(state, risk, now):
    """Apply one risk value (a level, a description dict, or a list of them)."""
    if risk is None:
        return
    if isinstance(risk, (list, tuple)):
        for item in risk:
            _apply_risk(state, item, now)
        return
    suppress(state, risk, now)


def device_batch(devices, policy, now):
    """Score a batch of device descriptions.

    Each device gets its own fresh state, so signals and risk events never leak
    from one device to another.  The computation is deterministic: the same
    input always produces the same result.
    """
    results = {}
    for spec in devices:
        device_id = spec.get("device_id")
        state = new_device(device_id, now)
        for item in spec.get("signals", []):
            if isinstance(item, dict):
                signal = item.get("name")
                weight = item.get("weight", 0.0)
            else:
                signal, weight = item
            add_signal(state, signal, weight, now)
        _apply_risk(state, spec.get("risk"), now)
        _apply_risk(state, spec.get("risks"), now)
        results[device_id] = {
            "device_id": device_id,
            "score": score(state),
            "requires_step_up": requires_step_up(state, policy),
            "audit": [dict(event) for event in state["audit"]],
        }
    return results
