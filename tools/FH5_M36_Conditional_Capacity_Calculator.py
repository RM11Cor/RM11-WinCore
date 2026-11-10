#!/usr/bin/env python3
"""FH5 M36: conditional math check ONLY, not a GPU/game runtime monitor.

Compiled glass DXIL loop evidence (see research/M36_VERIFIED_CONDITIONAL_GLASS_DESCRIPTOR_GATE.md):
  N1 = space0:b2 row71 component1, index = i+10 or i+11
  N2 = space0:b2 row71 component2, index = i+30 or i+31
Values N1, N2 and C must be OBSERVED elsewhere and are NOT included here.
"""
import argparse
import json

MAX_I32 = (1 << 31) - 1

def check(n1: int, n2: int, descriptor_count: int) -> dict:
    for name, x in (("N1", n1), ("N2", n2), ("descriptor_count", descriptor_count)):
        if type(x) is not int:
            raise ValueError(f"{name} must be an integer")
    if n1 < 0 or n2 < 0:
        raise ValueError("Negative loop bounds are outside this conditional proof")
    if n1 > MAX_I32 - 10 or n2 > MAX_I32 - 30:
        raise ValueError("Possible signed i32 overflow in texture index calculations")
    if not 0 <= descriptor_count <= MAX_I32:
        raise ValueError("Invalid descriptor capacity")
    a = n1 + 11 if n1 > 0 else 0
    b = n2 + 31 if n2 > 0 else 0
    required = max(a, b)
    return {
        "scope": "Only 4 original dynamic glass SRV handles in space6:t0",
        "first_loop_required_slots": a,
        "second_loop_required_slots": b,
        "minimum_required_slots": required,
        "reported_capacity": descriptor_count,
        "hypothetically_sufficient": descriptor_count >= required,
        "real_game_runtime_verified": False,
        "full_shader_descriptor_safety_proven": False,
        "note": "Supply verified same-render-state values; arbitrary examples prove nothing about actual FH5 runtime."
    }

def main():
    p = argparse.ArgumentParser(description="FH5 M36 conditional descriptor capacity; NOT a runtime measurement")
    p.add_argument("--n1", type=int, required=True, help="Observed b2 row71 component 1")
    p.add_argument("--n2", type=int, required=True, help="Observed b2 row71 component 2")
    p.add_argument("--capacity", type=int, required=True, help="Observed bound space6:t0 descriptor slots")
    args = p.parse_args()
    try:
        result = check(args.n1, args.n2, args.capacity)
    except ValueError as exc:
        p.error(str(exc))
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
