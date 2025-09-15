#!/usr/bin/env python3
import argparse, subprocess, random, re, sys

def run(b, x, timeout=3):
    p = subprocess.run([b], input=f"{x}\n", text=True,
                       capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def normalize(out):
    # "Enter an integer:" 같은 프롬프트/공백 제거
    s = "\n".join([ln.strip() for ln in out.strip().splitlines() if ln.strip()])
    # "Result: 7571" 같은 패턴이 있으면 그 값만 비교
    m = re.search(r"result\s*:\s*([-+]?\d+)", s, re.I)
    return m.group(1) if m else s

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin1", default="./cfg_dh_1flatten_binary")
    ap.add_argument("--bin2", default="./cfg_dh_1flatten_binary_deflatten")
    ap.add_argument("--seq-from", type=int, default=-2000)
    ap.add_argument("--seq-to", type=int, default=2000)
    ap.add_argument("--rand", type=int, default=10000)
    ap.add_argument("--rand-min", type=int, default=-10**6)
    ap.add_argument("--rand-max", type=int, default=10**6)
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    def check(x):
        rc1, o1, e1 = run(args.bin1, x, args.timeout)
        rc2, o2, e2 = run(args.bin2, x, args.timeout)
        n1, n2 = normalize(o1), normalize(o2)
        ok = (rc1 == rc2) and (n1 == n2)
        if not ok:
            print("=== MISMATCH ===")
            print(f"input={x}")
            print(f"{args.bin1}: rc={rc1} out={n1!r}")
            print(f"{args.bin2}: rc={rc2} out={n2!r}")
        return ok

    # 1) 연속 범위
    for x in range(args.seq_from, args.seq_to + 1):
        if not check(x):
            sys.exit(1)

    # 2) 랜덤
    rng = random.Random(0xC0FFEE)  # 재현성
    for _ in range(args.rand):
        x = rng.randint(args.rand_min, args.rand_max)
        if not check(x):
            sys.exit(1)

    print("All tests passed ✅")

if __name__ == "__main__":
    main()

