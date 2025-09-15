#!/usr/bin/env python3
import argparse, subprocess, random, re, sys, os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from subprocess import TimeoutExpired

def run(b, x, timeout):
    try:
        p = subprocess.run([b], input=f"{x}\n", text=True,
                           capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr, None
    except TimeoutExpired:
        return None, "", "", "timeout"

def norm(out):
    import re
    s = "\n".join(ln.strip() for ln in out.strip().splitlines() if ln.strip())
    m = re.search(r"result\s*:\s*([-+]?\d+)", s, re.I)
    return m.group(1) if m else s

def worker(x, b1, b2, t1, t2):
    rc1,o1,e1,err1 = run(b1, x, t1)
    if err1:  # 1차 timeout이면 넉넉한 타임아웃으로 1회 재시도
        rc1,o1,e1,err1 = run(b1, x, t2)
    rc2,o2,e2,err2 = run(b2, x, t1)
    if err2:
        rc2,o2,e2,err2 = run(b2, x, t2)

    if err1 or err2:
        return ("timeout", x, (rc1,norm(o1)), (rc2,norm(o2)))

    n1, n2 = norm(o1), norm(o2)
    ok = (rc1 == rc2) and (n1 == n2)
    return ("ok" if ok else "mismatch", x, (rc1,n1), (rc2,n2))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin1", required=True)
    ap.add_argument("--bin2", required=True)
    ap.add_argument("--seq-from", type=int, default=-500)
    ap.add_argument("--seq-to", type=int, default=500)
    ap.add_argument("--rand", type=int, default=2000)
    ap.add_argument("--rand-min", type=int, default=-10**6)
    ap.add_argument("--rand-max", type=int, default=10**6)
    ap.add_argument("--timeout", type=float, default=0.5)   # 1차 타임아웃
    ap.add_argument("--retry-timeout", type=float, default=2.0)  # 재시도 타임아웃
    ap.add_argument("--parallel", type=int, default=max(1, (os.cpu_count() or 2)//2))
    args = ap.parse_args()

    for b in (args.bin1, args.bin2):
        if not Path(b).exists(): print("[ERR] not found:", b); sys.exit(2)
        if not os.access(b, os.X_OK): print("[ERR] not exec:", b); sys.exit(2)

    # 입력 구성
    inputs = list(range(args.seq_from, args.seq_to + 1))
    rng = random.Random(0xC0FFEE)
    inputs += [rng.randint(args.rand_min, args.rand_max) for _ in range(args.rand)]

    print(f"[INFO] total cases: {len(inputs)} (parallel={args.parallel})")

    tested = 0
    with ThreadPoolExecutor(max_workers=args.parallel) as ex:
        futs = [ex.submit(worker, x, args.bin1, args.bin2, args.timeout, args.retry_timeout) for x in inputs]
        for fut in as_completed(futs):
            status, x, b1, b2 = fut.result()
            tested += 1
            if tested % 500 == 0:
                print(f"[PROGRESS] {tested}/{len(inputs)}")
            if status != "ok":
                if status == "timeout":
                    print(f"[TIMEOUT] input={x}  b1={b1}  b2={b2}")
                else:
                    print("=== MISMATCH ===")
                    print(f"input={x}")
                    print(f"{args.bin1}: rc={b1[0]} out={b1[1]!r}")
                    print(f"{args.bin2}: rc={b2[0]} out={b2[1]!r}")
                sys.exit(1)

    print(f"All {tested} tests passed ✅")

if __name__ == "__main__":
    main()
