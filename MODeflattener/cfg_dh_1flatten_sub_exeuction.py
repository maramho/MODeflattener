import re

# 입력 로그 파일
input_file = "cfg_dh_1flatten_gdb.txt"

# 출력 파일
output_file = "cfg_dh_1flatten_sub_info.txt"

# 정규식 패턴: sub $0x????, %eax
pattern = re.compile(r"sub\s+\$(0x[0-9a-fA-F]+),\s*%eax")

# 중복 제거용 set, 전체 기록용 리스트
unique_vals = set()
all_vals = []

# 파일 읽기 및 추출
with open(input_file, "r") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            val = match.group(1).lower()
            all_vals.append(val)       # 전체 기록
            unique_vals.add(val)       # 중복 제거용

# 정렬된 중복 제거 리스트
sorted_unique_vals = sorted(unique_vals, key=lambda x: int(x, 16))

# 파일로 저장
with open(output_file, "w") as out:
    out.write("[unique cmp_vals] (중복 제거된 값들)\n")
    for val in sorted_unique_vals:
        out.write(val + "\n")

    out.write("\n[all cmp_vals] (중복 포함한 원본 순서)\n")
    for val in all_vals:
        out.write(val + "\n")

print(f"[+] 고유 cmp_vals {len(sorted_unique_vals)}개, 전체 {len(all_vals)}개 항목 저장 완료 → {output_file}")
