import re

input_file = "cfg_dh_1flatten_gdb.txt"
output_file = "cfg_dh_1flatten_sub+address_info.txt"

sub_pattern = re.compile(r"sub\s+\$(0x[0-9a-fA-F]+),\s*%eax")
je_pattern = re.compile(r"je\s+(0x[0-9a-fA-F]+)")

state_to_target = {}

with open(input_file, "r") as f:
    lines = f.readlines()

i = 0
while i < len(lines):
    sub_match = sub_pattern.search(lines[i])
    if sub_match:
        state_val = int(sub_match.group(1), 16)

        # 다음 1~3줄 내에서 je 찾기
        for lookahead in range(1, 4):
            if i + lookahead < len(lines):
                je_match = je_pattern.search(lines[i + lookahead])
                if je_match:
                    target_addr = int(je_match.group(1), 16)
                    state_to_target[state_val] = target_addr
                    break
    i += 1

# 출력
with open(output_file, "w") as f:
    f.write("state_to_target = {\n")
    for k, v in sorted(state_to_target.items()):
        f.write(f"    0x{k:x}: 0x{v:x},\n")
    f.write("}\n")

print(f"[+] 추출 완료: {len(state_to_target)}개의 항목이 {output_file}에 저장됨.")

