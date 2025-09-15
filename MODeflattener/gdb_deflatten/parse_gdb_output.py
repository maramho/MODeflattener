import re
import json

# GDB 로그 파일 읽기
with open('gdb_deflatten/gdb_output.log', 'r') as file:
    log_data = file.read()

# 📍 state 변수 변경 감지
state_pattern = r"📍 state 변경 감지: (-?\d+) \(주소: (0x[0-9a-fA-F]+)\)"
state_matches = re.findall(state_pattern, log_data)

state_data = {}
for value, address in state_matches:
    if address not in state_data:
        state_data[address] = []
    state_data[address].append(int(value))

# 📍 JMP 또는 MOV 감지
jmp_mov_pattern = r"\[DEBUG\] JMP 또는 MOV 감지: (0x[0-9a-fA-F]+)"
jmp_mov_matches = re.findall(jmp_mov_pattern, log_data)

# Flattening 패턴이 있는지 확인
flattened_blocks = []
for address, changes in state_data.items():
    if changes == [0, 2, -1]:  # 🎯 특정 패턴 감지 (예: 0 → 2 → -1)
        flattened_blocks.append(address)

# JSON 저장
result = {
    "state_address": list(state_data.keys())[0] if state_data else None,
    "state_changes": state_data,
    "flattened_blocks": flattened_blocks,  # ✅ Flattening 패턴이 발생한 블록
    "jmp_mov_blocks": jmp_mov_matches  # ✅ JMP 또는 MOV가 감지된 블록
}

with open('gdb_deflatten/state_changes.json', 'w') as json_file:
    json.dump(result, json_file, indent=4)

print(f"✅ state_changes.json 생성 완료: {result}")
