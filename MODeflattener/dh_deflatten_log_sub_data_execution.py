import re

# 입력 파일과 출력 파일 경로
input_file = "dh_deflatten_log.txt"
output_file = "dh_deflatten_log_sub_data_execution_info.txt"

# 추출할 결과를 담을 리스트
cmp_values = []

# FLAG_EQ_CMP 패턴에 해당하는 정규식
pattern = re.compile(r"FLAG_EQ_CMP\(RAX\[0:32\], (.*?)\)")

# 파일에서 추출
with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            cmp_values.append(match.group(1))

# 결과 출력 파일로 저장
with open(output_file, "w", encoding="utf-8") as f:
    for value in cmp_values:
        f.write(value + "\n")

print(f"[✔] 총 {len(cmp_values)}개의 값을 {output_file}에 저장했습니다.")

