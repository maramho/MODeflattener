import os  # File output을 위한 import
import angr
import argparse
from future.utils import viewitems, viewvalues
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.analysis.simplifier import *
from miasm.expression.expression import *
from miasm.core.asmblock import *
from miasm.arch.x86.arch import mn_x86
from miasm.core.utils import encode_hex

from argparse import ArgumentParser
import time
import logging
import pprint

from mod_utils import *


jmp_count = 0
tracked_blocks = []  # 추적된 블록 기록
jmp_targets = []  # 🚀 JMP 명령어 저장할 리스트 추가
jmp_call_flow = {}  # 🚀 각 JMP가 호출하는 흐름 저장
neighboring_blocks = {}  # 🚀 이웃 블록 저장




def dynamic_analysis(binary_path, input_values):
    print(f"[INFO] Starting dynamic analysis for {binary_path}...")
    proj = angr.Project(binary_path, auto_load_libs=False)

    executed_blocks = set()

    for input_value in input_values:
        print(f"[INFO] Testing input: {input_value}")

        # ✅ Prepare input data
        input_data = (str(input_value) + "\n").encode()

        # ✅ `SimFile`을 생성할 때 `size` 추가
        sim_stdin = angr.SimFile("stdin", content=input_data, size=len(input_data))

        # ✅ 초기 상태 생성 (`full_init_state()` 사용)
        state = proj.factory.full_init_state(
            args=[binary_path],  # 실행 인자로 바이너리 추가
            stdin=sim_stdin,  # 🔹 stdin 설정
            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                         angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                         angr.options.UNICORN}  # 🔹 Unicorn 사용
        )

        # ✅ `stdin`을 명확히 설정
        state.posix.fd[0] = sim_stdin  # 🔹 fd[0]을 stdin으로 연결

        # ✅ Debugging: stdin이 정상적으로 설정되었는지 확인
        try:
            stdin_content = state.posix.dumps(0)  # 🔹 `read_storage` 대신 사용
            print(f"[DEBUG] Before Execution, Stdin: {stdin_content}")
        except Exception as e:
            print(f"[ERROR] Failed to dump stdin before execution: {e}")

        # 🔹 실행
        try:
            simgr = proj.factory.simgr(state)
            simgr.run()
        except Exception as e:
            print(f"[ERROR] Execution failed: {e}")
            continue

        # ✅ 실행된 블록 확인
        if simgr.active:
            for active_state in simgr.active:
                executed_blocks.update(active_state.history.bbl_addrs)
                output = active_state.posix.dumps(1).decode('utf-8', 'ignore')  # 🔹 stdout 읽기
                print(f"[INFO] Output for input {input_value}: {output}")

        print(f"[INFO] Executed Blocks: {sorted(executed_blocks)}")

    print(f"[INFO] Dynamic analysis completed. Total executed blocks: {len(executed_blocks)}")

    # 추가적인 디버깅 로그
    if len(executed_blocks) == 0:
        print("[ERROR] No blocks were executed. The binary might not be properly handled by angr.")

    return executed_blocks



def is_flattening_related_block(block_addr):
    """
    Flattening과 관련된 블록인지 판별하는 함수.
    - Dispatcher 및 Pre-Dispatcher 블록을 참조하는 경우
    - Flattening의 상태 변수 (state_var) 기반으로 동작하는 경우
    - 비정상적인 다수의 조건 분기가 포함된 경우
    """
    flattening_keywords = ["state_var", "switch", "case", "dispatcher"]
    
    block = main_asmcfg.getby_offset(block_addr)
    if not block:
        return False

    # ✅ 블록 내 Flattening 관련 키워드 존재 여부 확인
    for instr in block.lines:
        instr_str = str(instr).lower()
        if any(keyword in instr_str for keyword in flattening_keywords):
            return True

    return False



def deflat(ad, func_info):
    """
    Flattening을 제거하고, Dispatcher 및 불필요한 분기 블록을 정리한 정적 분석 수행.
    """
    global jmp_count
    main_asmcfg, main_ircfg = func_info
    patches = {}
    nop_addrs = set()  # NOP 처리된 주소를 추적

    # 🔹 Flattening 관련 블록을 식별하여 정리
    relevant_blocks, dispatcher, pre_dispatcher = get_cff_info(main_asmcfg)
    filtered_blocks = set(relevant_blocks)  # 새로운 필터링 리스트 생성

    if dispatcher is not None:
        print(f"[INFO] Removing dispatcher block @ {hex(dispatcher)} from flow")
        filtered_blocks.discard(dispatcher)

    if pre_dispatcher is not None:
        print(f"[INFO] Removing pre-dispatcher block @ {hex(pre_dispatcher)} from flow")
        filtered_blocks.discard(pre_dispatcher)

    # ✅ 추가적인 Flattening 관련 블록도 제거 (불필요한 상태 관리 블록 포함)
    for block in list(filtered_blocks):
        if is_flattening_related_block(block, main_asmcfg):
            print(f"[INFO] Removing additional flattening block @ {hex(block)}")
            filtered_blocks.discard(block)

    relevant_blocks = filtered_blocks  # 필터링된 블록만 유지

    if dispatcher is None or pre_dispatcher is None or not relevant_blocks:
        print(f"[ERROR] Unable to identify dispatcher or relevant blocks for func @ {hex(ad)}")
        return {}, nop_addrs, relevant_blocks, None

    # 🔥 Dispatcher 블록 상세 정보 출력
    dispatcher_blk = main_asmcfg.getby_offset(dispatcher)
    print(f"[DEBUG] Dispatcher block details:")
    for instr in dispatcher_blk.lines:
        print(f"  {instr.offset:#x}: {instr}")

    # 🔥 정리된 Relevant Blocks 출력
    print(f"[DEBUG] Relevant blocks after filtering:")
    for block in relevant_blocks:
        if isinstance(block, LocKey):
            block_offset = main_asmcfg.loc_db.get_location_offset(block)
            print(f"  Block Offset: {hex(block_offset)}")
        else:
            print(f"  {block:#x}")

    # 🔥 Flattening이 제거된 블록들만 패치 생성
    for addr in relevant_blocks:
        if isinstance(addr, LocKey):
            addr = main_asmcfg.loc_db.get_location_offset(addr)

        asmcfg = main_asmcfg.getby_offset(addr)
        instrs = [instr for instr in asmcfg.lines]

        link = {'next': '0x0'}
        try:
            for instr in instrs:
                if should_nop(instr, relevant_blocks, main_asmcfg.loc_db):
                    nop_addrs.add(instr.offset)
            patch = patch_gen(instrs, main_asmcfg.loc_db, nop_addrs, link)
            if patch:
                patches[addr] = patch
            else:
                print(f"[ERROR] Patch generation failed for block @ {hex(addr)}")
        except Exception as e:
            print(f"[ERROR] Exception during patch generation for block @ {hex(addr)}: {e}")

    print(f"[DEBUG] deflat returns: patches={len(patches)}, nop_addrs={len(nop_addrs)}, relevant_blocks={len(relevant_blocks)}")
    return patches, nop_addrs, relevant_blocks, dispatcher

def is_flattening_related_block(block_addr, asmcfg):
    """
    Flattening과 관련된 블록인지 판별하는 함수.
    - Dispatcher 및 Pre-Dispatcher 블록을 참조하는 경우
    - Flattening의 상태 변수 (state_var) 기반으로 동작하는 경우
    - 비정상적인 다수의 조건 분기가 포함된 경우
    """
    flattening_keywords = ["state_var", "switch", "case", "dispatcher"]
    
    block = asmcfg.getby_offset(block_addr)
    if not block:
        return False

    # ✅ 블록 내 Flattening 관련 키워드 존재 여부 확인
    for instr in block.lines:
        instr_str = str(instr).lower()
        if any(keyword in instr_str for keyword in flattening_keywords):
            return True

    return False



def find_state_var_usedefs(ircfg, state_var):
    """
    State Variable의 정의와 사용 주소를 찾습니다.
    """
    state_var_str = str(state_var)  # state_var를 문자열로 변환
    state_var_addrs = set()
    loc_db = ircfg.loc_db  # LocationDB 참조

    for block_addr, block in ircfg.blocks.items():
        # LocKey를 오프셋 주소로 변환
        offset = loc_db.get_location_offset(block_addr)

        for assignblk in block:
            for dst, src in assignblk.items():
                # src가 문자열이 아닐 경우 처리
                if not isinstance(src, str):
                    src = str(src)
                if state_var_str in src:
                    state_var_addrs.add(offset)  # 변환된 오프셋 주소 저장
                    print(f"[DEBUG] State variable found in block @ {hex(offset)}")
                    break

    return state_var_addrs


def calc_flattening_score(asm_graph):
    """
    Calculate the flattening score for the given assembly graph.
    A higher score indicates more control flow flattening.
    """
    score = 0.0
    for head in asm_graph.heads_iter():
        dominator_tree = asm_graph.compute_dominator_tree(head)
        for block in asm_graph.blocks:
            block_key = asm_graph.loc_db.get_offset_location(block.lines[0].offset)
            dominated = set(
                [block_key] + [b for b in dominator_tree.walk_depth_first_forward(block_key)]
            )
            if not any([b in dominated for b in asm_graph.predecessors(block_key)]):
                continue
            score = max(score, len(dominated) / len(asm_graph.nodes()))
    return score


def setup_logger(loglevel):
    FORMAT = '[%(levelname)s] %(message)s'
    logging.basicConfig(format=FORMAT)
    logger = logging.getLogger('modeflattener')

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)

    logger.setLevel(numeric_level)
    return logger


def is_meaningful_instruction(instr):
    """
    의미 있는 명령어를 식별합니다.
    """
    meaningful_ops = ["MOV", "ADD", "SUB", "MUL", "DIV", "CMP", "CALL", "RET"]
    # 의미 있는 명령어 확인
    if instr.name in meaningful_ops:
        return True
    # state_var 사용 여부 확인
    if "state_var" in str(instr.get_args_expr()):
        return True
    return False

# 🚀 추가: JMP 흐름을 저장할 리스트 (전역 변수)
jmp_flow = []

def should_nop(instr, relevant_blocks, loc_db):
    global jmp_count

    if instr.name == "JMP":
        jmp_count += 1
        try:
            target = instr.getdstflow(loc_db)
            if isinstance(target, ExprId):
                target_addr = loc_db.get_location_offset(target.loc_key)
                jmp_type = f"jmp {hex(target_addr)}"  # 🚀 JMP 대상 주소 기록
            else:
                target_addr = instr.args[0]  # 상대적 JMP 처리
                jmp_type = f"jmp {target_addr}"  

            # 🚀 JMP 흐름 저장
            jmp_flow[instr.offset] = target_addr
            jmp_targets.append(jmp_type)  # 🚀 저장
            print(f"[DEBUG] JMP {hex(instr.offset)} -> {jmp_type}")  # 🚀 출력
        except Exception as e:
            print(f"[ERROR] Exception while resolving JMP target @ {hex(instr.offset)}: {e}")

        return False  # 🚨 JMP 명령어는 NOP 처리하지 않음
    
    
    
def analyze_static_flow(asmcfg):
    """
    정적 분석을 수행하여 전체 흐름을 출력하고, JMP 명령어가 있을 때 흐름을 저장.
    """
    global jmp_count

    flow_analysis = []
    jmp_call_flow_cleaned = {}  # ✅ 에러 해결: 함수 내에서 초기화

    print("\n[INFO] Starting Static Flow Analysis...\n")

    for blk in asmcfg.blocks:
        blk_offset = asmcfg.loc_db.get_location_offset(blk.loc_key)
        print(f"[DEBUG] Analyzing block @ {hex(blk_offset)}")

        for instr in blk.lines:
            instr_info = f"{hex(instr.offset)}: {instr.name} {', '.join(map(str, instr.args))}"

            # 🚀 JMP 명령어가 있을 경우, 호출 흐름 추적
            if instr.name == "JMP":
                jmp_count += 1
                try:
                    target = instr.getdstflow(asmcfg.loc_db)
                    if isinstance(target, ExprId):
                        target_addr = asmcfg.loc_db.get_location_offset(target.loc_key)
                        jmp_type = f"jmp {hex(target_addr)}"
                    else:
                        jmp_type = f"jmp {instr.args[0]}"

                    jmp_targets.append(jmp_type)
                    instr_info += f"  --> {jmp_type}"

                    # ✅ 각 JMP가 점프하는 블록을 저장
                    if hex(instr.offset) not in jmp_call_flow_cleaned:
                        jmp_call_flow_cleaned[hex(instr.offset)] = []
                    jmp_call_flow_cleaned[hex(instr.offset)].append(hex(target_addr))

                except Exception as e:
                    print(f"[ERROR] Failed to resolve JMP target @ {hex(instr.offset)}: {e}")

            # ✅ 전체 흐름 저장
            flow_analysis.append(instr_info)

    # 🔥 전체 흐름 출력
    print("\n[INFO] Static Analysis Flow:\n")
    for line in flow_analysis:
        print(line)

    # 🔥 JMP 흐름 출력
    print("\n[INFO] Cleaned JMP Call Flow:\n")
    for jmp_addr, targets in jmp_call_flow_cleaned.items():
        print(f"  {jmp_addr} -> {', '.join(targets)}")

    print(f"\n[INFO] Total JMP Instructions: {jmp_count}")
    print("[INFO] Static Analysis Complete.")

    return jmp_call_flow_cleaned  # ✅ 함수가 반환하도록 변경


# 🚀 추가: JMP 흐름을 저장할 리스트 (전역 변수)
jmp_flow = []

def should_nop(instr, relevant_blocks, loc_db):
    global jmp_count

    if instr.name == "JMP":
        jmp_count += 1
        target_addr = None  # 🔹 target_addr 초기화

        try:
            target = instr.getdstflow(loc_db)
            if isinstance(target, ExprId):
                target_addr = loc_db.get_location_offset(target.loc_key)
                jmp_type = f"jmp {hex(target_addr)}"
            else:
                jmp_type = f"jmp {instr.args[0]}"

            jmp_targets.append(jmp_type)  
            print(f"[DEBUG] JMP {hex(instr.offset)} -> {jmp_type}")  

            # ✅ JMP 흐름을 추적하여 저장
            jmp_flow.append(f"[JMP] {hex(instr.offset)} → {jmp_type}")

            # ✅ JMP 발생 시 dh 시그니처 추가
            print(f"[INFO] JMP {hex(instr.offset)} encountered. Adding signature: dh")
            jmp_flow.append(f"[JMP] {hex(instr.offset)} → {jmp_type}  [dh]")

        except Exception as e:
            print(f"[ERROR] Failed to resolve JMP target @ {hex(instr.offset)}: {e}")
            target_addr = None  

        return False  
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Input binary file")
    parser.add_argument("patch_filename", help="Output binary file")

    args = parser.parse_args()

    forg = open(args.filename, 'rb')
    fpatch = open(args.patch_filename, 'wb')
    fpatch.write(forg.read())

    loc_db = LocationDB()
    cont = Container.from_stream(open(args.filename, 'rb'), loc_db)
    machine = Machine(cont.arch)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)

    asmcfg = mdis.dis_multiblock(0x1189)  

    lifter = machine.lifter_model_call(mdis.loc_db)
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

    patches, nop_addrs, relevant_blocks, dispatcher = deflat(0x1189, (asmcfg, ircfg))

    if relevant_blocks is None:
        relevant_blocks = []

    # ✅ 정적 분석 수행하고 결과 저장
    jmp_call_flow_cleaned = analyze_static_flow(asmcfg)  # 🔥 에러 해결

    print(f"[INFO] Total JMP Instructions: {jmp_count}")
    print(f"[INFO] Relevant Blocks: {sorted(relevant_blocks)}")
    print(f"[INFO] NOP Addresses: {sorted(nop_addrs)}")

    # ✅ Neighboring Blocks도 함께 출력
    print(f"\n[INFO] Neighboring Blocks (JMP 대상 블록과 연결된 블록):")
    for blk in relevant_blocks:
        print(f"  {hex(blk)} -> {', '.join(neighboring_blocks.get(hex(blk), []))}")

    # ✅ Cleaned JMP Flow를 출력 및 저장
    print("\n[INFO] Cleaned JMP Call Flow:")
    for jmp_addr, targets in jmp_call_flow_cleaned.items():
        print(f"  {jmp_addr} -> {', '.join(targets)}")

    with open("dh_cleaned_flow.txt", "w") as f:
        f.write("\n[INFO] Cleaned JMP Call Flow (Flattening 제거 후):\n")
        for jmp_addr, targets in jmp_call_flow_cleaned.items():
            f.write(f"  {jmp_addr} -> {', '.join(targets)}\n")

    print("\n[INFO] Cleaned JMP Flow recorded in dh_cleaned_flow.txt")

    # ✅ 동적 분석 수행
    input_values = [13, 46, 789]  # 테스트 입력값
    executed_blocks = dynamic_analysis(args.filename, input_values)  

    if executed_blocks:
        print(f"[INFO] Executed blocks from dynamic analysis: {sorted(executed_blocks)}")
    else:
        print("[ERROR] No blocks were executed. The binary might not be properly handled by angr.")

    for block in relevant_blocks:
        if block not in executed_blocks:
            print(f"[DEBUG] Static block not executed dynamically: {block:#x}")

    fpatch.close()
    print("[INFO] Deobfuscation complete.")




    


def save_cfg_visualization(asmcfg, filename="cfg_visualization.dot"):
    """
    Save CFG as a visual representation.
    """
    save_cfg(asmcfg, filename)
    print(f"[INFO] CFG saved as {filename.split('.')[0]}.png")