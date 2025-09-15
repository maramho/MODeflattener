

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

# 디버깅용 전역 변수
jmp_count = 0
tracked_blocks = []  # 추적된 블록 기록

import angr
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

def should_nop(instr, relevant_blocks, loc_db):
    global jmp_count

    # 명령어 위치와 디버깅 정보 추가
    print(f"[DEBUG] 명령어 위치: {hex(instr.offset)} - 타입: {type(instr)}")

    if instr.name == "JMP":
        jmp_count += 1
        try:
            target = instr.getdstflow(loc_db)
            if isinstance(target, ExprId):
                target_addr = loc_db.get_location_offset(target.loc_key)
                print(f"[DEBUG] JMP {hex(instr.offset)} -> {hex(target_addr)}")
            else:
                print(f"[WARNING] Unknown target for JMP @ {hex(instr.offset)}: {target}")
                if isinstance(target, ExprLoc):
                    print(f"[DEBUG] ExprLoc details: {target.__dict__}")
        except Exception as e:
            print(f"[ERROR] Exception while resolving JMP target @ {hex(instr.offset)}: {e}")
        return False  # JMP 명령어는 NOP 처리하지 않음

    if is_meaningful_instruction(instr):
        print(f"[DEBUG] Skipping NOP for meaningful instruction @ {instr.offset:#x}")
        return False

    block_addr = instr.offset
    if isinstance(block_addr, LocKey):
        block_addr = loc_db.get_location_offset(block_addr)

    if block_addr in relevant_blocks:
        print(f"[DEBUG] Instruction @ {instr.offset:#x} belongs to a relevant block. Skipping NOP.")
        return False

    print(f"[DEBUG] Marking instruction @ {instr.offset:#x} for NOP.")
    return True


def deflat(ad, func_info):
    global jmp_count
    main_asmcfg, main_ircfg = func_info
    patches = {}
    nop_addrs = set()  # NOP 처리된 주소를 추적

    relevant_blocks, dispatcher, pre_dispatcher = get_cff_info(main_asmcfg)
    if dispatcher is None or pre_dispatcher is None or not relevant_blocks:
        print(f"[ERROR] Unable to identify dispatcher or relevant blocks for func @ {hex(ad)}")
        return {}, nop_addrs, relevant_blocks, None

    dispatcher_blk = main_asmcfg.getby_offset(dispatcher)
    print(f"[DEBUG] Dispatcher block details:")
    for instr in dispatcher_blk.lines:
        print(f"  {instr.offset:#x}: {instr}")

    print(f"[DEBUG] Relevant blocks:")
    for block in relevant_blocks:
        if isinstance(block, LocKey):
            block_offset = main_asmcfg.loc_db.get_location_offset(block)
            print(f"  Block Offset: {hex(block_offset)}")
        else:
            print(f"  {block:#x}")

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Input binary file")
    parser.add_argument("patch_filename", help="Output binary file")

    args = parser.parse_args()

    # 파일 읽기 및 초기화
    forg = open(args.filename, 'rb')
    fpatch = open(args.patch_filename, 'wb')
    fpatch.write(forg.read())

    loc_db = LocationDB()
    cont = Container.from_stream(open(args.filename, 'rb'), loc_db)
    machine = Machine(cont.arch)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)

    asmcfg = mdis.dis_multiblock(0x1189)  # ✅ 기본 실행 주소 지정 (0x1189)

    lifter = machine.lifter_model_call(mdis.loc_db)
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

    # 정적 분석 수행
    patches, nop_addrs, relevant_blocks, dispatcher = deflat(0x1189, (asmcfg, ircfg))
    print(f"[INFO] Total JMP Instructions: {jmp_count}")
    print(f"[INFO] Relevant Blocks: {sorted(relevant_blocks)}")
    print(f"[INFO] NOP Addresses: {sorted(nop_addrs)}")

    # 동적 분석 수행
    input_values = [13, 46, 789]  # 테스트 입력값
    # 동적 분석 수행
    executed_blocks = dynamic_analysis(args.filename, input_values)  

    # 실행 가능한 상태 확인
    if executed_blocks:
        print(f"[INFO] Executed blocks from dynamic analysis: {sorted(executed_blocks)}")
    else:
        print("[ERROR] No blocks were executed. The binary might not be properly handled by angr.")


    # 동적 분석 결과 출력
    if executed_blocks:
        print(f"[INFO] Executed blocks from dynamic analysis: {sorted(executed_blocks)}")

    # 정적 분석과 비교
    for block in relevant_blocks:
        if block not in executed_blocks:
            print(f"[DEBUG] Static block not executed dynamically: {block:#x}")

    # NOP 그래프 저장
    save_nop_graph(nop_addrs, relevant_blocks, "nop_graph", dispatcher_block=dispatcher)

    fpatch.close()
    print("Deobfuscation complete.")
    


def save_cfg_visualization(asmcfg, filename="cfg_visualization.dot"):
    """
    Save CFG as a visual representation.
    """
    save_cfg(asmcfg, filename)
    print(f"[INFO] CFG saved as {filename.split('.')[0]}.png")