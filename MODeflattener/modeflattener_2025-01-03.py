import os  # File output을 위한 import
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
    """
    특정 명령어를 NOP 처리할지 여부를 판단합니다.
    """
    global jmp_count

    if instr.name == "JMP":
        jmp_count += 1
        try:
            # JMP 명령어의 대상 주소 추적
            target = instr.getdstflow(loc_db)
            if isinstance(target, ExprId):
                target_addr = loc_db.get_location_offset(target.loc_key)
                print(f"[INFO] JMP {instr.offset:#x} -> {target_addr:#x} [{jmp_count}]")
            else:
                print(f"[INFO] JMP {instr.offset:#x} -> Unknown Target [{jmp_count}]")
        except Exception as e:
            print(f"[ERROR] Failed to resolve JMP target @ {instr.offset:#x}: {e}")
        return False  # JMP 명령어는 NOP 처리하지 않음

    # 의미 있는 명령어 여부 판단
    if is_meaningful_instruction(instr):
        print(f"[DEBUG] Skipping NOP for meaningful instruction @ {instr.offset:#x}")
        return False

    # 블록이 중요한 블록인지 확인
    block_addr = instr.offset
    if isinstance(block_addr, LocKey):  # LocKey일 경우 변환
        block_addr = loc_db.get_location_offset(block_addr)

    if block_addr in relevant_blocks:
        print(f"[DEBUG] Instruction @ {instr.offset:#x} belongs to a relevant block. Skipping NOP.")
        return False

    # NOP 처리
    print(f"[DEBUG] Marking instruction @ {instr.offset:#x} for NOP.")
    return True


    # 의미 있는 명령어 여부 판단
    if is_meaningful_instruction(instr):
        return False

    # 블록이 중요한 블록인지 확인
    block_addr = instr.offset
    if isinstance(block_addr, LocKey):  # LocKey일 경우 변환
        block_addr = loc_db.get_location_offset(block_addr)

    if block_addr in relevant_blocks:
        return False

    # NOP 처리
    return True



def deflat(ad, func_info):
    global jmp_count
    main_asmcfg, main_ircfg = func_info
    patches = {}
    nop_addrs = set()  # NOP 처리된 주소를 추적

    relevant_blocks, dispatcher, pre_dispatcher = get_cff_info(main_asmcfg)
    if dispatcher is None or pre_dispatcher is None or not relevant_blocks:
        print(f"[ERROR] Unable to identify dispatcher or relevant blocks for func @ {hex(ad)}")
        return {}

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

    # NOP 처리
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

    # Backbone 처리
    backbone_start, backbone_end = dispatcher, addr + instrs[-1].l
    print(f"[DEBUG] Adding backbone patch from {hex(backbone_start)} to {hex(backbone_end)}")
    if backbone_start >= backbone_end:
        print(f"[ERROR] Invalid backbone patch range: {hex(backbone_start)} -> {hex(backbone_end)}")
    patches[backbone_start] = b"\x90" * (backbone_end - backbone_start)

    # 요약 정보 출력
    print(f"[SUMMARY] Total JMP Instructions: {jmp_count}")
    print(f"[SUMMARY] Total NOP Marked Instructions: {len(nop_addrs)}")
    print(f"[SUMMARY] NOP Marked Addresses: {sorted(nop_addrs)}")

    return patches



if __name__ == '__main__':
    parser = ArgumentParser("modeflattener")
    parser.add_argument('filename', help="file to deobfuscate")
    parser.add_argument('patch_filename', help="deobfuscated file name")
    parser.add_argument('address', help="obfuscated function address")
    parser.add_argument('-a', "--all", action="store_true",
                        help="find and deobfuscate all flattened functions recursively")
    parser.add_argument('-l', "--log", help="logging level (default=INFO)", default='info')

    args = parser.parse_args()
    _log = setup_logger(args.log)

    # 파일 읽기
    forg = open(args.filename, 'rb')
    fpatch = open(args.patch_filename, 'wb')
    fpatch.write(forg.read())

    loc_db = LocationDB()
    cont = Container.from_stream(open(args.filename, 'rb'), loc_db)
    machine = Machine(cont.arch)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)

    ad = int(args.address, 0)
    todo = [(mdis, None, ad)]
    done = set()
    all_funcs = set()
    all_funcs_blocks = {}

    # 블록 분석 루프 복원
    while todo:
        mdis, caller, ad = todo.pop(0)
        if ad in done:
            continue
        done.add(ad)

        # 블록 및 함수 정보 수집
        asmcfg = mdis.dis_multiblock(ad)
        lifter = machine.lifter_model_call(mdis.loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        all_funcs.add(ad)
        all_funcs_blocks[ad] = (asmcfg, ircfg)

        # 모든 블록 추적 옵션
        if args.all:
            for block in asmcfg.blocks:
                instr = block.get_subcall_instr()
                if not instr:
                    continue
                for dest in instr.getdstflow(mdis.loc_db):
                    if not dest.is_loc():
                        continue
                    offset = mdis.loc_db.get_location_offset(dest.loc_key)
                    todo.append((mdis, instr, offset))

    # 디스패칭 함수 처리
    for ad in all_funcs:
        asmcfg, ircfg = all_funcs_blocks[ad]
        score = calc_flattening_score(asmcfg)
        if score > 0.9:
            patches = deflat(ad, (asmcfg, ircfg))
            if patches:
                for offset, data in patches.items():
                    fpatch.seek(offset)
                    fpatch.write(data)

    fpatch.close()
    print("Deobfuscation complete.")
