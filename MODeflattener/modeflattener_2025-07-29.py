import os  # File output을 위한 import
import angr
import argparse
import claripy
import pprint
import time
import logging
import signal

from future.utils import viewitems, viewvalues
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.analysis.simplifier import *
from miasm.expression.expression import *
from miasm.core.asmblock import *
from miasm.arch.x86.arch import mn_x86
from miasm.core.utils import encode_hex
from mod_utils import extract_flattened_edges
from miasm.expression.expression import ExprAff, ExprCond
from argparse import ArgumentParser
from mod_utils import *
from collections import defaultdict
from angr.storage.file import SimFileStream


class TimeoutException(Exception):
    pass

class ScanfHook(angr.SimProcedure):
    input_value = 0

    def run(self, fmt_str, addr):
        self.state.memory.store(addr, ScanfHook.input_value, endness=self.state.arch.memory_endness)
        return 1




neighboring_blocks = defaultdict(list)
jmp_count = 0
tracked_blocks = []  # 추적된 블록 기록
jmp_targets = []  # 🚀 JMP 명령어 저장할 리스트 추가
jmp_call_flow = {}  # 🚀 각 JMP가 호출하는 흐름 저장


def timeout_handler(signum, frame):
    raise TimeoutException()

def dynamic_analysis(binary_path, main_addr, dispatcher_addr=None, log_level=logging.INFO):
    import os

    proj = angr.Project(binary_path, auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)

    executed_blocks_set = set()
    executed_blocks_list = []

    output_lines = []  # 📌 결과 저장용 리스트

    for step in range(1000):
        if not simgr.active:
            output_lines.append("[ERROR] No active states remaining.")
            break

        state = simgr.active[0]
        pc = state.addr

        if pc not in executed_blocks_set:
            executed_blocks_set.add(pc)
            executed_blocks_list.append(pc)

        output_lines.append(f"\n[Step {step}] PC = {hex(pc)}")

        # ✅ eax 기반 dispatcher 값 출력
        try:
            dispatcher_val = state.solver.eval(state.regs.eax)
            output_lines.append(f"    └─ dispatcher_val (from eax) = {dispatcher_val}")
        except Exception as e:
            output_lines.append(f"    └─ dispatcher_val (from eax) read failed: {e}")

        # 레지스터 상태 출력
        try:
            edi_val = state.solver.eval(state.regs.edi)
            esi_val = state.solver.eval(state.regs.esi)
            output_lines.append(f"    └─ edi = {edi_val}")
            output_lines.append(f"    └─ esi = {esi_val}")
        except Exception as e:
            output_lines.append(f"    └─ Register read error: {e}")

        simgr.step()

        # ✅ 동일 블록 반복 감지 (리스트에서 최근 5개 비교)
        if len(executed_blocks_list) > 5 and all(b == executed_blocks_list[-1] for b in executed_blocks_list[-5:]):
            output_lines.append("[INFO] 동일한 블록이 5번 반복됨. 루프 가능성으로 중단.")
            break

    # 결과 정리
    output_lines.append("\n[INFO] 실행된 블록 주소:")
    for addr in executed_blocks_list:
        output_lines.append(f"  {hex(addr)}")

    # 📁 파일로 저장
    output_path = os.path.join(os.getcwd(), "dynamic_code.txt")
    with open(output_path, "w") as f:
        for line in output_lines:
            f.write(line + "\n")

    return executed_blocks_list





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

    # 🔹 모든 dispatcher 블록 주소 추출
    dispatchers = get_all_dispatchers(main_asmcfg)
    print(f"[INFO] Dispatchers detected: {[hex(d) for d in dispatchers]}")

    # 🔹 전체 블록 중 dispatcher 제외 → 초기 relevant_blocks 생성
    all_blocks = [
        main_asmcfg.loc_db.get_location_offset(block.loc_key)
        for block in main_asmcfg.blocks
    ]
    filtered_blocks = set(all_blocks) - set(dispatchers)

    for dispatcher in dispatchers:
        print(f"[INFO] Removing dispatcher block @ {hex(dispatcher)} from flow")

    # ✅ 추가적인 Flattening 관련 블록 제거 (state_var, switch 등)
    for block in list(filtered_blocks):
        if is_flattening_related_block(block, main_asmcfg):
            print(f"[INFO] Removing additional flattening block @ {hex(block)}")
            filtered_blocks.discard(block)

    relevant_blocks = filtered_blocks  # 최종 유효 블록 집합

    if not relevant_blocks:
        print(f"[ERROR] No relevant blocks found after filtering @ {hex(ad)}")
        return {}, nop_addrs, relevant_blocks, None

    # ✅ 💡 여기에 flattened_edges 정의 추가!
    flattened_edges = extract_flattened_edges(main_asmcfg, main_asmcfg.loc_db)

    # 🔥 정리된 Relevant Blocks 출력
    print(f"[DEBUG] Relevant blocks after filtering:")
    print("[INFO] Cleaned JMP Call Flow (Flattening 제거 후):")
    for src, dst in flattened_edges:
        if dst is not None:
            print(f"  0x{src:X} -> 0x{dst:X}")
        else:
            print(f"  0x{src:X} -> [None]")

    # 🔥 Flattening이 제거된 블록들만 패치 생성
    for addr in relevant_blocks:
        asmcfg = main_asmcfg.getby_offset(addr)
        instrs = [instr for instr in asmcfg.lines]

        link = {'next': '0x0'}  # 임시 next
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
    return patches, nop_addrs, relevant_blocks, dispatcher, flattened_edges



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

    numeric_level = getattr(logging, log_level.upper(), None)
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
            #print(f"[DEBUG] JMP {hex(instr.offset)} -> {jmp_type}")  # 🚀 출력
        except Exception as e:
            print(f"[ERROR] Exception while resolving JMP target @ {hex(instr.offset)}: {e}")

        return False  # 🚨 JMP 명령어는 NOP 처리하지 않음
    
def analyze_static_flow(asmcfg):
    """
    정적 분석을 수행하여 전체 흐름을 출력하고, JMP 명령어가 있을 때 흐름을 저장.
    """
    global jmp_count
    global jmp_targets

    flow_analysis = []
    jmp_call_flow_cleaned = {}

    print("\n[INFO] Starting Static Flow Analysis...\n")

    for blk in asmcfg.blocks:
        blk_offset = asmcfg.loc_db.get_location_offset(blk.loc_key)
        print(f"[DEBUG] Analyzing block @ {hex(blk_offset)}")

        for instr in blk.lines:
            instr_info = f"{hex(instr.offset)}: {instr.name} {', '.join(map(str, instr.args))}"

            if instr.name == "JMP":
                jmp_count += 1
                dsts = []

                for arg in instr.args:
                    try:
                        if isinstance(arg, ExprInt):
                            target_addr = int(arg)
                            dsts.append(f"0x{target_addr:X}")
                            instr_info += f"  --> jmp 0x{target_addr:X}"
                        elif isinstance(arg, ExprId):
                            target_addr = asmcfg.loc_db.get_location_offset(arg.loc_key)
                            dsts.append(f"0x{target_addr:X}")
                            instr_info += f"  --> jmp 0x{target_addr:X}"
                        elif hasattr(arg, "cst"):
                            target_addr = int(arg.cst)
                            dsts.append(f"0x{target_addr:X}")
                            instr_info += f"  --> jmp 0x{target_addr:X}"
                        else:
                            dsts.append(str(arg))
                            instr_info += f"  --> jmp {arg}"
                    except Exception as e:
                        print(f"[ERROR] Failed to resolve JMP target @ {hex(instr.offset)}: {e}")

                jmp_call_flow_cleaned[hex(instr.offset)] = dsts
                jmp_targets.extend(dsts)

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

    return jmp_call_flow_cleaned


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
            #print(f"[DEBUG] JMP {hex(instr.offset)} -> {jmp_type}")  

            # ✅ JMP 흐름을 추적하여 저장
            jmp_flow.append(f"[JMP] {hex(instr.offset)} → {jmp_type}")

            # ✅ JMP 발생 시 dh 시그니처 추가
            #print(f"[INFO] JMP {hex(instr.offset)} encountered. Adding signature: dh")
            jmp_flow.append(f"[JMP] {hex(instr.offset)} → {jmp_type}  [dh]")

        except Exception as e:
            print(f"[ERROR] Failed to resolve JMP target @ {hex(instr.offset)}: {e}")
            target_addr = None  

        return False  

def analyze_conditional_jumps(asmcfg):
    """
    조건 분기 명령어(JZ, JNZ 등)를 분석하여 참/거짓 흐름을 추출한다.
    """
    cond_edges = []
    for block in asmcfg.blocks:
        blk_addr = asmcfg.loc_db.get_location_offset(block.loc_key)
        for instr in block.lines:
            if instr.name.startswith("J") and instr.name not in ["JMP", "JMPQ"]:
                try:
                    true_dst = instr.getdstflow(asmcfg.loc_db)
                    false_dst = block.bto[1] if len(block.bto) > 1 else None

                    true_addr = asmcfg.loc_db.get_location_offset(true_dst.loc_key) if isinstance(true_dst, ExprId) else None
                    false_addr = asmcfg.loc_db.get_location_offset(false_dst) if isinstance(false_dst, LocKey) else None

                    if true_addr is not None:
                        cond_edges.append((blk_addr, true_addr, "T"))  # 참
                    if false_addr is not None:
                        cond_edges.append((blk_addr, false_addr, "F"))  # 거짓

                except Exception as e:
                    print(f"[ERROR] 조건 분기 분석 실패 @ {hex(instr.offset)}: {e}")

    return cond_edges

def save_cfg_visualization(asmcfg, filename="cfg_visualization.dot"):
    save_cfg(asmcfg, filename)
    print(f"[INFO] CFG saved as {filename}")

    
def save_cfg(cfg, filename):
    with open(filename, "w") as f:
        f.write("digraph cfg {\n")
        for block in cfg.blocks:
            src_offset = cfg.loc_db.get_location_offset(block.loc_key)
            for dst in cfg.successors(block):
                dst_offset = cfg.loc_db.get_location_offset(dst.loc_key)
                f.write(f"    \"0x{src_offset:X}\" -> \"0x{dst_offset:X}\";\n")
        f.write("}\n")


def generate_cleaned_dot_from_jmpflow(jmp_call_flow_cleaned, out_dot_path="flattened_cleaned_deflat.dot"):
    with open(out_dot_path, "w") as f:
        f.write("digraph cleaned_cfg_deflat {\n")
        for src, dsts in jmp_call_flow_cleaned.items():
            for dst in dsts:
                if dst:  # dst가 비어있지 않을 경우만
                    f.write(f"    \"{src}\" -> \"{dst}\";\n")
        f.write("}\n")
    print(f"[INFO] Cleaned DOT_deflat 생성 완료: {out_dot_path}")


def write_edges_to_dot(edges, output_file="deflatten_cfg_edges.dot"):
    with open("deflatten_cfg_edges.dot", "w") as f:
        f.write("digraph G {\n")
        for src, dst in edges:
            f.write(f"\"{hex(src)}\" -> \"{hex(dst)}\";\n")
        f.write("}\n")
    print(f"[INFO] Deflattened CFG edges saved to {output_file}")

def write_cleaned_deflatten_dot(edges, dispatcher_addr, output_file="flattened_cleaned_final.dot"):
    with open(output_file, "w") as f:
        f.write("digraph cleaned_flattened_final {\n")
        for src, dst in edges:
            if dst != dispatcher_addr:
                f.write(f"    \"0x{src:X}\" -> \"0x{dst:X}\";\n")
        f.write("}\n")
    print(f"[INFO] Cleaned dispatcher-free CFG DOT 저장 완료: {output_file}")


def remove_dispatcher_edges(graph_dict, dispatcher_addr="0x1E62"):
    new_graph = {}
    for src, dsts in graph_dict.items():
        new_dsts = [dst for dst in dsts if dst != dispatcher_addr]
        if new_dsts:
            new_graph[src] = new_dsts
    return new_graph

def reconstruct_static_flow(graph_dict):
    # 블록 address를 오름차순 정렬
    ordered_nodes = sorted(graph_dict.keys(), key=lambda x: int(x, 16))
    new_edges = {}

    for i in range(len(ordered_nodes)-1):
        cur = ordered_nodes[i]
        nxt = ordered_nodes[i+1]
        if cur not in graph_dict:
            graph_dict[cur] = []
        graph_dict[cur].append(nxt)
    
    return graph_dict


def write_dot_file(graph_dict, output_path):
    with open(output_path, 'w') as f:
        f.write('digraph deobfuscated_cfg {\n')
        for src, dsts in graph_dict.items():
            for dst in dsts:
                f.write(f'    "{src}" -> "{dst}";\n')
        f.write('}\n')
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Input binary file")
    parser.add_argument("patch_filename", help="Output binary file")
    parser.add_argument("--output_dot", default="cfg_visualization.dot", help="Output DOT file name")

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
    
    patches, nop_addrs, relevant_blocks, dispatcher, flattened_edges = deflat(0x1189, (asmcfg, ircfg))

    write_edges_to_dot(flattened_edges, output_file="deflatten_cfg_edges.dot")

    
    
    save_cfg_visualization(asmcfg, filename=args.output_dot)
    
    # 🔥 Flattened Dispatcher → Case 흐름 분석 및 출력
    print("\n[*] Flattened Edges Based on Dispatcher → Case Flow:")
    
    flattened_edges = extract_flattened_edges(asmcfg, loc_db)
    
    if isinstance(dispatcher, list):
        dispatcher_addr = dispatcher[0]
    else:
        dispatcher_addr = dispatcher

    # dispatcher 분기 제거한 흐름을 DOT으로 저장
    write_cleaned_deflatten_dot(flattened_edges, dispatcher_addr)
    
    for src, dst in flattened_edges:
        print(f"  0x{src:X} → 0x{dst:X}")

    # ✅ dispatcher 흐름을 파일로도 저장
    with open("dispatcher_targets.txt", "w") as f:
        for src, dst in flattened_edges:
            f.write(f"0x{src:X} -> 0x{dst:X}\n")

    print("[INFO] Dispatcher 흐름 저장 완료: dispatcher_targets.txt")

    # DOT 파일 저장
    with open("flattened_edges.dot", "w") as f:
        f.write("digraph flattened_cfg {\n")
        for src, dst in flattened_edges:
            f.write(f"    \"0x{src:X}\" -> \"0x{dst:X}\";\n")
        f.write("}\n")

    print("[INFO] Flattened CFG DOT 파일 생성 완료: flattened_edges.dot")

    if relevant_blocks is None:
        relevant_blocks = []

    # ✅ 정적 분석 수행하고 결과 저장
    jmp_call_flow_cleaned = analyze_static_flow(asmcfg)  # 🔥 에러 해결

    print(f"[INFO] Total JMP Instructions: {jmp_count}")
    print(f"[INFO] Relevant Blocks: {sorted(relevant_blocks)}")
    print(f"[INFO] NOP Addresses: {sorted(nop_addrs)}")

    # ✅ Neighboring Blocks도 함께 출력
    # print(f"\n[INFO] Neighboring Blocks (JMP 대상 블록과 연결된 블록):")
    # for blk in relevant_blocks:
    #     print(f"  {hex(blk)} -> {', '.join(neighboring_blocks.get(hex(blk), []))}")

    # ✅ Cleaned JMP Flow를 출력 및 저장
    # print("\n[INFO] Cleaned JMP Call Flow:")
    # for jmp_addr, targets in jmp_call_flow_cleaned.items():
    #     print(f"  {jmp_addr} -> {', '.join(targets)}")

    with open("dh_cleaned_flow.txt", "w") as f:
        f.write("\n[INFO] Cleaned JMP Call Flow (Flattening 제거 후):\n")
        for jmp_addr, targets in jmp_call_flow_cleaned.items():
            f.write(f"  {jmp_addr} -> {', '.join(targets)}\n")

    print("\n[INFO] Cleaned JMP Flow recorded in dh_cleaned_flow.txt")

    # ✅ 동적 분석 수행=========================================================
    input_values = [13, 46, 789]  # 테스트 입력값
    proj = angr.Project(args.filename, auto_load_libs=False)
    main_sym = proj.loader.find_symbol("main")
    main_addr = main_sym.rebased_addr if main_sym else proj.entry

    executed_blocks = dynamic_analysis(args.filename, main_addr, log_level="INFO")


    if executed_blocks:
        print(f"[INFO] Executed blocks from dynamic analysis: {sorted(executed_blocks)}")
    else:
        print("[ERROR] No blocks were executed. The binary might not be properly handled by angr.")

    for block in relevant_blocks:
        if block not in executed_blocks:
            print(f"[DEBUG] Static block not executed dynamically: {block:#x}")

    fpatch.close()
    print("[INFO] Deobfuscation complete.")
    #============================================================================
    
    # 🔥 조건 분기 흐름 추출 및 출력
    print("\n[*] Conditional Jump Flow (JZ/JNZ 등):")
    cond_edges = analyze_conditional_jumps(asmcfg)
    for src, dst, cond in cond_edges:
        print(f"  0x{src:X} --[{cond}]--> 0x{dst:X}")

    # DOT 저장
    with open("conditional_edges.dot", "w") as f:
        f.write("digraph conditional_flow {\n")
        for src, dst, cond in cond_edges:
            color = "green" if cond == "T" else "red"
            f.write(f'    "0x{src:X}" -> "0x{dst:X}" [label="{cond}", color={color}];\n')
        f.write("}\n")
    print("[INFO] Conditional CFG DOT 파일 생성 완료: conditional_edges.dot")
    
    
    with open("flattened_cleaned.dot", "w") as f:
        f.write("digraph cleaned_jmp_flow {\n")
        for src, dst in flattened_edges:
            if dst is not None:
                f.write(f"    \"0x{src:X}\" -> \"0x{dst:X}\";\n")
            else:
                f.write(f"    \"0x{src:X}\" -> \"None\";\n")
        f.write("}\n")

    print("[INFO] Cleaned JMP DOT 파일 생성 완료: flattened_cleaned.dot")
    
    print("[DEBUG_dh1] generate_cleaned_dot_from_jmpflow 호출됨")
    print(f"[DEBUG_dh2] jmp_call_flow_cleaned 크기: {len(jmp_call_flow_cleaned)}")
    for src, dsts in jmp_call_flow_cleaned.items():
        print(f"[DEBUG_Dh3] {src} -> {dsts}")
    
    generate_cleaned_dot_from_jmpflow(jmp_call_flow_cleaned)
    
    edge_dict = {}
    for src, dst in flattened_edges:
        src_hex = f"0x{src:X}"
        dst_hex = f"0x{dst:X}"
        if src_hex not in edge_dict:
            edge_dict[src_hex] = []
        edge_dict[src_hex].append(dst_hex)

    # ✅ 2. dispatcher 제거
    cleaned_graph = remove_dispatcher_edges(edge_dict, dispatcher_addr=f"0x{dispatcher_addr:X}")

    # ✅ 3. 정적 순서 기반 재구성
    static_reconstructed_graph = reconstruct_static_flow(cleaned_graph)

    # ✅ 4. 최종 DOT 저장
    write_dot_file(static_reconstructed_graph, output_path="deobfuscated_cfg_static.dot")

    print("[INFO] Dispatcher 제거 + 정적 순서 기반 CFG DOT 저장 완료: deobfuscated_cfg_static.dot")
    
    

    

