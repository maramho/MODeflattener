import angr
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from argparse import ArgumentParser
from miasm.expression.expression import ExprLoc, LocKey


def symbolic_dispatcher_execution(binary_path, dispatcher_addr, state_var_offset):
    proj = angr.Project(binary_path, auto_load_libs=False)
    state = proj.factory.blank_state(addr=dispatcher_addr)

    # 상태 변수를 심볼릭 변수로 설정
    state_var = state.solver.BVS("state_var", 32)
    state.memory.store(state_var_offset, state_var)

    simgr = proj.factory.simgr(state)
    simgr.explore(find=lambda s: s.addr == dispatcher_addr + 0x20)  # 디스패처 종료 주소 예시

    if len(simgr.found) == 0:
        print("[ERROR] No valid paths found in dispatcher execution.")
        return {}

    found_state = simgr.found[0]
    branch_targets = {}
    for state_value in range(256):  # 상태 값 탐색
        constraint = state_var == state_value
        if found_state.solver.satisfiable(extra_constraints=[constraint]):
            try:
                target = found_state.solver.eval(found_state.regs.ip)
                branch_targets[state_value] = target
                print(f"[DEBUG] State {state_value}: JMP -> {hex(target)}")
            except Exception as e:
                print(f"[ERROR] State {state_value}: Exception - {e}")
        else:
            print(f"[DEBUG] State {state_value}: No valid path found")

    return branch_targets


def analyze_call_target(binary_path, target_addr):
    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    func = cfg.kb.functions[target_addr]

    print(f"[INFO] Analyzing function at {hex(target_addr)}")
    for block in func.blocks:
        print(f"[DEBUG] Block at {hex(block.addr)}:")
        for instr in block.capstone.insns:
            print(f"  {instr.mnemonic} {instr.op_str}")


def analyze_dispatcher_with_miasm(binary_path, dispatcher_addr, initial_state):
    from miasm.analysis.binary import Container
    from miasm.analysis.machine import Machine
    from miasm.expression.expression import ExprLoc
    from miasm.core.locationdb import LocationDB

    # Initialize LocationDB and load the binary
    loc_db = LocationDB()
    container = Container.from_stream(open(binary_path, "rb"), loc_db)
    machine = Machine(container.arch)
    dis_engine = machine.dis_engine(container.bin_stream, loc_db=loc_db)

    # Disassemble the dispatcher block
    dispatcher_block = dis_engine.dis_block(dispatcher_addr)
    print(f"[INFO] Disassembled dispatcher block at {hex(dispatcher_addr)}")

    # Add depth=0 to the analyze_block call
    analyze_block(container, dis_engine, dispatcher_block, [], [], initial_state, depth=0)
    


def analyze_block(container, dis_engine, block, call_flow, path, visited, state, dispatcher_addr, depth):
    try:
        if block.lines and hasattr(block.lines[0], "offset"):
            block_offset = block.lines[0].offset
        else:
            print("[WARNING] Block does not have a valid offset.")
            return

        if block_offset in visited:
            print(f"[INFO] Skipping already visited block: {hex(block_offset)}")
            return

        # 깊이 제한 추가
        if depth > 10:
            print(f"[WARNING] Depth limit reached at block {hex(block_offset)}, stopping further analysis.")
            return

        print(f"[INFO] Analyzing block at {hex(block_offset)}, Path: {path}, State: {state}, Depth: {depth}")
        path.append(block_offset)
        visited.add(block_offset)

        for instr in block.lines:
            if hasattr(instr, "name"):
                operands = ", ".join(map(str, instr.args)) if instr.args else "No operands"
                print(f"[DEBUG] Instruction: {instr.name}, Operands: {operands}")

                # Detect jump back to dispatcher
                if instr.name in ["CALL", "JMP"]:
                    target = instr.args[0]
                    if isinstance(target, ExprLoc):
                        target_addr = target.loc_key.key if isinstance(target.loc_key.key, int) else int(target.loc_key.key, 16)
                        if target_addr == dispatcher_addr:
                            print(f"[INFO] Detected loop back to Dispatcher at {hex(dispatcher_addr)} from {hex(block_offset)}")

                # Handle branch instructions
                if instr.name in ["JLE", "JMP", "JE", "JNE", "CALL"]:
                    target = instr.args[0]
                    if isinstance(target, ExprLoc):
                        analyze_target_location(container, dis_engine, target.loc_key, call_flow, path, visited, state, dispatcher_addr, depth + 1)

    except Exception as e:
        print(f"[ERROR] Failed to analyze block at {hex(block.offset)}: {e}")
        fallback_analysis(container, dis_engine, block.offset, call_flow, path, visited, state, dispatcher_addr, depth)
    finally:
        if path:
            path.pop()

def analyze_target_location(container, dis_engine, loc_key, call_flow, path, visited, state, depth):
    try:
        if isinstance(loc_key, LocKey):
            target_addr = loc_key.key if isinstance(loc_key.key, int) else int(loc_key.key, 16)
            print(f"[INFO] Resolved target address: {hex(target_addr)}")

            if target_addr in visited:  # 이미 방문한 주소인지 확인
                print(f"[INFO] Already visited block {hex(target_addr)}, skipping...")
                return

            # 새로운 블록 분석
            try:
                target_block = dis_engine.dis_block(target_addr)
                analyze_block(container, dis_engine, target_block, call_flow, path, visited, state, dispatcher_addr, depth)
            except Exception as e:
                print(f"[WARNING] Failed to disassemble block at {hex(target_addr)}: {e}")
                if "cannot disasm" in str(e):
                    print("[INFO] Attempting fallback analysis for block.")
                    fallback_analysis(container, dis_engine, target_addr, call_flow, path, visited, state, dispatcher_addr, depth + 1)

    except Exception as e:
        print(f"[ERROR] Failed to analyze target location {loc_key}: {e}")

def analyze_target_location(container, dis_engine, loc_key, call_flow, path, visited, state, dispatcher_addr, depth):
    try:
        if isinstance(loc_key, LocKey):
            target_addr = loc_key.key if isinstance(loc_key.key, int) else int(loc_key.key, 16)
            print(f"[DEBUG] Attempting to analyze target location: {hex(target_addr)}")

            if target_addr in visited:
                print(f"[INFO] Already visited block: {hex(target_addr)}")
                return

            target_block = dis_engine.dis_block(target_addr)
            analyze_block(container, dis_engine, target_block, call_flow, path, visited, state, dispatcher_addr, depth)
    except Exception as e:
        print(f"[ERROR] Failed to analyze target location {loc_key}: {e}")
        fallback_analysis(container, dis_engine, target_addr, call_flow, path, visited, state, dispatcher_addr, depth)
        

def fallback_analysis(container, dis_engine, target_addr, call_flow, path, visited, state, dispatcher_addr, depth):
    print(f"[INFO] Fallback analysis for block at {hex(target_addr)}, Depth: {depth}")

    if target_addr in visited:
        print(f"[INFO] Skipping already visited block during fallback: {hex(target_addr)}")
        return

    try:
        block = dis_engine.dis_block(target_addr)
        print(f"[INFO] Successfully disassembled block during fallback at {hex(target_addr)}")
        analyze_block(container, dis_engine, block, call_flow, path, visited, state, dispatcher_addr, depth)
        return
    except Exception as e:
        print(f"[WARNING] Disassembly failed during fallback: {e}")

    # Explore next possible addresses
    for offset in range(16, 64, 16):  # 16바이트 간격으로 시도
        next_possible_addr = target_addr + offset
        print(f"[INFO] Exploring next possible block at {hex(next_possible_addr)}...")
        try:
            analyze_target_location(container, dis_engine, LocKey(next_possible_addr), call_flow, path, visited, state, dispatcher_addr, depth + 1)
        except Exception as e:
            print(f"[ERROR] Exploration of block at {hex(next_possible_addr)} failed: {e}")
            
    for offset in range(16, 64, 16):  # 16~64 바이트 범위 탐색
        next_possible_addr = target_addr + offset
        print(f"[INFO] Exploring next possible block at {hex(next_possible_addr)}...")
        try:
            analyze_target_location(
                container, dis_engine, LocKey(next_possible_addr),
                call_flow, path, visited, state, dispatcher_addr, depth + 1
            )
        except Exception as e:
            print(f"[ERROR] Exploration of block at {hex(next_possible_addr)} failed: {e}")

def analyze_dispatcher_with_miasm(binary_path, dispatcher_addr, initial_state):
    loc_db = LocationDB()
    container = Container.from_stream(open(binary_path, "rb"), loc_db)
    machine = Machine(container.arch)
    dis_engine = machine.dis_engine(container.bin_stream, loc_db=loc_db)

    # Visited 초기화
    visited = set()

    # Disassemble the dispatcher block
    dispatcher_block = dis_engine.dis_block(dispatcher_addr)
    print(f"[INFO] Disassembled dispatcher block at {hex(dispatcher_addr)}")

    analyze_block(container, dis_engine, dispatcher_block, [], [], visited, initial_state, dispatcher_addr, depth=0)


def main():
    parser = ArgumentParser("dispatcher_analysis")
    parser.add_argument("binary", help="Path to the binary file.")
    parser.add_argument("dispatcher_addr", type=lambda x: int(x, 0), help="Address of the dispatcher block.")
    parser.add_argument("state_var_offset", type=lambda x: int(x, 0), help="Offset of the state variable in memory.")

    args = parser.parse_args()

    initial_state = {}

    # Dispatcher 주소 전달
    analyze_dispatcher_with_miasm(args.binary, args.dispatcher_addr, initial_state)


if __name__ == "__main__":
    main()