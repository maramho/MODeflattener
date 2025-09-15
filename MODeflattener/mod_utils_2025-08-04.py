from miasm.arch.x86.arch import mn_x86
from future.utils import viewitems, viewvalues
from miasm.core.utils import encode_hex
from miasm.core.graph import DiGraph
from miasm.ir.ir import *
from miasm.expression.expression import *
from miasm.analysis.ssa import get_phi_sources_parent_block, \
    irblock_has_phi
from miasm.analysis.data_flow import ReachingDefinitions,\
    DiGraphDefUse

import logging

_log = logging.getLogger('modeflattener')

asmb = lambda patch_str, loc_db: mn_x86.asm(mn_x86.fromstring(patch_str, loc_db, 32))[0]
rel = lambda addr, patch_addr: hex(addr - patch_addr)


def save_cfg(cfg, name):
    import subprocess
    open(name, 'w').write(cfg.dot())
    subprocess.call(["dot", "-Tpng", name, "-o", name.split('.')[0]+'.png'])
    subprocess.call(["rm", name])


def patch_gen(instrs, loc_db, nop_addrs, link):
    final_patch = b""
    start_addr = instrs[0].offset

    for instr in instrs:
        #omitting useless instructions
        if instr.offset not in nop_addrs:
            if instr.is_subcall():
                #generate asm for fixed calls with relative addrs
                patch_addr = start_addr + len(final_patch)
                tgt = loc_db.get_location_offset(instr.args[0].loc_key)
                _log.info("CALL %#x" % tgt)
                call_patch_str = "CALL %s" % rel(tgt, patch_addr)
                _log.debug("call patch : %s" % call_patch_str)
                call_patch = asmb(call_patch_str, loc_db)
                final_patch += call_patch
                _log.debug("call patch asmb : %s" % encode_hex(call_patch))
            else:
                #add the original bytes
                final_patch += instr.b

    patch_addr = start_addr + len(final_patch)
    _log.debug("jmps patch_addr : %#x", patch_addr)
    jmp_patches = b""
    # cleaning the control flow by patching with real jmps locs
    if 'cond' in link:
        t_addr = int(link['true_next'], 16)
        f_addr = int(link['false_next'], 16)
        jcc = link['cond'].replace('CMOV', 'J')
        _log.info("%s %#x" % (jcc, t_addr))
        _log.info("JMP %#x" % f_addr)

        patch1_str = "%s %s" % (jcc, rel(t_addr, patch_addr))
        jmp_patches += asmb(patch1_str, loc_db)
        patch_addr += len(jmp_patches)

        patch2_str = "JMP %s" % (rel(f_addr, patch_addr))
        jmp_patches += asmb(patch2_str, loc_db)
        _log.debug("jmp patches : %s; %s" % (patch1_str, patch2_str))

    else:
        n_addr = int(link['next'], 16)
        _log.info("JMP %#x" % n_addr)

        patch_str = "JMP %s" % rel(n_addr, patch_addr)
        jmp_patches = asmb(patch_str, loc_db)

        _log.debug("jmp patches : %s" % patch_str)

    _log.debug("jmp patches asmb : %s" % encode_hex(jmp_patches))
    final_patch += jmp_patches

    return final_patch


def get_cff_info(asmcfg):
    preds = {}
    relevant_blocks = []
    for blk in asmcfg.blocks:
        offset = asmcfg.loc_db.get_location_offset(blk.loc_key)
        preds[offset] = asmcfg.predecessors(blk.loc_key)
    pre_dispatcher = sorted(preds, key=lambda key: len(preds[key]), reverse=True)[0]
    dispatcher = asmcfg.successors(asmcfg.loc_db.get_offset_location(pre_dispatcher))[0]
    dispatcher = asmcfg.loc_db.get_location_offset(dispatcher)

    for loc in preds[pre_dispatcher]:
        offset = asmcfg.loc_db.get_location_offset(loc)
        father = get_block_father(asmcfg, offset)
        if father is not None:
            relevant_blocks.append(father)

    return relevant_blocks, dispatcher, pre_dispatcher


# do backwards search for jmp instruction to find start of relevant block
def get_block_father(asmcfg, blk_offset):
    print(f"[DEBUG] Processing block @ {hex(blk_offset)}")
    blk = asmcfg.getby_offset(blk_offset)
    checklist = [blk.loc_key]

    try:
        pred = asmcfg.predecessors(blk.loc_key)[0]
    except IndexError:
        print(f"[ERROR] No predecessors found for block at offset: {hex(blk_offset)}")
        # 이전 블록을 강제로 추적
        print(f"[INFO] Attempting to explore neighboring blocks for {hex(blk_offset)}")
        neighbors = [
            asmcfg.loc_db.get_location_offset(pred.loc_key)
            for pred in asmcfg.blocks if pred.loc_key != blk.loc_key
        ]
        print(f"[DEBUG] Neighboring blocks: {neighbors}")
        return neighbors[0] if neighbors else None

    while pred is not None:
        curr_bloc = asmcfg.loc_key_to_block(pred)
        if curr_bloc.lines[-1].name in ['JZ', 'JMP', 'JNZ']:
            break
        checklist.append(pred)
        try:
            pred = asmcfg.predecessors(curr_bloc.loc_key)[0]
        except IndexError:
            curr_offset = asmcfg.loc_db.get_location_offset(curr_bloc.loc_key)
            print(f"[ERROR] No further predecessors for block at offset: {hex(curr_offset)}")
            break

    return asmcfg.loc_db.get_location_offset(checklist[-1]) if checklist else None

def get_phi_vars(ircfg):
    res = []
    blks = list(ircfg.blocks)
    irblock = (ircfg.blocks[blks[-1]])

    if irblock_has_phi(irblock):
        for dst, sources in viewitems(irblock[0]):
            phi_vars = sources.args
            parent_blks = get_phi_sources_parent_block(
                ircfg,
                irblock.loc_key,
                phi_vars
            )

    for var, loc in parent_blks.items():
        irblock = ircfg.get_block(list(loc)[0])
        for asg in irblock:
            dst, src = asg.items()[0]
            if dst == var:
                res += [int(src)]

    return res


def find_var_asg(ircfg, var):
    val_list = []
    res = {}
    for lbl, irblock in viewitems(ircfg.blocks):
        for assignblk in irblock:
            result = set(assignblk).intersection(var)
            if not result:
                continue
            else:
                dst, src = assignblk.items()[0]
                if isinstance(src, ExprInt):
                    res['next'] = int(src)
                    val_list += [int(src)]
                elif isinstance(src, ExprSlice):
                    phi_vals = get_phi_vars(ircfg)
                    res['true_next'] = phi_vals[0]
                    res['false_next'] = phi_vals[1]
                    val_list += phi_vals
    return res, val_list


def find_state_var_usedefs(ircfg, search_var):
    var_addrs = set()
    reachings = ReachingDefinitions(ircfg)
    digraph = DiGraphDefUse(reachings)
    # the state var always a leaf
    for leaf in digraph.leaves():
        if leaf.var == search_var:
            for x in (digraph.reachable_parents(leaf)):
                var_addrs.add(ircfg.get_block(x.label)[x.index].instr.offset)
    return var_addrs

def trace_unknown_target(instr, loc_db):
    """
    Trace unknown JMP targets for additional insights.
    """
    try:
        target = instr.getdstflow(loc_db)
        if isinstance(target, ExprId):
            target_addr = loc_db.get_location_offset(target.loc_key)
            print(f"[DEBUG] Resolved target for JMP @ {hex(instr.offset)} -> {hex(target_addr)}")
        else:
            print(f"[DEBUG] Cannot resolve direct target for JMP @ {hex(instr.offset)}. Operand: {target}")
    except Exception as e:
        print(f"[ERROR] Exception while resolving JMP target @ {hex(instr.offset)}: {e}")


        
        
def save_nop_graph(nop_addrs, relevant_blocks, output_file="nop_graph.dot", dispatcher_block=None):
    from graphviz import Digraph

    dot = Digraph(comment="NOP Instruction Flow")
    
    if not nop_addrs:
        print("[WARNING] No NOP addresses found. Skipping NOP graph generation.")
        return  # ⬅️ NOP이 없으면 함수 종료

    for addr in sorted(nop_addrs):
        dot.node(f"{addr:#x}", f"NOP @ {addr:#x}")

    for blk in sorted(relevant_blocks):
        if blk in nop_addrs:
            dot.edge(f"{blk:#x}", f"{blk:#x}", label="Relevant Block")
    
    if dispatcher_block:
        dot.node(f"{dispatcher_block:#x}", "Dispatcher Block", shape="doublecircle")

        # 🚨 NOP 주소가 있을 때만 엣지 추가
        if nop_addrs:
            dot.edge(f"{dispatcher_block:#x}", f"{sorted(nop_addrs)[0]:#x}", label="Start")

    dot.render(output_file, format="png")
    print(f"[INFO] NOP 그래프가 {output_file}.png로 저장되었습니다.")

    
    
    
def save_execution_graph(executed_blocks, nop_blocks, output_file="execution_graph.dot"):
    """
    Save a graph showing executed blocks and NOP blocks.
    :param executed_blocks: Set of executed block addresses.
    :param nop_blocks: Set of NOP addresses.
    """
    from graphviz import Digraph

    dot = Digraph(comment="Execution Flow Graph")
    for block in executed_blocks:
        dot.node(f"{block:#x}", f"Executed @ {block:#x}", color="green")

    for nop in nop_blocks:
        if nop not in executed_blocks:
            dot.node(f"{nop:#x}", f"NOP @ {nop:#x}", color="red")

    for src, dst in zip(sorted(executed_blocks), sorted(executed_blocks)[1:]):
        dot.edge(f"{src:#x}", f"{dst:#x}", label="Executed Flow")

    dot.render(output_file, format="png")
    print(f"[INFO] Execution graph saved to {output_file}.png")
    
# ====== ADD  DH  ====== 
def is_dispatcher(block):
    """
    반복 flattening 패턴에 대응하기 위한 dispatcher 탐지
    jmp가 존재하고, 그 외에 연산이 거의 없는 블록을 dispatcher로 간주
    """
    jmp_count = 0
    other_count = 0
    for instr in block.lines:
        if instr.name.lower() in ["jmp", "je", "jne", "jg", "jl", "ja", "jb", "jz", "jnz"]:
            jmp_count += 1
        else:
            other_count += 1
    return jmp_count >= 1 and other_count <= 2  # jmp만 있거나 1~2개 이내이면 dispatcher 후보



def get_branch_targets(block, loc_db):
    """
    dispatcher 블럭에서 cmp/jmp 기반 분기 타겟 주소 추출
    """
    targets = []
    for instr in block.lines:
        if instr.name.lower().startswith("j"):  # 모든 분기 명령어
            print(f"[DEBUG] JMP instr: {instr.name}, args: {instr.args}")
            if len(instr.args) >= 1:
                dst_expr = instr.args[0]
                try:
                    # ExprLoc일 경우 내부 loc_key 추출
                    if isinstance(dst_expr, ExprLoc):
                        loc_key = dst_expr.loc_key
                        dst_offset = loc_db.get_location_offset(loc_key)
                        targets.append(dst_offset)
                        print(f"    [+] JMP target → 0x{dst_offset:x}")
                    else:
                        print(f"[WARN] Unknown jump target expr type: {dst_expr}")
                except Exception as e:
                    print(f"[WARN] Failed to resolve target: {dst_expr} → {e}")
                    continue
    return targets




def extract_flattened_edges(cfg, loc_db):
    print("[*] Flattened Edges Based on Dispatcher → Case Flow:")
    print("[DEBUG] CFG 블록 목록:")
    edges = []
    for block in cfg.blocks:
        try:
            addr = loc_db.get_location_offset(block.loc_key)
            print(f"[DEBUG] Inspecting block: 0x{addr:x} with {len(block.lines)} instructions")
        except Exception as e:
            print(f"[ERROR] Failed to get block address: {e}")
            continue

        if is_dispatcher(block):
            print(f"[MATCH] Dispatcher detected at 0x{addr:x}")
            switch_targets = get_branch_targets(block, loc_db)
            print(f"  ↳ Extracted {len(switch_targets)} targets: {switch_targets}")
            for tgt in switch_targets:
                print(f"    [+] Edge added: 0x{addr:x} -> 0x{tgt:x}")
                edges.append((addr, tgt))
        else:
            print(f"[SKIP] Block 0x{addr:x} is not a dispatcher")
    print(f"[*] Total extracted flattened edges: {len(edges)}")
    return edges


def get_switch_targets(block):
    """
    분기 블럭에서 jmp/jcc 타겟을 추출 (현재 dispatcher 추정 블럭에서)
    """
    targets = []
    for instr in block.lines:
        if instr.name.lower().startswith("j") and instr.args:
            try:
                target = instr.args[0]
                if hasattr(target, 'offset'):
                    targets.append(target.offset)
                elif hasattr(target, 'value'):
                    targets.append(target.value)
            except:
                continue
    return targets

def extract_conditional_edges(cfg, loc_db):
    """
    조건 분기(jz, jnz 등)에 기반하여 flattened 분기 흐름을 추출
    """
    edges = []
    print("[*] 조건 분기 기반 흐름 추출 시작")

    for block in cfg.blocks:
        addr = loc_db.get_location_offset(block.loc_key)
        if not block.lines:
            continue

        last_instr = block.lines[-1]
        mnemonic = last_instr.name.lower()

        if mnemonic in ["jz", "jnz", "je", "jne", "ja", "jb", "jg", "jl"]:
            print(f"[COND] 조건 분기 블록 탐지: 0x{addr:x} → {mnemonic}")

            true_target = None
            try:
                dst_expr = last_instr.args[0]
                if isinstance(dst_expr, ExprLoc):
                    loc_key = dst_expr.loc_key
                    true_target = loc_db.get_location_offset(loc_key)
            except Exception as e:
                print(f"[WARN] 분기 대상 추출 실패: {e}")

            # 조건이 참일 때 이동하는 타겟
            if true_target:
                edges.append((addr, true_target))
                print(f"  ↳ [True] 0x{addr:x} -> 0x{true_target:x}")

            # 조건이 거짓일 때는 다음 sequential block
            try:
                successors = cfg.successors(block.loc_key)
                for succ_key in successors:
                    succ_addr = loc_db.get_location_offset(succ_key)
                    if succ_addr != true_target:
                        edges.append((addr, succ_addr))
                        print(f"  ↳ [False] 0x{addr:x} -> 0x{succ_addr:x}")
            except Exception as e:
                print(f"[WARN] False 경로 추출 실패: {e}")

    print(f"[*] 총 조건 분기 엣지: {len(edges)}개")
    return edges

def get_all_dispatchers(asmcfg):
    """
    반복 flattening 구조에서 dispatcher 후보들을 모두 탐색
    """
    dispatcher_addrs = []
    for block in asmcfg.blocks:
        if is_dispatcher(block):  # 기존에 작성한 dispatcher 판별 함수
            addr = asmcfg.loc_db.get_location_offset(block.loc_key)
            dispatcher_addrs.append(addr)
    return dispatcher_addrs

