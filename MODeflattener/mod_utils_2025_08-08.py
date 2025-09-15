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
from miasm.expression.expression import ExprInt


import logging

_log = logging.getLogger('modeflattener')

asmb = lambda patch_str, loc_db: mn_x86.asm(mn_x86.fromstring(patch_str, loc_db, 32))[0]
rel = lambda addr, patch_addr: hex(addr - patch_addr)


def remove_dummy_jmps(block_or_cfg):
    patches = []

    # CFG인 경우
    if hasattr(block_or_cfg, 'blocks'):
        blocks = block_or_cfg.blocks
    else:
        blocks = [block_or_cfg]

    for block in blocks:
        for instr in block.lines:
            if instr.name == "jmp" and len(instr.args) == 1:
                arg = instr.args[0]
                if isinstance(arg, ExprInt) and arg.arg == instr.offset + instr.l:
                    print(f"[INFO] Found dummy jmp at {hex(instr.offset)} -> removing")
                    patches.append(PatchNop(instr.offset, instr.l))

    return patches


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

def get_cff_info(main_asmcfg, dispatcher):
    print(f"[DEBUG] 내가 넘긴 dispatcher = {hex(dispatcher)}")

    pre_dispatcher = None
    
    print("[DEBUG] Miasm CFG 내 블럭 offset 목록:")
    for block in main_asmcfg.blocks:
        offset = main_asmcfg.loc_db.get_location_offset(block.loc_key)
        print(f"    → 0x{offset:x}")
        offset = main_asmcfg.loc_db.get_location_offset(block.loc_key)
        for instr in block.lines:
            if instr.name.lower() in ['jmp', 'jz', 'je', 'jne', 'jnz'] and instr.args:
                dst_expr = instr.args[0]

                dst_addr = None
                if isinstance(dst_expr, ExprInt):
                    dst_addr = dst_expr.arg
                elif isinstance(dst_expr, ExprLoc):
                    dst_addr = main_asmcfg.loc_db.get_location_offset(dst_expr.loc_key)

                if dst_addr == dispatcher:
                    pre_dispatcher = instr.offset
                    print(f"[DEBUG] ✅ Found pre_dispatcher at: {hex(pre_dispatcher)}")
                    break
        if pre_dispatcher is not None:
            break

    if pre_dispatcher is None:
        raise ValueError(f"[ERROR] No predecessors found for dispatcher at {hex(dispatcher)}")

    # ✅ 직접 설정한 relevant_blocks 먼저 정의
    from mod_user_defined import state_to_target  # 수동 정의된 딕셔너리
    relevant_blocks = list(state_to_target.values())

    print(f"[DEBUG] ✅ Using manually extracted {len(relevant_blocks)} relevant blocks.")
    for rb in relevant_blocks:
        print(f"         → 0x{rb:x}")
    
    # 실제 CFG에 존재하는 블록만 필터링
    filtered_relevant_blocks = []
    for addr in relevant_blocks:
        block = main_asmcfg.getby_offset(addr)
        if block is not None:
            filtered_relevant_blocks.append(addr)
        else:
            print(f"[WARN] 블럭 없음 → 0x{addr:x}")

    relevant_blocks = filtered_relevant_blocks

    return relevant_blocks, dispatcher, pre_dispatcher



def extract_relevant_blocks(dispatcher_block, asmcfg):
    visited = set()
    worklist = [dispatcher_block]
    relevant_blocks = set()

    while worklist:
        block = worklist.pop()
        if block in visited:
            continue
        visited.add(block)
        relevant_blocks.add(asmcfg.loc_db.get_location_offset(block.loc_key))

        if not block.lines:
            continue

        last_instr = block.lines[-1]
        if last_instr.name.lower().startswith("j"):  # jmp, je, jne, jz, etc
            for arg in last_instr.args:
                if isinstance(arg, ExprLoc):
                    try:
                        target_offset = asmcfg.loc_db.get_location_offset(arg.loc_key)
                        target_block = asmcfg.getby_offset(target_offset)

                        if target_block:
                            worklist.append(target_block)
                    except Exception as e:
                        print(f"[WARN] Failed to get block at loc_key={arg.loc_key}: {e}")

    return relevant_blocks



def check_block_for_state_store(block):
    for instr in block.lines:
        print(f"  [DEBUG] Instr: {instr}")
        if instr.name == "mov" and len(instr.args) == 2:
            dst, src = instr.args
            if isinstance(dst, ExprMem) and isinstance(dst.arg, ExprOp) and \
                dst.arg.op == "+" and isinstance(dst.arg.args[0], ExprId) and dst.arg.args[0].name == "RBP" and \
                isinstance(dst.arg.args[1], ExprInt):

                offset_val = dst.arg.args[1].arg
                if offset_val >= (1 << 63):
                    offset_val -= (1 << 64)

                if offset_val == -4 and isinstance(src, (ExprInt, ExprId)):
                    print(f"  ✅ Found state store at offset -4")
                    return True
    return False


# do backwards search for jmp instruction to find start of relevant block
def get_block_father(asmcfg, blk_offset):
    blk = asmcfg.getby_offset(blk_offset)
    checklist = [blk.loc_key]

    pred = asmcfg.predecessors(blk.loc_key)[0]
    while True:
        curr_bloc = asmcfg.loc_key_to_block(pred)
        if curr_bloc.lines[-1].name in ['JZ', 'JMP', 'JNZ']:
            break
        checklist.append(pred)
        pred = asmcfg.predecessors(curr_bloc.loc_key)[0]

    return asmcfg.loc_db.get_location_offset(checklist[-1])


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

def get_state_target_map():
    return {
        0x7f1:   0x1265,
        0xaa5:   0x1270,
        0x1859:  0x1290,
        0x1113:  0x12a3,
        0x19a5:  0x12c0,
        0x1f1e:  0x12d0,
        0x2c1f:  0x12f0,
        0x1c0d:  0x1307,
        0x11ed:  0x1322,
        0x1e43:  0x1337,
        0x14e4:  0x134c,
        0x16e0:  0x135f,
        0x195a:  0x136b,
        0x112a:  0x1384,
        0x18ed:  0x13a2,
        0x15a0:  0x13b5,
        0x1b8f:  0x13c8,
        0x131a:  0x13d4,
        0x1a32:  0x11b2,
        0x10f7:  0x11c4,
        0x1f2a:  0x11dd,
        0x1a63:  0x11f6,
        0x10c1:  0x121b,
        0x1d3d:  0x120f,
        0x1f9a:  0x1234,
        0x1f87:  0x1240,
        0x17198: 0x1259,
        0x1f44:  0x128a,
        0x162fd: 0x129d,
        0xf1ec:  0x12dc,
    }

def get_next_state(curr_state):
    next_map = {
        1: 2,
        2: 3,
        3: 4,
        4: 5,
        5: 6,
        6: 7,
        7: 8,
    }
    return next_map.get(curr_state, None)


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
                elif fisinstance(src, ExprSlice):
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