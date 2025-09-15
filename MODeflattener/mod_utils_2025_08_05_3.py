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

    for block in main_asmcfg.blocks:
        offset = main_asmcfg.loc_db.get_location_offset(block.loc_key)
        print(f"[DEBUG] Block offset: {hex(offset)}")
        for instr in block.lines:
            print(f"  [DEBUG] Instr: {instr.name} at {hex(instr.offset)}")
            if instr.name == "jmp":
                print(f"    [DEBUG] JMP instr args: {instr.args}")
                if instr.args and isinstance(instr.args[0], ExprInt):
                    print(f"    [DEBUG] JMP target: {hex(instr.args[0].arg)}")


                
    print(f"[DEBUG] total blocks = {len(main_asmcfg.blocks)}")
    
    print(f"[DEBUG] type(main_asmcfg.blocks) = {type(main_asmcfg.blocks)}")

    pre_dispatcher = None

    for block in main_asmcfg.blocks:
        offset = main_asmcfg.loc_db.get_location_offset(block.loc_key)
        for instr in block.lines:
            print(f"[DEBUG] Checking instr: {instr.name} at {hex(instr.offset)}")
            if instr.args:
                print(f"         args[0]: {instr.args[0]} (type: {type(instr.args[0])})")

            if instr.name.lower() in ['jmp', 'jz', 'je', 'jne', 'jnz'] and instr.args:
                dst_expr = instr.args[0]

                # Dispatcher 주소로 가는 다양한 표현 대응
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

    # ✅ dispatcher 이후 분기 블럭 수집
    dispatcher_blk = main_asmcfg.getby_offset(dispatcher)
    successors = list(main_asmcfg.successors(dispatcher_blk.loc_key))
    
    print(f"[DEBUG] dispatcher successor count = {len(successors)}")

    if not successors:
        raise ValueError(f"[ERROR] No successors found for dispatcher at {hex(dispatcher)}")

    relevant_blocks = []

    print(f"[DEBUG] dispatcher successor count = {len(successors)}")
    for s in successors:
        s_offset = main_asmcfg.loc_db.get_location_offset(s)
        print(f"[DEBUG] before successor loc_key = {s}, offset = {hex(s_offset)}")
        target_block = main_asmcfg.getby_offset(s_offset)
        
        # 🎯 1-hop 검사
        print(f"\n[DEBUG] 1-hop Successor block at 0x{s_offset:x}")
        found = check_block_for_state_store(target_block)
        if found:
            relevant_blocks.append(s_offset)
            continue  # 중복 방지

        # 🎯 2-hop successors 검사
        nested_successors = list(main_asmcfg.successors(target_block.loc_key))
        for ns in nested_successors:
            ns_offset = main_asmcfg.loc_db.get_location_offset(ns)
            print(f"[DEBUG]    2-hop successor block at 0x{ns_offset:x}")
            nested_block = main_asmcfg.getby_offset(ns_offset)
            found_nested = check_block_for_state_store(nested_block)
            if found_nested:
                relevant_blocks.append(ns_offset)
                break  # 중복 방지
        if found:
            relevant_blocks.append(s_offset)

    return relevant_blocks, dispatcher, pre_dispatcher

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