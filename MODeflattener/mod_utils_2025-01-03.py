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
    for blk in asmcfg.blocks:
        if isinstance(blk, LocKey):
            blk_offset = asmcfg.loc_db.get_location_offset(blk)
            print(f"[DEBUG] Relevant block offset: {hex(blk_offset)}")
        else:
            blk_offset = blk.lines[0].offset  # AsmBlock의 첫 번째 라인의 오프셋을 사용
            print(f"[DEBUG] Relevant block offset: {hex(blk_offset)}")

        offset = asmcfg.loc_db.get_location_offset(blk.loc_key)
        preds[offset] = asmcfg.predecessors(blk.loc_key)

    try:
        pre_dispatcher = sorted(preds, key=lambda key: len(preds[key]), reverse=True)[0]
        print(f"[DEBUG] Pre-dispatcher found at: {hex(pre_dispatcher)}")
    except IndexError:
        print("[ERROR] Could not determine pre_dispatcher.")
        return None, None, None

    try:
        dispatcher = asmcfg.successors(asmcfg.loc_db.get_offset_location(pre_dispatcher))[0]
        dispatcher = asmcfg.loc_db.get_location_offset(dispatcher)
        print(f"[DEBUG] Dispatcher found at: {hex(dispatcher)}")
    except IndexError:
        print("[ERROR] Could not determine dispatcher.")
        return None, None, None

    relevant_blocks = set(preds[pre_dispatcher]) | set(preds[dispatcher])
    return list(relevant_blocks), dispatcher, pre_dispatcher


# do backwards search for jmp instruction to find start of relevant block
def get_block_father(asmcfg, blk_offset):
    blk = asmcfg.getby_offset(blk_offset)
    checklist = [blk.loc_key]

    try:
        pred = asmcfg.predecessors(blk.loc_key)[0]
    except IndexError:
        print(f"[ERROR] No predecessors found for block at offset: {hex(blk_offset)}")
        return None

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
    """
    주어진 IR CFG에서 state_var의 사용 위치를 탐지합니다.
    """
    var_addrs = set()

    for lbl, irblock in viewitems(ircfg.blocks):
        for assignblk in irblock:
            # 명령어의 모든 표현식 탐색
            all_exprs = assignblk.items()
            for dst, src in all_exprs:
                if search_var in dst.get_r() or search_var in src.get_r():
                    instr_offset = assignblk.instr.offset
                    var_addrs.add(instr_offset)
                    print(f"[DEBUG] Found state_var usage in dst/src at {hex(instr_offset)}")
                    continue

            # 추가 탐색: 명령어의 모든 표현식 분석
            for expr in assignblk.instr.get_args_expr():
                print(f"[DEBUG] Analyzing expression: {expr}")
                if any(search_var in sub_expr.get_r() for sub_expr in expr.get_r()):
                    instr_offset = assignblk.instr.offset
                    var_addrs.add(instr_offset)
                    print(f"[DEBUG] Found state_var in expression at {hex(instr_offset)}")
                    break

    if not var_addrs:
        print("[ERROR] No addresses found for state variable usage.")
    return var_addrs


    nop_addrs = find_state_var_usedefs(main_ircfg, state_var)
    print(f"[DEBUG] Found state_var usedef addresses: {nop_addrs}")
    if not nop_addrs:
        print(f"[WARNING] No state_var usages found in function @ {hex(ad)}")

    
