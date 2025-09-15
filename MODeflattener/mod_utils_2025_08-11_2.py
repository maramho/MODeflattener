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
from miasm.expression.expression import ExprOp, ExprMem, ExprId, ExprInt
from miasm.expression.expression import ExprOp, ExprMem, ExprId, ExprInt, ExprLoc


import logging

_log = logging.getLogger('modeflattener')

SWITCHVAR_MEM_OFFSETS = {0x34, -0x2C, -0x04}

asmb = lambda patch_str, loc_db: mn_x86.asm(mn_x86.fromstring(patch_str, loc_db, 32))[0]
rel = lambda addr, patch_addr: hex(addr - patch_addr)


def _u32(x):
    return x & 0xFFFFFFFF

def _s32(x):
    x = x & 0xFFFFFFFF
    return x if x < 0x80000000 else x - 0x100000000

def _decide_cmov(dst_val, src_val, relop, L, R):
    """
    dst_val: cmov의 대상 레지스터 원래 값 (예: EAX = IMM_A)
    src_val: cmov의 소스 레지스터 값   (예: ECX = IMM_B)
    relop:   'le','l','ge','g','z','nz','a','ae','b','be'
    L, R:    직전 cmp L, R
    비교 의미:
      - l/le/g/ge 는 32비트 **signed**
      - a/ae/b/be 는 32비트 **unsigned**
      - z/nz      는 32비트 **동등/비동등**
    반환: 선택된 IMM(int) 또는 None
    """
    if None in (dst_val, src_val, L, R):
        return None

    # 32비트 정규화
    A  = _u32(dst_val)
    B  = _u32(src_val)
    Ls = _s32(L)
    Rs = _s32(R)
    Lu = _u32(L)
    Ru = _u32(R)

    if   relop == 'le': return B if Ls <= Rs else A
    elif relop == 'l':  return B if Ls <  Rs else A
    elif relop == 'ge': return B if Ls >= Rs else A
    elif relop == 'g':  return B if Ls >  Rs else A
    elif relop == 'z':  return B if Lu == Ru else A
    elif relop == 'nz': return B if Lu != Ru else A
    elif relop == 'a':  return B if Lu >  Ru else A   # above   (unsigned>)
    elif relop == 'ae': return B if Lu >= Ru else A   # above=  (unsigned>=)
    elif relop == 'b':  return B if Lu <  Ru else A   # below   (unsigned<)
    elif relop == 'be': return B if Lu <= Ru else A   # below=  (unsigned<=)
    return None


def _capture_stack_consts_for_next(block, known_mem, known_regs):
    """
    현재 블록에서 [RBP/RSP + off]에 쓰는 값이 IMM이거나,
    REG/MEM이지만 상수로 해석되면 known_mem[(base, off)] = imm 로 기록.
    """
    for ins in getattr(block, "lines", []):
        if ins.name.lower() == 'mov' and len(ins.args) == 2:
            dst, src = ins.args
            if isinstance(dst, ExprMem):
                ptr = getattr(dst, 'ptr', None)
                if isinstance(ptr, ExprOp) and ptr.op == '+':
                    base, off = ptr.args
                    if isinstance(base, ExprId) and isinstance(off, ExprInt) and base.name in ('RBP','RSP'):
                        offv = off.arg if off.arg < (1 << 63) else off.arg - (1 << 64)
                        val = _resolve_expr_to_const(block.lines, src, known_mem, known_regs, base_names=('RBP','RSP'))
                        if val is not None:
                            known_mem[(base.name, offv)] = val

def _backtrack_reg_to_imm_or_pair(ircfg, start_block, start_reg, max_depth=10):
    """
    주어진 ircfg에서 start_reg 값을 거슬러 올라가 즉시값(imm) 또는 (reg1, reg2) 형태로 추적.
    max_depth: 무한루프 방지를 위한 추적 깊이 제한
    """
    visited = set()
    reg_val = start_reg
    depth = 0

    while depth < max_depth:
        depth += 1
        if reg_val in visited:
            break
        visited.add(reg_val)

        found = False
        for assign in ircfg.get_assign_bl(start_block.loc_key):
            dst, src = assign
            if dst == reg_val:
                # 즉시값이면 반환
                if src.is_int():
                    return src
                # 레지스터 쌍이면 반환
                elif src.is_mem():
                    return (src.arg, None)
                elif src.is_loc():
                    reg_val = src
                    found = True
                    break
        if not found:
            break
    return None

def _backtrack_mem_to_imm(lines, base_names=('RBP','RSP'), off_candidates=(-0x4, -0x8, -0xC, -0x10, -0x14, -0x18, -0x1C)):
    """
    블록 내부에서 뒤로 스캔하며 [base+off] 위치에 어떤 IMM이 저장됐는지 추적.
    간단 케이스만 지원:
      mov [rbp-0xC], IMM
      mov reg, IMM ; ... ; mov [rbp-0xC], reg
    찾으면 (base, off, imm) 반환, 없으면 None
    """
    for i in range(len(lines)-1, -1, -1):
        ins = lines[i]
        nm = ins.name.lower()
        if nm == 'mov' and len(ins.args) == 2:
            dst, src = ins.args
            if isinstance(dst, ExprMem):
                ptr = getattr(dst, 'ptr', None)
                if isinstance(ptr, ExprOp) and ptr.op == '+':
                    base, off = ptr.args
                    if isinstance(base, ExprId) and isinstance(off, ExprInt) and base.name in base_names:
                        offv = off.arg
                        if offv >= (1<<63):
                            offv -= (1<<64)
                        if offv in off_candidates:
                            if _is_imm(src):
                                return (base.name, offv, _as_int(src))
                            if _is_reg(src):
                                imm = _backtrack_reg_to_imm(lines[:i+1], src)
                                if imm is not None:
                                    return (base.name, offv, imm)
    return None

    
def _is_switchvar_mem(expr):
    if not isinstance(expr, ExprMem):
        return False
    ptr = expr.ptr
    if not isinstance(ptr, ExprOp) or ptr.op != '+':
        return False
    base, off = ptr.args
    if not isinstance(base, ExprId) or not isinstance(off, ExprInt):
        return False
    # RSP/RBP 모두 허용 (ID 이름 비교)
    if base.name not in ("RSP", "RBP"):
        return False
    val = off.arg
    # 음수 오프셋 64-bit 표기 보정
    if val >= (1 << 63):
        val -= (1 << 64)
    return val in SWITCHVAR_MEM_OFFSETS

def _is_imm(x):
    return isinstance(x, ExprInt)

def _is_reg(x, name=None):
    if not isinstance(x, ExprId):
        return False
    return (name is None) or (x.name.upper() == name.upper())

def _as_int(x):
    return int(x.arg) if isinstance(x, ExprInt) else None


def _find_tail_jmp_to_dispatcher(block, dispatcher_addr, asmcfg):
    if not block.lines:
        return None
    last = block.lines[-1]
    if last.name.lower() != 'jmp' or not last.args:
        return None

    dst = last.args[0]
    # 직주소 / 라벨 모두 처리
    if isinstance(dst, ExprInt):
        dst_addr = dst.arg
    elif isinstance(dst, ExprLoc):
        dst_addr = asmcfg.loc_db.get_location_offset(dst.loc_key)
    else:
        return None

    return last.offset if dst_addr == dispatcher_addr else None

def make_rel32_jmp_bytes(src_addr, dst_addr, length=5):
    """
    E9 rel32 JMP로 바꿀 때 쓸 원시 바이트 생성.
    length가 5보다 크면 남는 바이트는 NOP로 패딩.
    """
    rel = (dst_addr - (src_addr + 5)) & 0xFFFFFFFF
    jmp = bytes([0xE9]) + rel.to_bytes(4, byteorder='little', signed=False)
    if length > 5:
        jmp += b'\x90' * (length - 5)
    return jmp

def _backtrack_reg_to_imm(lines, reg):
    """ 같은 블록 내에서 reg를 마지막으로 즉치로 설정한 mov를 역추적 """
    target = reg.name
    for ins in reversed(lines):
        if ins.name.lower() == 'mov' and len(ins.args) == 2:
            dst, src = ins.args
            if _is_reg(dst, target) and _is_imm(src):
                return _as_int(src)
    return None

def _resolve_expr_to_const(lines, expr, known_mem, known_regs=None, base_names=('RBP','RSP')):
    if known_regs is None: known_regs = {}
    if isinstance(expr, ExprInt):
        return int(expr.arg)
    if isinstance(expr, ExprId):
        # known_regs 우선
        v = known_regs.get(expr.name.upper())
        if v is not None:
            return v
        # (필요 시 블록 내 _backtrack_reg_to_imm)
        return _backtrack_reg_to_imm(lines, expr)

    if isinstance(expr, ExprMem):
        ptr = getattr(expr, 'ptr', None)
        if isinstance(ptr, ExprOp) and ptr.op == '+':
            base, off = ptr.args
            if isinstance(base, ExprId) and isinstance(off, ExprInt) and base.name in base_names:
                offv = off.arg if off.arg < (1 << 63) else off.arg - (1 << 64)
                key = (base.name, offv)
                if key in known_mem:
                    return known_mem[key]
                mem = _backtrack_mem_to_imm(lines, base_names=(base.name,), off_candidates=(offv,))
                if mem is not None:
                    return mem[2]
    return None


def _capture_regs_for_next(block, known_regs, known_mem):
    """
    레지스터 상수 전파(간단 버전)
      - mov reg, IMM               → reg = IMM
      - mov reg, [rbp/rsp+off]     → known_mem에 있으면 reg = const
      - add/sub reg, IMM           → reg = reg ± IMM  (reg가 상수일 때만)
      - inc/dec reg                → reg = reg ± 1    (reg가 상수일 때만)
    """
    for ins in getattr(block, "lines", []):
        nm = ins.name.lower()

        # mov reg, <expr>
        if nm == 'mov' and len(ins.args) == 2 and isinstance(ins.args[0], ExprId):
            dst_reg = ins.args[0].name.upper()
            src     = ins.args[1]

            # src를 상수로 해석 (IMM / REG / MEM 모두 시도)
            # _resolve_expr_to_const(lines, expr, known_mem, known_regs, base_names=...)
            try:
                val = _resolve_expr_to_const(block.lines, src, known_mem, known_regs, base_names=('RBP','RSP'))
            except TypeError:
                # (_resolve_expr_to_const가 known_regs 파라미터 없는 옛 시그니처인 경우)
                val = _resolve_expr_to_const(block.lines, src, known_mem, base_names=('RBP','RSP'))

            if val is not None:
                known_regs[dst_reg] = val & 0xFFFFFFFF
            continue

        # add/sub reg, IMM
        if nm in ('add', 'sub') and len(ins.args) == 2 and isinstance(ins.args[0], ExprId) and isinstance(ins.args[1], ExprInt):
            r = ins.args[0].name.upper()
            k = int(ins.args[1].arg)
            if r in known_regs:
                known_regs[r] = (known_regs[r] + (k if nm == 'add' else -k)) & 0xFFFFFFFF
            continue

        # inc/dec reg
        if nm in ('inc', 'dec') and len(ins.args) == 1 and isinstance(ins.args[0], ExprId):
            r = ins.args[0].name.upper()
            if r in known_regs:
                known_regs[r] = (known_regs[r] + (1 if nm == 'inc' else -1)) & 0xFFFFFFFF
            continue

        # 산술(가벼운 것만)
        if nm in ('add','sub','inc','dec'):
            # add/sub reg, IMM  / inc/dec reg
            if nm in ('add','sub') and len(ins.args)==2 and isinstance(ins.args[0], ExprId) and isinstance(ins.args[1], ExprInt):
                r = ins.args[0].name.upper()
                k = int(ins.args[1].arg)
                if r in known_regs:
                    known_regs[r] = (known_regs[r] + (k if nm=='add' else -k)) & 0xFFFFFFFF
            elif nm in ('inc','dec') and len(ins.args)==1 and isinstance(ins.args[0], ExprId):
                r = ins.args[0].name.upper()
                if r in known_regs:
                    known_regs[r] = (known_regs[r] + (1 if nm=='inc' else -1)) & 0xFFFFFFFF
                    
                    
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

    for block in main_asmcfg.blocks:
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

    # ✅ dispatcher 이후 분기 블럭들을 모두 수집 (재귀 탐색 포함)
    dispatcher_blk = main_asmcfg.getby_offset(dispatcher)
    relevant_blocks = list(extract_relevant_blocks(dispatcher_blk, main_asmcfg))

    print(f"[DEBUG] ✅ Extracted {len(relevant_blocks)} relevant blocks after dispatcher.")
    for rb in relevant_blocks:
        print(f"         → 0x{rb:x}")

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


def _decide_cmov(dst_val, src_val, relop, L, R):
    # signed
    if relop == 'le': return src_val if L <= R else dst_val
    if relop == 'l':  return src_val if L <  R else dst_val
    if relop == 'ge': return src_val if L >= R else dst_val
    if relop == 'g':  return src_val if L >  R else dst_val
    if relop == 'z':  return src_val if L == R else dst_val
    if relop == 'nz': return src_val if L != R else dst_val
    # unsigned (32-bit)
    Lu = L & 0xFFFFFFFF; Ru = R & 0xFFFFFFFF
    if relop == 'a':   return src_val if Lu >  Ru else dst_val   # above
    if relop == 'ae':  return src_val if Lu >= Ru else dst_val   # above or equal
    if relop == 'b':   return src_val if Lu <  Ru else dst_val   # below
    if relop == 'be':  return src_val if Lu <= Ru else dst_val   # below or equal
    return None