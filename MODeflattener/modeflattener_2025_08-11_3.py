from future.utils import viewitems, viewvalues
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.analysis.simplifier import *
from miasm.expression.expression import *
from miasm.core.asmblock import *
from miasm.arch.x86.arch import mn_x86
from miasm.core.utils import encode_hex
from mod_utils import _backtrack_mem_to_imm
from mod_utils import _mem_key_from_exprmem
from miasm.expression.expression import ExprLoc
from miasm.expression.expression import ExprOp, ExprMem, ExprId, ExprInt, ExprLoc

from mod_utils import (
    _is_reg, _is_imm, _as_int,
    _is_switchvar_mem, _backtrack_reg_to_imm,
    _find_tail_jmp_to_dispatcher, make_rel32_jmp_bytes,
    _backtrack_mem_to_imm,
    _decide_cmov,
    _capture_stack_consts_for_next,   # ← 추가
    _capture_regs_for_next, 
    get_cff_info,
)

from argparse import ArgumentParser
import time
import logging
import pprint

class PatchNop:
    def __init__(self, offset, size):
        self.offset = offset
        self.data = b'\x90' * size  # NOP opcode (0x90) * size
        
        
class PatchBytes:
    def __init__(self, offset, data: bytes):
        self.offset = offset
        self.data = data


def _mem_key_from_exprmem(m):
    # ExprMem 형태에서 (BASE, OFF) 키 추출: ('RBP', -0x10) 같은 형태
    if isinstance(m, ExprMem) and isinstance(m.ptr, ExprOp) and m.ptr.op == '+':
        base, off = m.ptr.args
        if _is_reg(base) and isinstance(off, ExprInt):
            base_name = base.name.upper()
            offv = off.arg if off.arg < (1 << 63) else off.arg - (1 << 64)
            return (base_name, offv)
    return None

  
def _succ_offsets(asmcfg, bb):
    """ 버전 독립적으로 후속 블록 offset 리스트 얻기 """
    offs = []
    for succ in getattr(bb, "bto", []):
        loc_key = None
        from miasm.expression.expression import ExprLoc
        if isinstance(succ, ExprLoc):
            loc_key = succ.loc_key
        elif hasattr(succ, "loc_key"):
            loc_key = getattr(succ, "loc_key")
        elif hasattr(succ, "arg") and isinstance(getattr(succ, "arg"), ExprLoc):
            loc_key = succ.arg.loc_key
        else:
            continue
        try:
            off = asmcfg.loc_db.get_location_offset(loc_key)
            offs.append(off)
        except Exception:
            continue
    return offs

def _last_jmp_target_addr(asmcfg, block):
    """ 블록 마지막이 JMP라면 그 목적지(정수 주소) 반환, 아니면 None """
    if not block.lines:
        return None
    last = block.lines[-1]
    if last.name.lower() != 'jmp' or not last.args:
        return None
    dst = last.args[0]
    if isinstance(dst, ExprInt):
        return dst.arg
    if isinstance(dst, ExprLoc):
        return asmcfg.loc_db.get_location_offset(dst.loc_key)
    return None


def _is_compare_node(block):
    """ (sub|cmp) eax, IMM ; je/jz ... 가 같은 블록 안에 존재하면 비교 노드로 본다 """
    saw_imm_cmp = False
    for ins in block.lines:
        nm = ins.name.lower()
        if nm in ('sub', 'cmp') and len(ins.args) == 2:
            if _is_reg(ins.args[0], 'EAX') and _is_imm(ins.args[1]):
                saw_imm_cmp = True
        if nm in ('je', 'jz') and saw_imm_cmp:
            return True
    return False


def build_dispatcher_map(asmcfg, dispatcher_addr):
    """
    1) dispatcher_addr에서 시작해 BFS로 비교 노드들을 따라가며 state->target 수집
    2) 보강: 함수 내 모든 블록을 순회하며 (sub|cmp eax,IMM ; je T) 패턴이면
       T 블록의 마지막 JMP가 dispatcher로 복귀하는지 확인해서 map에 추가
    """
    m = {}
    visited = set()
    work = [dispatcher_addr]

    # --- (1) BFS 체인 추적 ---
    while work:
        cur = work.pop()
        if cur in visited:
            continue
        visited.add(cur)

        bb = asmcfg.getby_offset(cur)
        ins = bb.lines
        imm_val = None

        # 같은 블록 안에서 (sub|cmp eax,IMM) → (je/jz T) 패턴 추출
        for op in ins:
            nm = op.name.lower()
            if nm in ('sub', 'cmp') and len(op.args) == 2:
                if _is_reg(op.args[0], 'EAX') and _is_imm(op.args[1]):
                    imm_val = _as_int(op.args[1])
            elif nm in ('je', 'jz') and op.args and imm_val is not None:
                dst = op.args[0]
                if isinstance(dst, ExprInt):
                    tgt_addr = dst.arg
                elif isinstance(dst, ExprLoc):
                    tgt_addr = asmcfg.loc_db.get_location_offset(dst.loc_key)
                else:
                    tgt_addr = None
                if tgt_addr is not None:
                    m[imm_val] = tgt_addr

        # 후속 후보들 모두 넣기 (fall-through, jmp $+5, 기타)
        for nxt in _succ_offsets(asmcfg, bb):
            try:
                nxt_bb = asmcfg.getby_offset(nxt)
            except Exception:
                continue
            # 비교 노드면 계속 추적
            if _is_compare_node(nxt_bb):
                work.append(nxt)

        # 마지막 명령이 JMP면 그 목적지도 비교노드라면 추적
        tail = _last_jmp_target_addr(asmcfg, bb)
        if tail is not None:
            try:
                tail_bb = asmcfg.getby_offset(tail)
                if _is_compare_node(tail_bb):
                    work.append(tail)
            except Exception:
                pass

    # --- (2) 브루트포스 보강: 함수 전체에서 'dispatcher 복귀' 타겟만 추가 ---
    for block in asmcfg.blocks:
        ins = block.lines
        imm_val = None
        tgt_addr = None

        for op in ins:
            nm = op.name.lower()
            if nm in ('sub', 'cmp') and len(op.args) == 2:
                if _is_reg(op.args[0], 'EAX') and _is_imm(op.args[1]):
                    imm_val = _as_int(op.args[1])
            elif nm in ('je', 'jz') and op.args and imm_val is not None:
                dst = op.args[0]
                if isinstance(dst, ExprInt):
                    tgt_addr = dst.arg
                elif isinstance(dst, ExprLoc):
                    tgt_addr = asmcfg.loc_db.get_location_offset(dst.loc_key)
                else:
                    tgt_addr = None

                if tgt_addr is not None:
                    # 이 타겟 블록이 dispatcher로 복귀하면 dispatcher chain의 한 case로 인정
                    try:
                        tgt_bb = asmcfg.getby_offset(tgt_addr)
                    except Exception:
                        continue
                    j = _last_jmp_target_addr(asmcfg, tgt_bb)
                    if j == dispatcher_addr:
                        m[imm_val] = tgt_addr

    # 디버그 출력
    if not m:
        print("[WARN] dispatcher map empty")
    else:
        print("[DEBUG] dispatcher map:")
        for k, v in sorted(m.items()):
            print(f"  state {hex(k)} -> {hex(v)}")
    return m


def _backtrack_reg_to_imm_or_pair(lines, reg):
    tgt = reg.name
    for i in range(len(lines)-1, -1, -1):
        ins = lines[i]
        nm = ins.name.lower()

        # mov reg, IMM
        if nm == 'mov' and len(ins.args)==2:
            dst, src = ins.args
            if _is_reg(dst, tgt) and _is_imm(src):
                return {_as_int(src)}

        # cmov* reg, src_reg  → 둘 다 직전 IMM이면 {imm1, imm2}
        if nm.startswith('cmov') and len(ins.args)==2:
            dst, src = ins.args
            if _is_reg(dst, tgt) and _is_reg(src):
                imm_dst = _backtrack_reg_to_imm(lines[:i], dst)
                imm_src = _backtrack_reg_to_imm(lines[:i], src)
                s = set()
                if imm_dst is not None: s.add(imm_dst)
                if imm_src is not None: s.add(imm_src)
                if s: return s
    return None


def extract_next_state(block, known_mem=None, known_regs=None):
    if known_mem  is None: known_mem  = {}
    if known_regs is None: known_regs = {}
    lines = block.lines

    for idx in range(len(lines)-1, -1, -1):
        ins = lines[idx]
        if ins.name.lower() == 'mov' and len(ins.args) == 2:
            dst, src = ins.args
            if _is_switchvar_mem(dst):
                # 1) 직접 IMM 저장
                if _is_imm(src):
                    return { _as_int(src) }

                # 2) reg → mem 저장
                if _is_reg(src):
                    base_set = _backtrack_reg_to_imm_or_pair(lines[:idx+1], src)

                    # 2-1) 이미 단일 IMM로 확정된 경우 즉시 반환
                    if base_set and len(base_set) == 1:
                        return base_set

                    # 2-2) cmov 단일화 시도 (base_set이 None이거나 2개 이상일 때)
                    imm_a = imm_b = None
                    relop = None
                    L_const = R_const = None
                    src_reg_name = None   # ★ 추가

                    scan_lim = 32
                    for j in range(idx-1, max(-1, idx-scan_lim), -1):
                        pj = lines[j]; nm = pj.name.lower()

                        # cmov* eax, <reg>  → src_reg_name 기억 + relop 기록
                        if nm.startswith('cmov') and len(pj.args) == 2 and _is_reg(pj.args[0], 'EAX') and _is_reg(pj.args[1]):
                            src_reg_name = pj.args[1].name.upper()
                            rel_map = {
                                'cmovle':'le','cmovl':'l','cmovge':'ge','cmovg':'g',
                                'cmovz':'z','cmovnz':'nz',
                                'cmova':'a','cmovae':'ae','cmovb':'b','cmovbe':'be',
                            }
                            relop = rel_map.get(nm, relop)
                            continue

                        # mov eax, IMM / mov <src_reg>, IMM
                        if nm == 'mov' and len(pj.args)==2 and _is_reg(pj.args[0]) and _is_imm(pj.args[1]):
                            r = pj.args[0].name.upper()
                            if r == 'EAX':
                                imm_a = _as_int(pj.args[1])
                            elif src_reg_name and r == src_reg_name:
                                imm_b = _as_int(pj.args[1])

                        # cmp L, R
                        if nm == 'cmp' and len(pj.args) == 2:
                            L, R = pj.args

                            # --- L ---
                            if _is_imm(L):
                                L_const = _as_int(L)
                            elif _is_reg(L):
                                # 1) known_regs 우선
                                _rname = L.name.upper()
                                L_const = known_regs.get(_rname)
                                # 2) 없으면 역추적
                                if L_const is None:
                                    L_const = _backtrack_reg_to_imm(lines[:j+1], L)
                            elif isinstance(L, ExprMem):
                                key = _mem_key_from_exprmem(L)
                                if known_mem is not None and key in known_mem:
                                    L_const = known_mem[key]
                                else:
                                    mem = _backtrack_mem_to_imm(
                                        lines[:j+1],
                                        base_names=('RBP', 'RSP'),
                                        off_candidates=(-0x4, -0x8, -0xC, -0x10, -0x14, -0x18, -0x1C, -0x20)
                                    )
                                    if mem is not None:
                                        _, _, L_const = mem

                            # --- R ---
                            if _is_imm(R):
                                R_const = _as_int(R)
                            elif _is_reg(R):
                                _rname = R.name.upper()
                                R_const = known_regs.get(_rname)
                                if R_const is None:
                                    R_const = _backtrack_reg_to_imm(lines[:j+1], R)
                            elif isinstance(R, ExprMem):
                                key = _mem_key_from_exprmem(R)
                                if known_mem is not None and key in known_mem:
                                    R_const = known_mem[key]
                                else:
                                    mem = _backtrack_mem_to_imm(
                                        lines[:j+1],
                                        base_names=('RBP', 'RSP'),
                                        off_candidates=(-0x4, -0x8, -0xC, -0x10, -0x14, -0x18, -0x1C, -0x20)
                                    )
                                    if mem is not None:
                                        _, _, R_const = mem

                        

                    # 모든 재료가 모였으면 결정 시도
                    if relop and (imm_a is not None) and (imm_b is not None) and (L_const is not None) and (R_const is not None):
                        decided = _decide_cmov(imm_a, imm_b, relop, L_const, R_const)
                        if decided is not None:
                            return {decided}

                    # 2-3) cmov 단일화 실패: base_set이 있으면 그대로 반환(2개 후보), 아니면 불확정
                    if base_set:
                        return base_set
                    return None


def setup_logger(loglevel):
    FORMAT = '[%(levelname)s] %(message)s'
    logging.basicConfig(format=FORMAT)
    logger = logging.getLogger('modeflattener')

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)

    logger.setLevel(numeric_level)

    return logger

# https://synthesis.to/2021/03/15/control_flow_analysis.html
def calc_flattening_score(graph):
    cnt_cmp_or_sub = 0
    cnt_je_or_jmp = 0
    cnt_blocks = 0

    for block in graph.blocks:
        lines = block.lines
        for i, line in enumerate(lines):
            if line.name.startswith("sub") or line.name.startswith("cmp"):
                cnt_cmp_or_sub += 1
            elif line.name.startswith("je") or line.name.startswith("jmp"):
                cnt_je_or_jmp += 1
        cnt_blocks += 1

    if cnt_blocks == 0:
        return 0.0

    score = (cnt_cmp_or_sub + cnt_je_or_jmp) / float(cnt_blocks * 2)
    return score


# callback to stop disassembling when it encounters any jump
def stop_on_jmp(mdis, cur_bloc, offset_to_dis):
    jmp_instr_check = cur_bloc.lines[-1].name in ['JMP','JZ','JNZ']

    if jmp_instr_check:
        cur_bloc.bto.clear()
        offset_to_dis.clear()


                            
                            
def deflat(addr, main_asmcfg):
    # 1) dispatcher 체인 분석
    relevant_blocks, dispatcher, pre_dispatcher = get_cff_info(main_asmcfg, dispatcher=addr)
    state_to_target = build_dispatcher_map(main_asmcfg, dispatcher)

    patches = []
    # ★ 모든 체인 공통 상태 (중복/충돌/중복 NOP 방지)
    jmp_target_by_off = {}   # off -> target (이미 같은 타깃으로 패치했는지 기록)
    jmp_conflicts     = set()# 서로 다른 타깃으로 시도된 off들(→ 패치 금지)
    nop_sites         = set()# 이미 NOP 찍은 오프셋들(중복 방지)

    # 2) 각 state의 target_block부터 체인 따라 직접 연결
    for state_val, target_bb in state_to_target.items():
        visited_chain = set()
        cur = target_bb

        # 체인별 컨텍스트 (상수 전파)
        known_mem  = {}   # ('RBP', -0x10) -> int
        known_regs = {}

        while True:
            if cur in visited_chain:
                break
            visited_chain.add(cur)

            block  = main_asmcfg.getby_offset(cur)
            instrs = block.lines

            tail_off = _find_tail_jmp_to_dispatcher(block, dispatcher, main_asmcfg)

            # next_state 계산 (컨텍스트 전달)
            next_state_set = extract_next_state(block, known_mem=known_mem, known_regs=known_regs)

            # 불확정(없음/복수) → 안전하게 디스패처 유지
            if not next_state_set or len(next_state_set) >= 2:
                msg = ("None" if not next_state_set
                       else ", ".join(sorted(hex(x) for x in next_state_set)))
                print(f"[WARN] keeping tail JMP at {hex(cur)}; candidates={msg}")
                # 컨텍스트 업데이트: REG → MEM
                _capture_regs_for_next(block, known_regs, known_mem)
                _capture_stack_consts_for_next(block, known_mem, known_regs)
                break

            # 단일 후보
            next_state = next(iter(next_state_set))
            nxt = state_to_target.get(next_state)
            if nxt is None:
                # 체인 종결
                _capture_regs_for_next(block, known_regs, known_mem)
                _capture_stack_consts_for_next(block, known_mem, known_regs)
                break

            # ==== tail JMP 교체 (★ 한 번만, 충돌/중복 방지) ====
            if tail_off is not None:
                last = instrs[-1]
                off  = last.offset

                prev = jmp_target_by_off.get(off)
                if prev is not None and prev != nxt:
                    # 서로 다른 타깃으로 두 번 시도 → 이 오프셋은 디스패처 유지
                    if off not in jmp_conflicts:
                        jmp_conflicts.add(off)
                        print(f"[CONFLICT] jmp@{hex(off)} targets {hex(prev)} vs {hex(nxt)} → keep dispatcher")
                elif prev == nxt:
                    # 같은 타깃으로는 이미 패치함 → 재시도/로그 모두 스킵
                    pass
                else:
                    # 최초 패치
                    jmp_target_by_off[off] = nxt
                    jbytes = make_rel32_jmp_bytes(off, nxt, last.l)
                    patches.append(PatchBytes(off, jbytes))
                    print(f"[INFO] Direct JMP patch {hex(off)} → {hex(nxt)} (len={last.l})")

                    # ★ state write NOP: switchVar에 쓰는 mov만, 그리고 이 블록이 실제로 direct JMP 됐을 때 1회만
                    for ins in instrs:
                        if ins.name.lower() == 'mov' and len(ins.args) == 2:
                            dst, src = ins.args
                            if _is_switchvar_mem(dst) and ins.offset not in nop_sites:
                                patches.append(PatchNop(ins.offset, ins.l))
                                nop_sites.add(ins.offset)
            else:
                print(f"[WARN] No tail JMP...")

            # 컨텍스트 업데이트 (REG → MEM)
            _capture_regs_for_next(block, known_regs, known_mem)
            _capture_stack_consts_for_next(block, known_mem, known_regs)

            # 다음 블록 진행
            if nxt in visited_chain:
                break
            cur = nxt

    # ==== 체인 모두 끝난 뒤: 충돌/중복 정리 ====
    if jmp_conflicts:
        # 충돌난 오프셋의 PatchBytes는 모두 제거(디스패처 유지)
        patches = [p for p in patches
                   if not (isinstance(p, PatchBytes) and p.offset in jmp_conflicts)]

    # 최종 dedup (동일 오프셋/데이터 중복 제거)
    seen = set()
    dedup = []
    for p in patches:
        key = (p.__class__.__name__, p.offset, getattr(p, 'data', None))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(p)
    patches = dedup

    print(f"[SUMMARY] dispatcher cases: {len(state_to_target)}")
    djmps = sum(1 for p in patches if isinstance(p, PatchBytes))
    nops  = sum(1 for p in patches if isinstance(p, PatchNop))
    print(f"[SUMMARY] patches written: {djmps} direct jmps, {nops} nops")
    return patches





if __name__ == '__main__':
    parser = ArgumentParser("modeflattener")
    parser.add_argument('filename', help="file to deobfuscate")
    parser.add_argument('patch_filename', help="deobfuscated file name")
    parser.add_argument('address', help="obfuscated function address")
    parser.add_argument('-a', "--all", action="store_true",
                        help="find and deobfuscate all flattened functions recursively")
    parser.add_argument('-l', "--log", help="logging level (default=INFO)",
                        default='info')

    args = parser.parse_args()

    loglevel = args.log
    _log = setup_logger(loglevel)

    deobf_start_time = time.time()

    forg = open(args.filename, 'rb')
    fpatch = open(args.patch_filename, 'wb')
    fpatch.write(forg.read())

    loc_db = LocationDB()

    global cont
    cont = Container.from_stream(open(args.filename, 'rb'), loc_db)

    supported_arch = ['x86_32', 'x86_64']
    _log.info("Architecture : %s"  % cont.arch)

    if cont.arch not in supported_arch:
        _log.error("Architecture unsupported : %s" % cont.arch)
        exit(1)

    section_ep = cont.bin_stream.bin.virt.parent.getsectionbyvad(cont.entry_point).sh
    bin_base_addr = section_ep.addr - section_ep.offset
    _log.info('bin_base_addr: %#x' % bin_base_addr)

    machine = Machine(cont.arch)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)

    ad = int(args.address, 0)
    todo = [(mdis, None, ad)]
    done = set()
    all_funcs = set()
    all_funcs_blocks = {}

    while todo:
        mdis, caller, ad = todo.pop(0)
        if ad in done:
            continue
        done.add(ad)
        asmcfg = mdis.dis_multiblock(ad)
        lifter = machine.lifter_model_call(mdis.loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        _log.info('found func @ %#x (%d)' % (ad, len(all_funcs)))

        all_funcs.add(ad)
        all_funcs_blocks[ad] = (asmcfg, ircfg)

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

    for ad in all_funcs:
        asmcfg = all_funcs_blocks[ad][0]
        score = calc_flattening_score(asmcfg)

        # flattening score 무시: address 직접 지정한 경우는 무조건 deflat 시도
        if not args.all or ad == int(args.address, 0):
            print('-------------------------')
            print('|    func : %#x    |' % ad)
            print('-------------------------')
            fcn_start_time = time.time()
            patches = deflat(ad, all_funcs_blocks[ad][0])

            if patches:
                for patch in patches:
                    offset = patch.offset
                    data = patch.data

                    print(f"[+] Writing patch at {hex(offset)}: {len(data)} bytes")

                    fpatch.seek(offset - bin_base_addr)
                    fpatch.write(data)

                fcn_end_time = time.time() - fcn_start_time
                _log.info("PATCHING SUCCESSFUL for function @ %#x (%.2f secs)\n" % (ad, fcn_end_time))
            else:
                _log.error("PATCHING UNSUCCESSFUL for function @ %#x\n" % ad)

        else:
            _log.error("unable to deobfuscate func %#x (cff score = %f)\n" % (ad, score))

    fpatch.close()
    deobf_end_time = time.time() - deobf_start_time

    _log.info("Deobfuscated file saved at '%s' (Total Time Taken : %.2f secs)" % (args.patch_filename, deobf_end_time))