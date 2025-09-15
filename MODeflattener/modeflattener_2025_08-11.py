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

from miasm.expression.expression import ExprLoc
from miasm.expression.expression import ExprOp, ExprMem, ExprId, ExprInt, ExprLoc
from mod_utils import (
    _is_reg, _is_imm, _as_int,
    _is_switchvar_mem, _backtrack_reg_to_imm,
    _find_tail_jmp_to_dispatcher, make_rel32_jmp_bytes
)

from argparse import ArgumentParser
import time
import logging
import pprint

from mod_utils import *

class PatchNop:
    def __init__(self, offset, size):
        self.offset = offset
        self.data = b'\x90' * size  # NOP opcode (0x90) * size
        
        
class PatchBytes:
    def __init__(self, offset, data: bytes):
        self.offset = offset
        self.data = data
        
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
    """
    reg 최종값이 IMM 하나인지, cmov로 '둘 중 하나의 IMM'인지 역추적.
    반환: {imm} 또는 {imm1, imm2} (둘 다 IMM일 때), 실패 시 None
    """
    tgt = reg.name
    # 블록 내에서 역방향 스캔
    for i in range(len(lines) - 1, -1, -1):
        ins = lines[i]
        nm = ins.name.lower()

        # mov reg, IMM
        if nm == 'mov' and len(ins.args) == 2:
            dst, src = ins.args
            if _is_reg(dst, tgt) and _is_imm(src):
                return { _as_int(src) }

        # cmov* reg, reg2  (둘 다 직전 IMM이면 두 후보 집합 반환)
        if nm.startswith('cmov') and len(ins.args) == 2:
            dst, src = ins.args
            if _is_reg(dst, tgt) and _is_reg(src):
                imm_dst = _backtrack_reg_to_imm(lines[:i], dst)
                imm_src = _backtrack_reg_to_imm(lines[:i], src)
                s = set()
                if imm_dst is not None:
                    s.add(imm_dst)
                if imm_src is not None:
                    s.add(imm_src)
                if s:
                    return s
                return None

    return None


def extract_next_state(block):
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
                    # 우선 간단히 reg=IMM 또는 cmov(두 IMM)까지 집합으로
                    base_set = _backtrack_reg_to_imm_or_pair(lines[:idx+1], src)
                    if base_set and len(base_set) == 1:
                        return base_set
                    # 3) cmov 패턴을 'cmp [rbp-0xC], K'와 함께 단일화 시도
                    #    (아래는 가장 흔한 형태만 다룸: cmp mem, IMM ; cmovle eax, ecx ; mov [switchVar], eax)
                    #    필요한 경우 다른 cmov 조건도 추가 가능(cmovl, cmovg 등)
                    #    먼저, 바로 위쪽에서 cmp/ cmovle / mov eax,IMM / mov ecx,IMM 등을 수집
                    imm_a = None
                    imm_b = None
                    imm_k = None
                    saw_cmp_mem = False
                    saw_cmovle = False
                    # 앞쪽으로 최대 N개만 스캔(적당히 12~16)
                    for j in range(idx-1, max(-1, idx-16), -1):
                        pj = lines[j]
                        nm = pj.name.lower()
                        # mov eax, IMM / mov ecx, IMM
                        if nm == 'mov' and len(pj.args) == 2 and _is_imm(pj.args[1]) and _is_reg(pj.args[0]):
                            rname = pj.args[0].name.upper()
                            if rname == 'EAX':
                                imm_a = _as_int(pj.args[1])
                            elif rname == 'ECX':
                                imm_b = _as_int(pj.args[1])
                        # cmp [rbp-0xC], IMM_K
                        if nm == 'cmp' and len(pj.args) == 2 and isinstance(pj.args[0], ExprMem) and _is_imm(pj.args[1]):
                            ptr = getattr(pj.args[0], 'ptr', None)
                            if isinstance(ptr, ExprOp) and ptr.op == '+':
                                base, off = ptr.args
                                if isinstance(base, ExprId) and base.name in ('RBP','RSP') and isinstance(off, ExprInt):
                                    offv = off.arg
                                    if offv >= (1<<63): offv -= (1<<64)
                                    if offv in (-0xC,):
                                        saw_cmp_mem = True
                                        imm_k = _as_int(pj.args[1])
                        # cmovle eax, ecx
                        if nm == 'cmovle' and len(pj.args) == 2 and _is_reg(pj.args[0],'EAX') and _is_reg(pj.args[1],'ECX'):
                            saw_cmovle = True

                    if saw_cmp_mem and saw_cmovle and imm_a is not None and imm_b is not None and imm_k is not None:
                        # [rbp-0xC]의 값을 같은 블록에서 역추적
                        mem_const = _backtrack_mem_to_imm(lines[:idx+1], base_names=('RBP','RSP'), off_candidates=(-0xC,))
                        if mem_const is not None:
                            _, _, v = mem_const
                            # cmp v, imm_k ; cmovle이면 'v <= imm_k'일 때 ECX(=imm_b)
                            if v <= imm_k:
                                return { imm_b }
                            else:
                                return { imm_a }

                    # 단일화 실패 → 불확정
                    if base_set:
                        return base_set
                    return None

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
    relevant_blocks, dispatcher, pre_dispatcher = get_cff_info(main_asmcfg, dispatcher=addr)  # :contentReference[oaicite:0]{index=0}
    state_to_target = build_dispatcher_map(main_asmcfg, dispatcher)

    patches = []
    visited = set()

    # 2) 각 state의 target_block부터 체인 따라 직접 연결
    for state_val, target_bb in state_to_target.items():
        if target_bb in visited:
            continue

        cur = target_bb
        while True:
            visited.add(cur)
            block = main_asmcfg.getby_offset(cur)
            instrs = block.lines

            print(f"\n[+] Original BB at {hex(cur)}:")
            for instr in instrs:
                print(f"    {instr}")

            # (A) tail JMP가 dispatcher로 복귀한다면 → 이후 direct JMP로 대체 예정
            tail_off = _find_tail_jmp_to_dispatcher(block, dispatcher, main_asmcfg)

            # (C) next_state 계산 (집합 또는 None)
            next_state_set = extract_next_state(block)

            if next_state_set is None:
                print(f"[WARN] next_state undecidable at {hex(cur)}; keeping tail JMP.")
                break

            if len(next_state_set) >= 2:
                print(f"[WARN] multiple next_state candidates "
                    f"{sorted([hex(x) for x in next_state_set])} at {hex(cur)}; keeping tail JMP.")
                break

            # 단일 IMM 확정
            next_state = next(iter(next_state_set))
            nxt = state_to_target.get(next_state)
            if nxt is None:
                print(f"[INFO] next_state {hex(next_state)} not in dispatcher map; keeping tail JMP at {hex(cur)}.")
                break

            # (B) 이제서야 state 설정 mov들을 NOP (직접 점프로 대체할 때만)
            for instr in instrs:
                if instr.name == "mov" and len(instr.args) == 2:
                    dst, src = instr.args
                    if isinstance(dst, ExprMem) and isinstance(dst.ptr, ExprOp) and dst.ptr.op == "+":
                        off = dst.ptr.args[1]
                        if isinstance(off, ExprInt):
                            offv = off.arg
                            if offv >= (1<<63):
                                offv -= (1<<64)
                            if offv in (0x34, -0x2C, -0x04):
                                print(f"[INFO] NOP state set @ {hex(instr.offset)}")
                                patches.append(PatchNop(instr.offset, instr.l))

            # (E) tail JMP 위치에 direct JMP(cur→nxt)로 덮어쓰기
            if tail_off is not None:
                last = instrs[-1]
                jmp_bytes = make_rel32_jmp_bytes(last.offset, nxt, last.l)
                patches.append(PatchBytes(last.offset, jmp_bytes))
                print(f"[INFO] Direct JMP patch {hex(last.offset)} → {hex(nxt)} (len={last.l})")
            else:
                print(f"[WARN] No tail JMP to replace at {hex(cur)}; skipping direct JMP insertion.")

            if nxt in visited:
                break
            cur = nxt

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