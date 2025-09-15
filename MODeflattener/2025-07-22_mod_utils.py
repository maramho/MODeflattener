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
from miasm.ir.ir import *
# from miasm.ir.ir import IRJump


class IRJump:
    """IRJump 클래스가 miasm.ir.ir에 없을 경우 직접 정의"""
    def __init__(self, expr):
        self.expr = expr


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

def get_cff_info(asmcfg, loc_db):
    print("[DEBUG] get_cff_info() 실행 시작")

    relevant_blocks = set()
    dispatcher = None
    pre_dispatcher = None
    jmp_blocks = []

    for block in asmcfg.blocks:
        if not block.lines:
            continue  # 빈 블록 건너뛰기

        block_addr = loc_db.get_location_offset(block.loc_key)
        print(f"[DEBUG] 블록: {hex(block_addr)}")

        for instr in block.lines:
            if "MOV" in instr.name:
                args = instr.get_args_expr()
                if args and len(args) > 1 and isinstance(args[0], ExprMem) and isinstance(args[1], ExprInt):
                    print(f"[DEBUG] 찾은 MOV: {instr}")
                    relevant_blocks.add(block_addr)

            if "JMP" in instr.name:
                print(f"[DEBUG] 찾은 JMP: {instr}")
                relevant_blocks.add(block_addr)
                jmp_blocks.append(block_addr)

    if not relevant_blocks:
        print("[WARNING] relevant_blocks를 찾지 못했으므로, 전체 블록을 스캔합니다.")
        relevant_blocks = {block.lines[0].offset for block in asmcfg.blocks if block.lines}

    relevant_blocks = sorted(relevant_blocks)

    # 🔥 JMP가 있는 블록 중 가장 먼저 나오는 블록을 dispatcher로 설정
    if jmp_blocks:
        dispatcher = jmp_blocks[0]  # ✅ 가장 먼저 등장하는 JMP 블록을 dispatcher로 설정
    else:
        dispatcher = relevant_blocks[0] if relevant_blocks else None

    pre_dispatcher = relevant_blocks[1] if len(relevant_blocks) >= 2 else None

    print(f"[DEBUG] get_cff_info() 종료, relevant_blocks 개수: {len(relevant_blocks)}")
    print(f"[DEBUG] dispatcher: {dispatcher}, pre_dispatcher: {pre_dispatcher}")

    return relevant_blocks, dispatcher, pre_dispatcher


# do backwards search for jmp instruction to find start of relevant block
def get_block_father(asmcfg, blk_offset):
    blk = asmcfg.getby_offset(blk_offset)
    checklist = [blk.loc_key]

    pred = asmcfg.predecessors(blk.loc_key)
    if not pred:
        _log.error(f"ERROR: Block at {hex(blk_offset)} has no predecessors! Returning original block.")
        return blk_offset  # 오류 방지를 위해 원래 블록 반환

    pred = pred[0]  # 기존 코드
    while True:
        curr_bloc = asmcfg.loc_key_to_block(pred)
        if curr_bloc.lines[-1].name in ['JZ', 'JMP', 'JNZ']:
            break
        checklist.append(pred)
        pred = asmcfg.predecessors(curr_bloc.loc_key)[0] if asmcfg.predecessors(curr_bloc.loc_key) else pred

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

def find_state_var_usedefs(ircfg, state_var):
    state_var_uses = []
    state_var_val = int(state_var)
    tolerance = 0x200  # 허용 오프셋 확장

    for addr, irblock in ircfg.blocks.items():
        try:
            real_addr = ircfg.loc_db.get_location_offset(addr)
            print(f"[DEBUG] 전체 블록 스캔: {hex(real_addr)}")
        except Exception as e:
            print(f"[ERROR] LocKey 변환 실패: {e}")
            continue

        for assignblk in irblock:
            print(f"[DEBUG] 명령어: {assignblk}")  # 모든 명령어 출력

            for dst, src in assignblk.items():
                # ✅ 직접 참조
                if str(state_var_val) in str(dst) or str(state_var_val) in str(src):
                    state_var_uses.append(real_addr)
                    print(f"[DEBUG] 직접 사용 발견: {hex(real_addr)} → {assignblk}")

                # ✅ IRDst 탐지 및 추적 강화
                if "IRDst" in str(assignblk):
                    irdst_target = list(assignblk.items())[0][1]
                    print(f"[DEBUG] IRDst 분석 대상: {irdst_target}")
                    if isinstance(irdst_target, ExprInt):
                        diff = abs(irdst_target.arg - state_var_val)
                        if diff <= tolerance:
                            state_var_uses.append(real_addr)
                            print(f"[DEBUG] IRDst 사용 발견 (허용 오프셋 내): {hex(real_addr)} → {assignblk}")
                        else:
                            print(f"[DEBUG] IRDst 값 차이({diff})가 허용 범위를 초과했습니다.")
                    elif isinstance(irdst_target, ExprId):
                        print(f"[DEBUG] IRDst가 식별자: {irdst_target}")

                # ✅ MOV 명령어 탐지 (레지스터 포함)
                if hasattr(assignblk, 'name') and assignblk.name == 'MOV':
                    if (isinstance(src, ExprInt) and abs(src.arg - state_var_val) <= tolerance) or \
                       (isinstance(dst, ExprInt) and abs(dst.arg - state_var_val) <= tolerance):
                        state_var_uses.append(real_addr)
                        print(f"[DEBUG] MOV 명령어 발견: {assignblk}")

                # ✅ 메모리 참조 탐지 (간접 참조 추가)
                if isinstance(dst, ExprMem) or isinstance(src, ExprMem):
                    mem_expr = dst if isinstance(dst, ExprMem) else src
                    if str(state_var_val) in str(mem_expr):
                        state_var_uses.append(real_addr)
                        print(f"[DEBUG] 메모리 참조 사용 발견: {hex(real_addr)} → {assignblk}")
                    elif isinstance(mem_expr, ExprInt):
                        diff = abs(mem_expr.arg - state_var_val)
                        if diff <= tolerance:
                            state_var_uses.append(real_addr)
                            print(f"[DEBUG] 메모리 오프셋 사용 발견: {hex(real_addr)} → {assignblk}")

                # ✅ 복합 연산 탐지 (ADD, SUB, XOR, CMP, AND, OR, TEST)
                if hasattr(assignblk, 'name') and assignblk.name in ["ADD", "SUB", "XOR", "CMP", "AND", "OR", "TEST"]:
                    if any(isinstance(op, ExprInt) and abs(op.arg - state_var_val) <= tolerance for op in [dst, src]):
                        state_var_uses.append(real_addr)
                        print(f"[DEBUG] 복합 연산 사용 발견: {hex(real_addr)} → {assignblk}")

    if not state_var_uses:
        print(f"[WARNING] state_var {state_var} 사용 주소를 찾지 못했습니다.")

    return state_var_uses






def resolve_jump_target(asmcfg, loc_db, jmp_target):
    # 🔥 loc_key_* 처리
    if isinstance(jmp_target, ExprId) and 'loc_key' in str(jmp_target):
        loc_key = str(jmp_target)
        try:
            target_offset = loc_db.get_location_offset(loc_key)
            print(f"[DEBUG] loc_key 변환 성공: {loc_key} → {hex(target_offset)}")
            return target_offset
        except Exception as e:
            print(f"[ERROR] loc_key 변환 실패: {loc_key}, 에러: {e}")
            return None

    # 🔥 QWORD PTR [RIP + offset] 처리
    elif isinstance(jmp_target, ExprMem) and "RIP" in str(jmp_target):
        try:
            print(f"[DEBUG] JMP 대상: {jmp_target}")
            rip_offset_str = str(jmp_target).split("+")[1].split("]")[0]
            print(f"[DEBUG] 추출된 RIP 오프셋 문자열: {rip_offset_str}")

            rip_offset = int(rip_offset_str.strip(), 16)
            print(f"[DEBUG] RIP 오프셋 (정수): {hex(rip_offset)}")

            base_blocks = list(asmcfg.blocks)
            print(f"[DEBUG] base_blocks: {base_blocks}")

            if base_blocks:
                base_block = base_blocks[0]
                print(f"[DEBUG] base_block 정보: {base_block}")

                # LocKey가 존재하는지 확인
                if hasattr(base_block, 'loc_key'):
                    rip_base = loc_db.get_location_offset(base_block.loc_key)
                    print(f"[DEBUG] RIP base: {hex(rip_base)}")

                    resolved_addr = rip_base + rip_offset
                    print(f"[DEBUG] RIP 기반 JMP 변환 성공: {jmp_target} → {hex(resolved_addr)}")
                    return resolved_addr
                else:
                    print("[ERROR] base_block에 loc_key 속성이 없습니다.")
                    return None
            else:
                print("[WARNING] base_blocks가 비어 있습니다.")
                return None

        except AttributeError as ae:
            print(f"[ERROR] AttributeError 발생: {ae}")
        except ValueError as ve:
            print(f"[ERROR] ValueError 발생: {ve}")
        except Exception as e:
            print(f"[ERROR] RIP 기반 JMP 변환 실패: {jmp_target}, 에러: {e}")

        return None
    return None

def find_state_var_usedefs(ircfg, state_var):
    state_var_uses = []
    state_var_val = str(state_var)

    for addr, irblock in ircfg.blocks.items():
        # 🔥 LocKey를 실제 오프셋으로 변환
        try:
            real_addr = ircfg.loc_db.get_location_offset(addr)
            print(f"[DEBUG] 전체 블록 스캔: {hex(real_addr)}")  # 오프셋으로 변환 후 출력
        except Exception as e:
            print(f"[ERROR] LocKey 변환 실패: {e}")
            continue

        for assignblk in irblock:
            for dst, src in assignblk.items():
                # ✅ 직접 참조
                if state_var_val in str(dst) or state_var_val in str(src):
                    state_var_uses.append(real_addr)
                    print(f"[DEBUG] 직접 사용 발견: {hex(real_addr)} → {assignblk}")

                # ✅ 메모리 참조
                if isinstance(dst, ExprMem) or isinstance(src, ExprMem):
                    mem_expr = dst if isinstance(dst, ExprMem) else src
                    if state_var_val in str(mem_expr):
                        state_var_uses.append(real_addr)
                        print(f"[DEBUG] 메모리 참조 사용 발견: {hex(real_addr)} → {assignblk}")

                # ✅ 간접 JMP 명령어 탐지
                if "JMP" in str(assignblk):
                    jmp_target = list(assignblk.items())[0][1]
                    if isinstance(jmp_target, ExprInt) and int(jmp_target) == int(state_var):
                        state_var_uses.append(real_addr)
                        print(f"[DEBUG] JMP 대상에서 발견: {hex(real_addr)} → {assignblk}")

                # ✅ XOR, ADD, SUB 등 복합 연산 탐지
                if hasattr(assignblk, 'name') and assignblk.name in ["XOR", "ADD", "SUB"]:
                    if state_var_val in str(dst) or state_var_val in str(src):
                        state_var_uses.append(real_addr)
                        print(f"[DEBUG] 복합 연산 사용 발견: {hex(real_addr)} → {assignblk}")

    if not state_var_uses:
        print(f"[WARNING] state_var {state_var} 사용 주소를 찾지 못했습니다.")

    return state_var_uses





# mod_utils.py의 resolve_jump_target 함수 수정
def resolve_jump_target(asmcfg, loc_db, jmp_target):
    if isinstance(jmp_target, ExprId) and 'loc_key' in str(jmp_target):
        try:
            # 🔥 loc_key_* 숫자 추출
            target_offset = int(str(jmp_target).split('_')[-1])  
            
            # 🔥 loc_db에서 정확한 주소 찾기 시도
            loc_key = [key for key in loc_db.offsets if key.offset == target_offset]
            if loc_key:
                resolved_addr = loc_db.get_location_offset(loc_key[0])
                print(f"[DEBUG] loc_key 변환 성공: {jmp_target} → {hex(resolved_addr)}")
                return resolved_addr

            # 🔥 loc_db에 없으면 기본값 사용
            print(f"[WARNING] loc_db에 {jmp_target}가 없음, 기본값 사용")
            return target_offset

        except ValueError:
            print(f"[ERROR] loc_key 변환 실패: {jmp_target}")
            return None


        
    
    if isinstance(jmp_target, ExprId):
        print(f"[DEBUG] JMP 대상이 식별자: {jmp_target}")
        for block in asmcfg.blocks:
            for instr in block.lines:
                if instr.name == "MOV":
                    args = instr.get_args_expr()
                    if len(args) == 2 and args[0] == jmp_target:
                        if isinstance(args[1], ExprInt):
                            print(f"[DEBUG] loc_key 변환: {jmp_target} → {hex(args[1].arg)}")
                            return args[1].arg  # 실제 주소 반환
        return None

    # QWORD PTR [RIP + offset]과 같은 경우
    elif isinstance(jmp_target, ExprMem):
        if "RIP" in str(jmp_target):
            try:
                # RIP + offset 계산
                rip_offset = int(str(jmp_target).split("+")[1].split("]")[0], 16)

                # 🔥 수정된 부분: 딕셔너리가 아닌 리스트로 처리
                base_addresses = loc_db.offsets  # 이미 리스트 형태로 되어 있음

                if not base_addresses:
                    print(f"[ERROR] loc_db.offsets에 유효한 주소가 없습니다.")
                    return None

                rip_base = base_addresses[0]  # 첫 번째 유효 주소 사용
                resolved_addr = rip_base + rip_offset

                print(f"[DEBUG] RIP 기반 JMP 변환 성공: {jmp_target} → {hex(resolved_addr)}")
                return resolved_addr

            except (ValueError, IndexError, AttributeError) as e:
                print(f"[ERROR] RIP 기반 JMP 변환 실패: {e}")
                return None
            



#test1#