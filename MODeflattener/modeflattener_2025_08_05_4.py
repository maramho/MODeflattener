from future.utils import viewitems, viewvalues
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.analysis.simplifier import *
from miasm.expression.expression import *
from miasm.core.asmblock import *
from miasm.arch.x86.arch import mn_x86
from miasm.core.utils import encode_hex

from argparse import ArgumentParser
import time
import logging
import pprint

from mod_utils import *

class PatchNop:
    def __init__(self, offset, size):
        self.offset = offset
        self.data = b'\x90' * size  # NOP opcode (0x90) * size

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
    relevant_blocks, dispatcher, pre_dispatcher = get_cff_info(main_asmcfg, dispatcher=addr)

    patches = []
    visited = set()
    for bb_addr in relevant_blocks:
        if bb_addr in visited:
            continue
        visited.add(bb_addr)

        block = main_asmcfg.getby_offset(bb_addr)
        instrs = block.lines

        print(f"\n[+] Original BB at {hex(bb_addr)}:")
        for instr in instrs:
            print(f"    {instr}")

        # ✅ dispatcher로 jump하는 마지막 JMP 제거
        last_instr = instrs[-1]
        if last_instr.name.lower() == "jmp":
            print(f"[INFO] Removing dispatcher jump at {hex(last_instr.offset)}")
            patches.append(PatchNop(last_instr.offset, last_instr.l))  # ✅ 수정된 부분

        # ✅ dispatcher state 설정 mov 제거 (0x34(%rsp) or -0x2C(%rbp))
        for instr in instrs:
            if instr.name == "mov" and len(instr.args) == 2:
                dst, src = instr.args
                if isinstance(dst, ExprMem) and dst.arg.op == "+":
                    offset_val = dst.arg.args[1].arg
                    if offset_val == 0x34 or offset_val == -0x2C:
                        print(f"[INFO] Removing state set instr at {hex(instr.offset)}")
                        patches.append(PatchNop(instr.offset, instr.l))  # ✅ 수정된 부분

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