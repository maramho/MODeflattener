import graphviz

import re
from miasm.analysis.machine import Machine
from miasm.arch.x86.arch import mn_x86
from miasm.core import parse_asm
from miasm.core import asmblock
from miasm.arch.x86.lifter_model_call import LifterModelCall_x86_32
from miasm.core.locationdb import LocationDB
from miasm.loader.strpatchwork import StrPatchwork
from miasm.analysis.binary import Container
from miasm.ir.ir import IRCFG
from miasm.ir.ir import _expr_loc_to_symb
import logging

# Quiet warnings
asmblock.log_asmblock.setLevel(logging.ERROR)

class IRCfgGraphviz(IRCFG):

    def node2lines(self, node):
        node_name = self.loc_db.pretty_str(node)
        yield self.DotCellDescription(
            text="%s" % node_name,
            attr={
                'align': 'center',
                'colspan': 2,
                'bgcolor': 'grey',
            }
        )
        if node not in self._blocks:
            yield [self.DotCellDescription(text="NOT PRESENT", attr={'bgcolor': 'red'})]
            return
        for i, assignblk in enumerate(self._blocks[node]):
            for dst, src in assignblk.items():

                new_src = src.visit(lambda expr:_expr_loc_to_symb(expr, self.loc_db))
                new_dst = dst.visit(lambda expr:_expr_loc_to_symb(expr, self.loc_db))
                line = "%s = %s" % (new_dst, new_src)
                if self._dot_offset:
                    yield [self.DotCellDescription(text="%-4d" % i, attr={}),
                           self.DotCellDescription(text=line, attr={})]
                else:
                    yield self.DotCellDescription(text=line, attr={})
            yield self.DotCellDescription(text="", attr={})

    @classmethod
    def from_ircfg(cls, ircfg):
        new_ircfg = IRCfgGraphviz(ircfg.IRDst, ircfg.loc_db, blocks=ircfg.blocks)
        for node in ircfg.nodes():
            new_ircfg.add_node(node)
        for src, dst in ircfg.edges():
            new_ircfg.add_uniq_edge(src, dst)
        return new_ircfg

    def graphviz(self):
        self.gv = graphviz.Digraph('html_table')
        self._dot_offset = False
        escape_chars = re.compile('[' + re.escape('{}') + '&|<>' + ']')
        td_attr = {'align': 'left'}
        nodes_attr = {'shape': 'Mrecord',
                      'fontname': 'Courier New'}

        for node in self.nodes():
            elements = [x for x in self.node2lines(node)]
            node_id = self.nodeid(node)
            out_node = '<<table border="0" cellborder="0" cellpadding="3">'

            node_html_lines = []
            for lineDesc in elements:
                out_render = ""
                if isinstance(lineDesc, self.DotCellDescription):
                    lineDesc = [lineDesc]
                for col in lineDesc:
                    out_render += "<td %s>%s</td>" % (
                        self._attr2str(td_attr, col.attr),
                        escape_chars.sub(self._fix_chars, str(col.text)))
                node_html_lines.append(out_render)

            node_html_lines = ('<tr>' +
                               ('</tr><tr>').join(node_html_lines) +
                               '</tr>')

            out_node += node_html_lines + "</table>>"
            self.gv.node(
                "%s" % node_id,
                label=out_node,
                shape="Mrecord"
            )


        for src, dst in self.edges():
            attrs = self.edge_attr(src, dst)
            self.gv.edge(
                str(self.nodeid(src)),
                str(self.nodeid(dst)),
                "",
                attrs,
            )

        return self.gv



def graph_x86_asm(asm, lifter_model_call=False):
    # First, asm code
    machine = Machine("x86_32")

    code = asm + "\nend:\n"
    loc_db = LocationDB()
    asmcfg = parse_asm.parse_txt(
        mn_x86, 32, code,
        loc_db
    )
    virt = StrPatchwork()
    loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)
    patches = asmblock.asm_resolve_final(
        machine.mn,
        asmcfg,
    )
    for offset, raw in patches.items():
        virt[offset] = raw
    data = bytes(virt)
    cont = Container.fallback_container(
        data,
        vm=None, addr=0,
        loc_db=loc_db,
    )
    dis_engine = machine.dis_engine
    mdis = dis_engine(cont.bin_stream, loc_db=cont.loc_db)

    asmcfg = mdis.dis_multiblock(0)

    # Translate to IR
    if lifter_model_call:
        lifter = LifterModelCall_x86_32(loc_db)
    else:
        lifter = machine.ir(loc_db)

    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
    new_ircfg = IRCfgGraphviz.from_ircfg(ircfg)
    return new_ircfg.graphviz()
