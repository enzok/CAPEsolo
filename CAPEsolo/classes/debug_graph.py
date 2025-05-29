import shutil
from pathlib import Path
import html
import graphviz

from .web_server import LocalWebServer

HAS_GRAPHVIZ = shutil.which("dot") is not None

BRANCH_MNEMONICS = {
    "jmp",
    "je",
    "jz",
    "jne",
    "jnz",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "jcxz",
    "jecxz",
    "jo",
    "jno",
    "js",
    "jns",
    "jp",
    "jpe",
    "jnp",
    "jpo",
    "jg",
    "jge",
    "jl",
    "jle",
    "ret",
    "retn",
}

NON_CONTROL_MNEMONICS = {
    "nop",
    "db",
    "mov",
    "add",
    "sub",
    "xor",
    "and",
    "or",
    "cmp",
    "lea",
    "push",
    "pop",
    "inc",
    "dec",
    "test",
    "shr",
    "shl",
    "sal",
    "sar",
    "imul",
    "idiv",
    "not",
    "neg",
    "xchg",
    "mul",
}


class BasicBlock:
    def __init__(self, startAddr):
        self.startAddr = startAddr
        self.instructions = []
        self.endAddr = None
        self.targets = []

    def AddInstruction(self, instr):
        self.instructions.append(instr)
        self.endAddr = instr[0]

    def AddTarget(self, targetAddr):
        if targetAddr not in self.targets:
            self.targets.append(targetAddr)


class CfgBuilder:
    def __init__(self, instructions):
        self.instructions = instructions
        self.blocks = {}
        self.entryPoint = instructions[0][0] if instructions else None

    def BuildBlocks(self):
        addrToInstr = {addr: (addr, hexBytes, text) for addr, hexBytes, text in self.instructions}
        leaders = set([self.entryPoint])

        for i, (addr, _, text) in enumerate(self.instructions):
            parts = text.split()
            mnemonic = parts[0].lower() if parts else ""
            if mnemonic in BRANCH_MNEMONICS:
                if mnemonic not in {"ret", "retn"} and len(parts) > 1:
                    try:
                        target = int(parts[1], 16)
                        leaders.add(target)
                    except ValueError:
                        pass

                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1][0])

        sortedAddrs = sorted(addrToInstr.keys())
        currentBlock = None

        for addr in sortedAddrs:
            if addr in leaders:
                if currentBlock:
                    self.blocks[currentBlock.startAddr] = currentBlock
                currentBlock = BasicBlock(addr)

            instr = addrToInstr[addr]
            parts = instr[2].split()
            mnemonic = parts[0].lower() if parts else ""
            currentBlock.AddInstruction(instr)

            if mnemonic in BRANCH_MNEMONICS:
                if mnemonic not in {"ret", "retn"} and len(parts) > 1:
                    try:
                        target = int(parts[1], 16)
                        currentBlock.AddTarget(target)
                    except ValueError:
                        pass

                if mnemonic not in {"jmp", "ret", "retn"}:
                    nextIndex = self.instructions.index(instr) + 1
                    if nextIndex < len(self.instructions):
                        currentBlock.AddTarget(self.instructions[nextIndex][0])
                self.blocks[currentBlock.startAddr] = currentBlock
                currentBlock = None

        if currentBlock:
            self.blocks[currentBlock.startAddr] = currentBlock

    def RenderGraph(self):
        basePath = Path(__file__).resolve().parent.parent / "graph"
        outputPath = basePath / "x64dbgCfgEmulation"

        dot = graphviz.Digraph(
            comment="Control Flow Graph",
            format="svg",
            engine="dot",
            graph_attr={"rankdir": "TB", "splines": "ortho", "nodesep": "1.2", "ranksep": "1.2", "pad": "0.4", "dpi": "300"},
            node_attr={
                "fontsize": "20",
                "fontname": "monospace",
                "shape": "box",
                "style": "rounded,filled",
                "fillcolor": "#ffffff",
                "color": "#000000",
                "fontcolor": "#000000",
                "penwidth": "1.2",
                "margin": "0.2,0.1",
            },
            edge_attr={
                "fontsize": "14",
                "fontcolor": "#000000",
                "color": "gray",
                "arrowsize": "0.6",
                "penwidth": "1.0",
            },
        )

        for block in self.blocks.values():
            label_lines = [f"{addr:08x}: {html.escape(text)}" for addr, _, text in block.instructions]
            label = r"\l".join(label_lines) + r"\l"
            node_id = f"n_{block.startAddr:08x}"
            dot.node(node_id, label=label)

        for block in self.blocks.values():
            lastInstr = block.instructions[-1] if block.instructions else None
            if not lastInstr:
                continue

            addr, _, text = lastInstr
            parts = text.split()
            mnemonic = parts[0].lower() if parts else ""
            hasTarget = len(parts) > 1 and parts[1].startswith("0x")
            jumpTarget = int(parts[1], 16) if hasTarget else None
            idx = self.instructions.index(lastInstr)
            fallThrough = self.instructions[idx + 1][0] if idx + 1 < len(self.instructions) else None

            for target in block.targets:
                fromID = f"n_{block.startAddr:08x}"
                toId = f"n_{target:08x}"
                isLoop = target <= block.startAddr
                if isLoop:
                    edgeAttrs = {"arrowhead": "normal", "constraint": "false", "color": "blue", "minlen": "3"}
                    dot.edge(fromID, toId, **edgeAttrs)
                    continue
                else:
                    edgeAttrs = {"arrowhead": "normal", "constraint": "true", "color": "black"}
                    if mnemonic == "jmp":
                        edgeAttrs["color"] = "black"
                    elif mnemonic in BRANCH_MNEMONICS:
                        if target == jumpTarget:
                            edgeAttrs["color"] = "green"
                        else:
                            edgeAttrs["color"] = "red"
                    elif target == fallThrough:
                        edgeAttrs["color"] = "black"

                    dot.edge(fromID, toId, **edgeAttrs)

        dot.render(str(outputPath), view=False)
        return

    def ShowFlowGraph(self):
        self.RenderGraph()
        serverPath = Path(__file__).resolve().parent.parent / "graph"
        server = LocalWebServer(serverPath)
        if not server.IsRunning():
            server.Start()

        server.OpenBrowser()
