import io
import shutil

import graphviz
import wx

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
    "call",
    "ret",
    "retn",
}

HAS_GRAPHVIZ = shutil.which("dot") is not None


class FlowGraphDialog(wx.Dialog):
    def __init__(self, parent, instructions):
        """Generate a flowchart using graphviz and display it in a scrollable dialog."""
        busy = wx.BusyInfo("Generating graph, please wait...", parent)
        wx.YieldIfNeeded()
        try:
            style = wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER
            super().__init__(parent, title="Flow Graph", size=wx.Size(600, 800), style=style)

            basicBlocks = []
            addressToBlock = {}
            currentBlock = []
            for instr in instructions:
                currentBlock.append(instr)
                mnem = instr.text.split()[0].lower()
                if mnem in BRANCH_MNEMONICS:
                    idx = len(basicBlocks)
                    basicBlocks.append(currentBlock)
                    addressToBlock[currentBlock[0].address] = idx
                    currentBlock = []
            if currentBlock:
                idx = len(basicBlocks)
                basicBlocks.append(currentBlock)
                addressToBlock[currentBlock[0].address] = idx

            dot = graphviz.Digraph(format='png')
            dot.attr('graph', rankdir='TB', splines='ortho', nodesep='0.3', ranksep='0.5', overlap='false')
            dot.attr('node', shape='box', style='rounded', fontname='Courier', fontsize='8', margin='0.1,0.05')
            dot.attr('edge', arrowsize='0.6')

            for i, block in enumerate(basicBlocks):
                label = "\l".join(f"{instr.address:08X}  {instr.text}" for instr in block) + "\l"
                dot.node(f"B{i}", label=label)

            for i, block in enumerate(basicBlocks):
                src = f"B{i}"
                if i + 1 < len(basicBlocks):
                    dot.edge(src, f"B{i + 1}")
                lastText = block[-1].text.split()
                mnem = lastText[0].lower()
                if mnem in BRANCH_MNEMONICS and len(lastText) > 1:
                    try:
                        tgt = int(lastText[-1], 16)
                        j = addressToBlock.get(tgt)
                        if j is not None:
                            dot.edge(src, f"B{j}", color='blue')
                    except ValueError:
                        pass

            try:
                pngData = dot.pipe()
            except graphviz.backend.ExecutableNotFound:
                wx.MessageBox(
                    "Graphviz executable not found. Please install Graphviz from https://graphviz.org/download/",
                    "Error",
                    wx.OK | wx.ICON_ERROR
                )
                self.Destroy()
                return

        finally:
            del busy

        stream = io.BytesIO(pngData)
        # noinspection PyTypeChecker
        image = wx.Image(stream, wx.BITMAP_TYPE_PNG)
        bitmap = wx.Bitmap(image)

        panel = wx.ScrolledWindow(self)
        panel.SetScrollRate(20, 20)
        panel.SetVirtualSize(bitmap.GetSize())

        staticBmp = wx.StaticBitmap(panel, wx.ID_ANY, wx.BitmapBundle.FromBitmap(bitmap))
        panelSizer = wx.BoxSizer(wx.VERTICAL)
        panelSizer.Add(staticBmp, 1, wx.EXPAND)
        panel.SetSizer(panelSizer)

        mainSizer = wx.BoxSizer(wx.VERTICAL)
        mainSizer.Add(panel, 1, wx.EXPAND | wx.ALL, 10)
        self.SetSizer(mainSizer)
        self.Layout()
