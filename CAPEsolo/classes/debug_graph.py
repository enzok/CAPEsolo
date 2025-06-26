import html
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import graphviz
import wx
from wx.svg import SVGimage

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
    "int3",
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
        leaders = {self.entryPoint}

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
            graph_attr={
                "rankdir": "TB",
                "splines": "ortho",
                "nodesep": "1.2",
                "ranksep": "1.2",
                "pad": "0.4",
                "dpi": "300",
                "bgcolor": "lightgray",
            },
            node_attr={
                "fontsize": "20",
                "fontname": "monospace",
                "shape": "box",
                "style": "rounded,filled",
                "fillcolor": "#ffffff",
                "fontcolor": "#000000",
                "color": "#000000",
                "penwidth": "1.2",
                "margin": "0.2,0.1",
            },
            edge_attr={
                "fontsize": "14",
                "color": "gray",
                "fontcolor": "#000000",
                "arrowsize": "0.6",
                "penwidth": "1.0",
            },
        )

        for block in self.blocks.values():
            label_lines = [f"{addr:08x}: {html.escape(text)}" for addr, _, text in block.instructions]
            label = r"\l".join(label_lines) + r"\l"
            node_id = f"{block.startAddr:08x}"
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
            row = self.instructions.index(lastInstr)
            fallThrough = self.instructions[row + 1][0] if row + 1 < len(self.instructions) else None

            for target in block.targets:
                fromID = f"{block.startAddr:08x}"
                toId = f"{target:08x}"
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


class SvgFrame(wx.Frame):
    def __init__(self, target=None):
        super().__init__(None, title="Disassembly Graph", size=(800, 800))
        panel = wx.Panel(self)
        self.resizeTimer = None

        svgPath = Path(__file__).resolve().parent.parent / "graph" / "x64dbgCfgEmulation.svg"
        svgImage = SVGimage.CreateFromFile(str(svgPath))

        class SvgPanel(wx.Panel):
            def __init__(self, parent, svgImage: SVGimage, svgPath: str, focusText: str = None, onViewChanged=None):
                super().__init__(parent)
                self.svgImage = svgImage
                self.svgPath = svgPath
                self.onViewChanged = onViewChanged
                self.focusText = (focusText or "").lower()
                self.targetCenter = None
                self.targetFontPx = None
                self.matchedNode = None
                if self.focusText:
                    self.FindTextCenter()

                self.currentScale = 1.0
                self.panX = 0.0
                self.panY = 0.0
                self.isFirstLayout = True
                self.isPanning = False
                self.panStartMouse = (0, 0)
                self.panStartOffset = (0.0, 0.0)
                self.resetScale = 1.0
                self.resetTranslateX = 0.0
                self.resetTranslateY = 0.0

                self.Bind(wx.EVT_PAINT, self.OnPaint)
                self.Bind(wx.EVT_MOUSEWHEEL, self.OnMouseWheel)
                self.Bind(wx.EVT_LEFT_DOWN, self.OnLeftDown)
                self.Bind(wx.EVT_MOTION, self.OnMouseMotion)
                self.Bind(wx.EVT_LEFT_UP, self.OnLeftUp)

            def FindTextCenter(self):
                try:
                    tree = ET.parse(self.svgPath)
                    root = tree.getroot()
                    for node in root.iter():
                        tag = node.tag
                        if "}" in tag:
                            tag = tag.split("}", 1)[1]

                        if tag.lower() == "text":
                            textContent = "".join(node.itertext()).strip().lower()
                            if self.focusText in textContent:
                                self.matchedNode = node
                                xAttr = node.get("x")
                                yAttr = node.get("y")
                                if xAttr is not None and yAttr is not None:
                                    try:
                                        cx = float(xAttr)
                                        cy = float(yAttr)
                                    except:
                                        cx = cy = None
                                else:
                                    cx = cy = None

                                fs = node.get("font-size", "")
                                fontPx = None
                                if fs.endswith("pt"):
                                    try:
                                        ptVal = float(fs[:-2])
                                        fontPx = ptVal * (96.0 / 72.0)
                                    except:
                                        fontPx = None
                                elif fs.endswith("px"):
                                    try:
                                        fontPx = float(fs[:-2])
                                    except:
                                        fontPx = None

                                self.targetFontPx = fontPx
                                self.targetCenter = (cx, cy)
                                break
                except Exception as e:
                    print(f"Error parsing SVG for focus text: {e}")
                    self.matchedNode = None

            def OnPaint(self, event):
                dc = wx.PaintDC(self)
                gc = wx.GraphicsContext.Create(dc)
                panelW, panelH = self.GetClientSize()
                svgW = self.svgImage.width
                svgH = self.svgImage.height
                if self.isFirstLayout:
                    if svgW > 0 and svgH > 0:
                        padding_ratio = 0.9
                        scaleX = panelW / svgW
                        scaleY = panelH / svgH
                        baseScale = min(scaleX, scaleY) * padding_ratio
                    else:
                        baseScale = 1.0

                    self.currentScale = baseScale
                    self.panX = (panelW - svgW * baseScale) / 2
                    self.panY = (panelH - svgH * baseScale) / 2
                    self.resetScale = self.currentScale
                    self.resetTranslateX = self.panX / self.currentScale
                    self.resetTranslateY = self.panY / self.currentScale
                    self.isFirstLayout = False

                gc.Scale(self.currentScale, self.currentScale)
                gc.Translate(self.panX / self.currentScale, self.panY / self.currentScale)
                self.svgImage.RenderToGC(gc)

                if self.onViewChanged:
                    self.onViewChanged()

            def OnMouseWheel(self, event):
                rotation = event.GetWheelRotation()
                zoomFactor = 1.2 if rotation > 0 else 1 / 1.2
                mx, my = event.GetPosition()
                svgX = (mx - self.panX) / self.currentScale
                svgY = (my - self.panY) / self.currentScale
                newScale = max(0.05, min(self.currentScale * zoomFactor, 20))
                self.currentScale = newScale
                self.panX = mx - svgX * self.currentScale
                self.panY = my - svgY * self.currentScale
                self.Refresh()
                if self.onViewChanged:
                    self.onViewChanged()

            def OnLeftDown(self, event):
                self.isPanning = True
                self.panStartMouse = event.GetPosition()
                self.panStartOffset = (self.panX, self.panY)
                self.CaptureMouse()

            def OnMouseMotion(self, event):
                if self.isPanning and event.Dragging() and event.LeftIsDown():
                    mx, my = event.GetPosition()
                    startMx, startMy = self.panStartMouse
                    dx = mx - startMx
                    dy = my - startMy
                    self.panX = self.panStartOffset[0] + dx
                    self.panY = self.panStartOffset[1] + dy
                    self.Refresh()
                    if self.onViewChanged:
                        self.onViewChanged()

            def OnLeftUp(self, event):
                if self.isPanning:
                    self.isPanning = False
                    if self.HasCapture():
                        self.ReleaseMouse()

            def ResetView(self):
                panelW, panelH = self.GetClientSize()
                svgW = self.svgImage.width
                svgH = self.svgImage.height

                if svgW > 0 and svgH > 0:
                    padding_ratio = 0.9
                    scaleX = panelW / svgW
                    scaleY = panelH / svgH
                    baseScale = min(scaleX, scaleY) * padding_ratio
                else:
                    baseScale = 1.0

                self.currentScale = baseScale
                self.panX = (panelW - svgW * baseScale) / 2
                self.panY = (panelH - svgH * baseScale) / 2
                self.resetScale = self.currentScale
                self.resetTranslateX = self.panX / self.currentScale
                self.resetTranslateY = self.panY / self.currentScale
                self.Refresh()
                if self.onViewChanged:
                    self.onViewChanged()

        def getMainParams():
            return svgPanel.currentScale, svgPanel.panX, svgPanel.panY, svgPanel.GetSize().width, svgPanel.GetSize().height

        def setMainViewFromOverview(centerX, centerY):
            panelW, panelH = svgPanel.GetSize()
            svgPanel.panX = (panelW / 2) - (centerX * svgPanel.currentScale)
            svgPanel.panY = (panelH / 2) - (centerY * svgPanel.currentScale)
            svgPanel.Refresh()

        svgPanel = SvgPanel(panel, svgImage, str(svgPath), target, onViewChanged=lambda: overview.Refresh())
        overview = OverviewPanel(panel, svgImage, getMainParams, setMainViewFromOverview)

        hSizer = wx.BoxSizer(wx.HORIZONTAL)
        vSizer = wx.BoxSizer(wx.VERTICAL)
        vSizer.Add(svgPanel, 1, wx.EXPAND)
        resetBtn = wx.Button(panel, label="Reset View")
        vSizer.Add(resetBtn, 0, wx.ALL | wx.ALIGN_LEFT, 5)
        resetBtn.Bind(wx.EVT_BUTTON, lambda event: svgPanel.ResetView())
        hSizer.Add(vSizer, 1, wx.EXPAND)
        hSizer.Add(overview, 0, wx.ALL, 5)

        panel.SetSizer(hSizer)
        self.Bind(wx.EVT_SIZE, self.OnDebouncedResize)
        self.Show()

    def OnDebouncedResize(self, event):
        event.Skip()
        if self.resizeTimer:
            self.resizeTimer.Stop()
        self.resizeTimer = wx.CallLater(300, self.DoResize)

    def DoResize(self):
        children = self.GetChildren()
        for child in children:
            if isinstance(child, wx.Panel):
                for sub in child.GetChildren():
                    if hasattr(sub, 'ResetView'):
                        sub.ResetView()
                    if hasattr(sub, 'Refresh'):
                        sub.Refresh()


class OverviewPanel(wx.Panel):
    def __init__(self, parent, svgImage, getMainViewParams, setMainViewFromOverview):
        super().__init__(parent, size=(200, 200))
        self.svgImage = svgImage
        self.getMainViewParams = getMainViewParams
        self.setMainViewFromOverview = setMainViewFromOverview

        self.Bind(wx.EVT_PAINT, self.OnPaint)
        self.Bind(wx.EVT_LEFT_DOWN, self.OnLeftDown)
        self.Bind(wx.EVT_MOTION, self.OnMouseMove)
        self.Bind(wx.EVT_LEFT_UP, self.OnLeftUp)

        self.dragging = False

    def OnPaint(self, event):
        dc = wx.PaintDC(self)
        gc = wx.GraphicsContext.Create(dc)
        panelW, panelH = self.GetSize()
        svgW = self.svgImage.width
        svgH = self.svgImage.height

        if svgW == 0 or svgH == 0:
            return

        scale = min(panelW / svgW, panelH / svgH)
        offsetX = (panelW - svgW * scale) / 2
        offsetY = (panelH - svgH * scale) / 2
        gc.Translate(offsetX, offsetY)
        gc.Scale(scale, scale)
        self.svgImage.RenderToGC(gc)
        currentScale, panX, panY, panelW_main, panelH_main = self.getMainViewParams()
        viewX = -panX / currentScale
        viewY = -panY / currentScale
        viewW = panelW_main / currentScale
        viewH = panelH_main / currentScale
        gc.SetPen(wx.Pen("red", 1))
        gc.SetBrush(wx.Brush(wx.Colour(255, 0, 0, 50)))  # translucent red
        gc.ResetTransform()
        gc.Translate(offsetX, offsetY)
        gc.Scale(scale, scale)
        gc.DrawRectangle(viewX, viewY, viewW, viewH)
        self.overviewScale = scale
        self.overviewOffset = (offsetX, offsetY)

    def OnLeftDown(self, event):
        self.dragging = True
        self.MoveMainViewToMouse(event.GetPosition())

    def OnMouseMove(self, event):
        if self.dragging and event.Dragging() and event.LeftIsDown():
            self.MoveMainViewToMouse(event.GetPosition())

    def OnLeftUp(self, event):
        self.dragging = False

    def MoveMainViewToMouse(self, pos):
        mouseX, mouseY = pos
        ox, oy = self.overviewOffset
        scale = self.overviewScale
        svgX = (mouseX - ox) / scale
        svgY = (mouseY - oy) / scale
        self.setMainViewFromOverview(svgX, svgY)
