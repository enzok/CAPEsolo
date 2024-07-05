import glob
import importlib
import os
from pathlib import Path

import wx


class ConfigsPanel(wx.Panel):
    def __init__(self, parent):
        super(ConfigsPanel, self).__init__(parent)
        self.configHits = parent.configHits
        self.analysisDir = parent.analysisDir
        self.capesoloRoot = parent.capesoloRoot
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.configsButton = wx.Button(self, label="Extract Configs")
        self.configsButton.Bind(wx.EVT_BUTTON, self.ExtractConfigs)
        self.configsButton.Disable()
        vbox.Add(self.configsButton, proportion=0, border=5)
        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.EXPAND, size=(-1, 100)
        )
        fontCourier = wx.Font(
            10, wx.FONTFAMILY_MODERN, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL
        )
        self.resultsWindow.SetFont(fontCourier)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)
        content = "Extract after viewing Payloads and Yara Processing."
        self.resultsWindow.SetValue(content)
        self.SetSizer(vbox)

    def PrintResults(self, cfg):
        content = ""
        if isinstance(cfg, list):
            for key, value in cfg[0].items():
                if isinstance(value, map):
                    value = list(value)
                content += f"\t{key}: {value}\n"
        elif isinstance(cfg, dict):
            for key, value in cfg.items():
                if isinstance(value, map):
                    value = list(value)
                content += f"\t{key}: {value}\n"
        return content

    def ExtractConfigs(self, event):
        content = ""
        self.resultsWindow.SetValue("")

        for hit in self.configHits:
            decoderModule = ""
            hitPath = list(hit.keys())[0]
            hitName = hit.get(hitPath, "")
            path = os.path.join(self.capesoloRoot, "parsers")
            decoders = [
                os.path.basename(decoder)[:-3]
                for decoder in glob.glob(f"{path}/[!_]*.py")
            ]
            for decoder in decoders:
                if hitName == decoder:
                    try:
                        decoderModule = importlib.import_module(
                            f"parsers.{decoder}", __package__
                        )
                        break
                    except Exception as e:
                        content += f"\n{path}: Fix parser code in {decoder}, {e}"
            if decoderModule:
                if self.analysisDir not in hitPath:
                    hitPath = Path(self.analysisDir) / hitPath
                filedata = Path(hitPath).read_bytes()
                if hasattr(decoderModule, "extract_config"):
                    cfg = decoderModule.extract_config(filedata)
                else:
                    cfg = decoderModule.config(filedata)
                if cfg:
                    content += f"\u2022 {hitPath}:\n\tFamily: {hitName}\n"
                    content += self.PrintResults(cfg)
            else:
                content += f"\n{hitPath}: No parser for {hitName}"

        self.resultsWindow.SetValue(content)

    def UpdateConfigsButtonState(self):
        if self.configHits:
            self.configsButton.Enable()
        else:
            self.configsButton.Disable()
