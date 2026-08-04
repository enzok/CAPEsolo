import hashlib
import importlib
import importlib.util
import json
import os
from contextlib import suppress
from pathlib import Path

import wx

from .theme import FONT_CODE, apply_theme
from CAPEsolo.capelib.path_utils import path_exists, path_mkdir

# Host-side only: a file handed back by a config parser via "dump_files". Deliberately
# outside the monitor's range so it can't collide with a code in cape\cape.h.
PARSER_EXTRACTED = 0x10000


def DumpParserFiles(cfg, analysisDir, newPayloads):
    """Write files handed back by a config parser into the CAPE folder.

    A parser only receives the file data, never the analysis paths, so it returns the raw
    bytes in "dump_files" and we do the writing. Each blob is named by its own sha256 and
    the bytes are replaced by that hash in the config, so a payload is never rendered into
    the results window or serialised into the JSON report.
    """
    dumped = {}
    capeDir = Path(analysisDir) / "CAPE"
    try:
        dumpFiles = cfg.get("dump_files") or {}
        if isinstance(dumpFiles, dict):
            dumpFiles = [dumpFiles]

        for entry in dumpFiles:
            for label, blob in entry.items():
                if not isinstance(blob, (bytes, bytearray)):
                    continue
                blob = bytes(blob)
                sha256 = hashlib.sha256(blob).hexdigest()
                dumped[label] = sha256
                destPath = capeDir / sha256
                # Content addressed, so an existing file is the same file. Skipping the
                # write also keeps re-extraction from duplicating the files.json entry
                # and the Payloads/Yara tab entries.
                if path_exists(str(destPath)):
                    continue

                if not path_exists(str(capeDir)):
                    path_mkdir(str(capeDir), exist_ok=True)
                destPath.write_bytes(blob)
                relPath = f"CAPE/{sha256}"
                metaEntry = {
                    "path": relPath,
                    "filepath": "",
                    "pids": [],
                    "ppids": [],
                    "metadata": f"{PARSER_EXTRACTED};?;?;?",
                    "category": "CAPE",
                }
                # Append-writes are atomic
                with open(Path(analysisDir) / "files.json", "a") as fh:
                    print(json.dumps(metaEntry, ensure_ascii=False), file=fh)
                newPayloads.append(relPath)
    except Exception as e:
        print(f"CAPE parser: Failed to write dumped file - {e}")
    finally:
        # Unconditional: a write failure or a malformed dump_files must not leave raw
        # bytes behind in the config.
        if dumped:
            cfg["dump_files"] = dumped
        else:
            cfg.pop("dump_files", None)

    return cfg


def PrintResults(cfg):
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


def Extract(configHits, analysisDir, jsonResults=False, newPayloads=None):
    content = ""
    configs = []
    if newPayloads is None:
        newPayloads = []
    CAPE_PARSERS = ("core", "community")
    customParsers = os.path.join(os.path.expanduser("~"), "Desktop", "custom")

    for hit in configHits:
        decoderModule = ""
        hitPath = list(hit.keys())[0]
        hitName = hit.get(hitPath, "")
        modPath = os.path.join(customParsers, f"{hitName}.py")

        for parser in CAPE_PARSERS:
            try:
                decoderModule = importlib.import_module(f"cape_parsers.CAPE.{parser}.{hitName}", __package__)
            except (ImportError, IndexError, AttributeError):
                continue
            except SyntaxError as e:
                print(f"CAPE parser: Fix your code in {parser}/{hitName} - {e}")
            except Exception as e:
                print(f"CAPE parser: Fix your code in {parser}/{hitName} - {e}")

        if not decoderModule:
            try:
                spec = importlib.util.spec_from_file_location(hitName, modPath)
                decoderModule = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(decoderModule)
            except (FileNotFoundError, ImportError, AttributeError):
                continue
            except SyntaxError as e:
                print(f"CAPE parser: Fix your code in {modPath} - {e}")
            except Exception as e:
                print(f"CAPE parser: Fix your code in {modPath} - {e}")

        if decoderModule:
            cfg = ""
            if analysisDir not in hitPath:
                hitPath = Path(analysisDir) / hitPath
            filedata = Path(hitPath).read_bytes()
            with suppress(Exception):
                if hasattr(decoderModule, "extract_config"):
                    cfg = decoderModule.extract_config(filedata)
                else:
                    cfg = decoderModule.config(filedata)
            if cfg:
                for entry in cfg if isinstance(cfg, list) else [cfg]:
                    if isinstance(entry, dict) and "dump_files" in entry:
                        DumpParserFiles(entry, analysisDir, newPayloads)

                if jsonResults:
                    configs.append({hitPath: cfg})

                content += f"\u2022 {hitPath}:\n\tFamily: {hitName}\n"
                content += PrintResults(cfg)
        else:
            content += f"\n{hitPath}: No parser for {hitName}"

    if jsonResults:
        return configs

    return content


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
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.EXPAND, size=wx.Size(-1, 100)
        )
        self.resultsWindow.SetFont(FONT_CODE)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)
        content = "Extract after Yara Processing."
        self.resultsWindow.SetValue(content)
        self.SetSizer(vbox)
        apply_theme(self)

    def ExtractConfigs(self, event):
        self.resultsWindow.SetValue("")
        newPayloads = []
        content = Extract(self.configHits, self.analysisDir, newPayloads=newPayloads)
        self.resultsWindow.SetValue(content)
        if newPayloads:
            self.UpdatePayloadPanels(newPayloads)

    def UpdatePayloadPanels(self, newPayloads):
        """Feed parser-dumped payloads to the Payloads and Yara tabs.

        Both tabs load once and have already run by the time configs can be extracted, so
        they are updated in place rather than reloaded. Any CAPE name the new yara hits
        produce is appended to configHits, so re-running the extraction picks it up.
        """
        frame = self.GetMainFrame()
        payloadsTab = getattr(frame, "payloadsTab", None)
        yaraTab = getattr(frame, "yaraTab", None)
        for relPath in newPayloads:
            if payloadsTab:
                payloadsTab.AddPayload(relPath)
            if yaraTab:
                yaraTab.AddPayload(relPath)

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()

        return parent

    def UpdateConfigsButtonState(self):
        if self.configHits:
            self.configsButton.Enable()
        else:
            self.configsButton.Disable()
