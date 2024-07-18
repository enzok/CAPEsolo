import os

from CAPEsolo.capelib.utils import LoadFilesJson
from CAPEsolo.capelib.yaralib import YaraProcessor


class ProcessYara:
    def __init__(self, analysisDir):
        self.yara = YaraProcessor()
        self.yara.init_yara()
        self.yara_results = []
        self.analysisDir = analysisDir

    def Scan(self, target):
        hits = {}
        hits[target] = self.yara.get_yara(target)
        self.yara_results.append({target: hits[target]})

    def ScanPayloads(self):
        hits = {}
        content = LoadFilesJson(self.analysisDir)
        if "error" not in content.keys():
            for file in content.keys():
                if content[file].get("category", "") in ("files", "CAPE", "procdump"):
                    path = os.path.join(self.analysisDir, file)
                    hits[file] = self.yara.get_yara(path)
                    self.yara_results.append({file: hits[file]})
