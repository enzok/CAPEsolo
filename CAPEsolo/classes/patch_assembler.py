import logging

import keystone as ks

from .patch_models import PatchEntry

log = logging.getLogger(__name__)


class Assembler:
    def __init__(self, bitMode: int = 64):
        engineMode = ks.KS_MODE_64 if bitMode == 64 else ks.KS_MODE_32
        self.ksEngine = ks.Ks(ks.KS_ARCH_X86, engineMode)

    def AssembleAt(self, asmText: str, baseAddress: int = 0) -> tuple[str, list[PatchEntry]]:
        hexString = ""
        currentAddr = baseAddress
        entries: list[PatchEntry] = []

        for lineNumber, rawLine in enumerate(asmText.splitlines(), start=1):
            line = rawLine.split(";", 1)[0].strip()
            if not line:
                continue

            try:
                encoding, _ = self.ksEngine.asm(line, currentAddr)
            except ks.KsError as e:
                errorMsg = f"Assembly error on line {lineNumber}: {line} - {e}"
                log.error(errorMsg)
                return errorMsg, []

            instrHex = bytes(encoding).hex().upper()
            entry = PatchEntry(address=currentAddr, originalBytes="", patchedBytes=instrHex, instruction=line)
            entries.append(entry)

            hexString += instrHex
            currentAddr += len(instrHex) // 2

        return hexString, entries
