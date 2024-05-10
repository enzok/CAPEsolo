from __future__ import absolute_import
import os
import logging
from time import sleep

from lib.api.process import Process
from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)


class POSFaker(Auxiliary):
    """ Start a process to generate track 1 or 2 data in supplied process
        Make sure gencc.exe is included in the analyzer bin directory
        https://github.com/bizdak/ccgen
    """

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = True

    def start(self):
        if not self.enabled:
            return True

        try:
            posproc = self.options.get("posproc", None)
            if not posproc:
                return True

            pospath = os.path.join(os.getcwd(), "bin", "ccgen.exe")
            if not os.path.exists(pospath):
                log.info("Skipping POSFaker, ccgen.exe was not found in bin/")
                return True

            posname = self.options.get("posname")

            if posname:
                newpath = os.path.join(os.getcwd(), "bin", posname)
                os.rename(pospath, newpath)
                pospath = newpath
                sleep(1)

            pos = Process()
            pos.execute(path=pospath, suspended=False)
            sleep(5)

        except Exception:
            import traceback

            log.exception(traceback.format_exc())

        return True
