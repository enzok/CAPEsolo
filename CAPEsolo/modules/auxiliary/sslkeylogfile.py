import logging
import os
import tempfile

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

SSLKEYLOGFILE = "SSLKEYLOGFILE"


class SslKeyLogFile(Auxiliary):
    """Collect SSLKEYLOGFILE logs from guests.

    For Schannel (Windows native TLS) key capture, the registry key
    HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyLogging
    must have Enable=1 (REG_DWORD). This requires a reboot to take effect, so
    it should be baked into the VM snapshot — not set at runtime.
    This module handles setting the SSLKEYLOGFILE path at analysis start.
    """

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.sslkeylogfile
        if self.enabled:
            self.upload_prefix = "aux/sslkeylogfile"
            self.upload_file = "sslkeys.log"
            self.log_path = ""

    def upload_sslkeylogfile(self):
        """Upload SSLKEYLOGFILE log to the host if present."""
        try:
            if not self.log_path or not os.path.isfile(self.log_path):
                log.info("SSLKEYLOGFILE was never created at '%s'", self.log_path)
                return

            # upload_to_host skips a zero byte file without uploading anything, and this used
            # to log "uploaded" straight afterwards regardless - so an empty key log looked
            # like a successful upload and the missing file on the host had no explanation.
            # Empty is the normal outcome when nothing in the guest honoured the variable.
            size = os.path.getsize(self.log_path)
            if not size:
                log.warning(
                    "SSLKEYLOGFILE at '%s' is empty - nothing in the guest wrote TLS secrets "
                    "to it, so there is nothing to upload",
                    self.log_path,
                )
                return

            log.debug('Attemping to upload SSLKEYLOGFILE from "%s"', self.log_path)
            upload_to_host(self.log_path, f"{self.upload_prefix}/{self.upload_file}")
            log.info("SSLKEYLOGFILE uploaded (%d bytes)", size)
        except Exception:
            log.exception("SslKeyLogFile encountered an exception while uploading '%s'", self.log_path)
            raise

    def start(self):
        if not self.enabled:
            log.debug("SslKeyLogFile auxiliary module not enabled")
            return
        log.info("SslKeyLogFile auxiliary module enabled")
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as keylog:
            # Set SSLKEYLOGFILE system environment variable
            log.info("Setting %s to %s", SSLKEYLOGFILE, keylog.name)
            # Set system env
            xcode = os.system("Setx {0} {1} /m".format(SSLKEYLOGFILE, keylog.name))
            # Update local process env
            os.environ[SSLKEYLOGFILE] = keylog.name

            if xcode != 0:
                log.info("Failed to set %s", SSLKEYLOGFILE)

            self.log_path = keylog.name

    def finish(self):
        if self.enabled:
            self.upload_sslkeylogfile()
