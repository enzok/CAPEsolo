import logging

log = logging.getLogger(__name__)

TIMEOUT = 6000


class CommandPipeHandler:
    """Handles messages received on the command pipe from the debug server."""

    def __init__(self, console):
        self.console = console
        self.connected = False

    def _handle_break(self, data):
        with self.console.breakCondition:
            if data:
                self.console.debuggerResponse = data
                self.console.breakCondition.notify_all()
            if not self.console.pendingCommand:
                notified = self.console.breakCondition.wait_for(lambda: self.console.pendingCommand is not None, timeout=TIMEOUT)
                if not notified:
                    self.console.pendingCommand = None
                    return b":TIMEOUT"
                command = self.console.pendingCommand
                self.console.pendingCommand = None
                return command
            return None

    def _handle_dbgcmd(self, data):
        cmd, _ = data.split(b":", 1)
        with self.console.breakCondition:
            if cmd == b"INIT" and not self.connected:
                notified = self.console.breakCondition.wait_for(lambda: self.console.debuggerResponse, timeout=TIMEOUT)
                if notified:
                    response = b"INIT:" + self.console.debuggerResponse
                    self.console.debuggerResponse = None
                    self.connected = True
                    return response
                else:
                    self.console.debuggerResponse = None
                    return b":TIMEOUT"

            self.console.pendingCommand = data
            self.console.breakCondition.notify_all()
            notified = self.console.breakCondition.wait_for(lambda: self.console.debuggerResponse is not None, timeout=TIMEOUT)
            if not notified:
                self.console.pendingCommand = None
                return b":TIMEOUT"

            response = b":" + self.console.debuggerResponse
            if cmd:
                response = cmd + response

            self.console.debuggerResponse = None
            return response

    def dispatch(self, data):
        response = b":NOPE"
        if not data or b":" not in data:
            log.critical("[DEBUG CONSOLE] Unknown command received from the debug server: %s", data.strip())
        else:
            command, arguments = data.strip().split(b":", 1)
            # log.info((command, data, "console dispatch"))
            fn = getattr(self, f"_handle_{command.lower().decode()}", None)
            if not fn:
                log.critical("[DEBUG CONSOLE] Unknown command received from the debug server: %s", data.strip())
            else:
                try:
                    response = fn(arguments)
                    # if response.decode("ascii")[0] not in ("M", "R", "K", "I"):
                    # log.info(response)
                except Exception as e:
                    log.error(e, exc_info=True)
                    log.exception(
                        "[DEBUG CONSOLE] Pipe command handler exception (command %s args %s)",
                        command,
                        arguments,
                    )
        return response

