import argparse
import logging
import sys
import threading
import time

import pywintypes
import win32event
import win32file

log = logging.getLogger(__name__)

PIPE = r"\\.\pipe\debugger_pipe"


class PipeServerBlocking:
    def __init__(self, pipe_name):
        self.pipe_name = pipe_name
        self.pipe = None
        self.running = True
        self.connected = False
        self.lock = threading.Lock()  # For thread-safe pipe access

    def connect_to_pipe(self):
        """Connect to an existing named pipe."""
        retries = 0
        max_retries = 10
        retry_delay = 1

        while retries < max_retries and self.running:
            try:
                self.pipe = win32file.CreateFile(
                    self.pipe_name,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None, win32file.OPEN_EXISTING,
                    0, None  # Blocking mode, no OVERLAPPED
                )
                log.info(f"Connected to existing pipe {self.pipe_name}.")
                self.connected = True
                return
            except pywintypes.error as e:
                if e.winerror in [2, 231]:  # File not found or pipe busy
                    retries += 1
                    log.debug(f"Pipe not ready. Retry {retries}/{max_retries}...")
                    time.sleep(retry_delay)
                else:
                    log.error(f"Error connecting to pipe: {e}")
                    sys.exit(1)
        log.error(f"Failed to connect to pipe {self.pipe_name} after {max_retries} attempts.")
        sys.exit(1)

    def send_message(self, message):
        """Send a message through the pipe and wait indefinitely for a response."""
        if not self.connected or not self.pipe:
            log.error("Cannot send message: Not connected to pipe.")
            print("Cannot send message: Not connected to pipe.")
            return

        try:
            with self.lock:
                # Blocking write
                win32file.WriteFile(self.pipe, message.encode('utf-8') + b"\n")
                log.info(f"Sent: {message}")
                print(f"Sent: {message}")

                # Blocking read, wait indefinitely for response
                result, data = win32file.ReadFile(self.pipe, 4096)
                if result == 0:
                    response = data.decode('utf-8').strip()
                    log.info(f"Received response: {response}")
                    print(f"Received response: {response}")
                else:
                    log.error("Failed to read response from pipe.")
                    print("Failed to read response from pipe.")
        except pywintypes.error as e:
            log.error(f"Pipe operation error: {e}")
            print(f"Pipe operation error: {e}")
            self.connected = False
            with self.lock:
                if self.pipe:
                    win32file.CloseHandle(self.pipe)
                    self.pipe = None

    def run(self):
        """Handle command line input, send messages, and wait for responses."""
        print("Enter messages to send (e.g., 'BREAK:some_data' or 'quit' to exit):")
        while self.running:
            if not self.connected:
                self.connect_to_pipe()
            try:
                message = input("> ").strip()
                if message.lower() == "quit":
                    self.running = False
                elif message:
                    self.send_message(message)
            except KeyboardInterrupt:
                self.running = False
            except EOFError:
                self.running = False

        # Cleanup
        with self.lock:
            if self.connected and self.pipe:
                win32file.CloseHandle(self.pipe)
        log.info("Pipe server shutting down...")
        print("Pipe server shutting down...")


class PipeServer:
    def __init__(self, pipe_name):
        self.pipe_name = pipe_name
        self.pipe = None
        self.running = True
        self.connected = False
        self.lock = threading.Lock()  # For thread-safe pipe access

    def connect_to_pipe(self):
        """Connect to an existing named pipe."""
        retries = 0
        max_retries = 10
        retry_delay = 1

        while retries < max_retries and self.running:
            try:
                self.pipe = win32file.CreateFile(
                    self.pipe_name,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None, win32file.OPEN_EXISTING,
                    win32file.FILE_FLAG_OVERLAPPED, None  # Enable overlapped I/O
                )
                log.info(f"Connected to existing pipe {self.pipe_name}.")
                self.connected = True
                return
            except pywintypes.error as e:
                if e.winerror in [2, 231]:  # File not found or pipe busy
                    retries += 1
                    log.debug(f"Pipe not ready. Retry {retries}/{max_retries}...")
                    time.sleep(retry_delay)
                else:
                    log.error(f"Error connecting to pipe: {e}")
                    sys.exit(1)
        log.error(f"Failed to connect to pipe {self.pipe_name} after {max_retries} attempts.")
        sys.exit(1)

    def listen_for_messages(self):
        """Listen for incoming messages from the pipe."""
        while self.running:
            if not self.connected:
                self.connect_to_pipe()

            overlapped = pywintypes.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)
            try:
                # Asynchronous read
                result = win32file.ReadFile(self.pipe, 4096, overlapped)
                # Wait for read completion (timeout of 100ms to keep responsive)
                wait_result = win32event.WaitForSingleObject(overlapped.hEvent, 100)
                if wait_result == win32event.WAIT_OBJECT_0:
                    bytes_read = win32file.GetOverlappedResult(self.pipe, overlapped, True)
                    if bytes_read > 0:
                        message = win32file.ReadFile(self.pipe, bytes_read)[1].decode('utf-8').strip()
                        log.info(f"Received: {message}")
                elif wait_result == win32event.WAIT_TIMEOUT:
                    continue  # Timeout, loop to check running status
            except pywintypes.error as e:
                if e.winerror == 109:  # Pipe broken
                    log.info("Pipe connection broken.")
                    self.connected = False
                    with self.lock:
                        if self.pipe:
                            win32file.CloseHandle(self.pipe)
                            self.pipe = None
                elif e.winerror == 233:  # Pipe not connected
                    log.debug("Pipe not connected, retrying...")
                    self.connected = False
                    time.sleep(0.1)
                else:
                    log.error(f"Pipe read error: {e}")
                    self.running = False
            finally:
                if overlapped.hEvent:
                    win32file.CloseHandle(overlapped.hEvent)

    def send_message(self, message):
        """Send a message through the pipe asynchronously."""
        if not self.connected or not self.pipe:
            log.error("Cannot send message: Not connected to pipe.")
            return
        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)
        try:
            with self.lock:
                win32file.WriteFile(self.pipe, message.encode('utf-8') + b"\n", overlapped)
            # Don’t wait for completion, just log
            log.info(f"Sent: {message}")
        except pywintypes.error as e:
            log.error(f"Error sending message: {e}")
            self.connected = False
            with self.lock:
                if self.pipe:
                    win32file.CloseHandle(self.pipe)
                    self.pipe = None
        finally:
            if overlapped.hEvent:
                win32file.CloseHandle(overlapped.hEvent)

    def run(self):
        """Start the pipe server and handle command line input."""
        listener_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        listener_thread.start()

        print("Enter messages to send (or 'quit' to exit):")
        while self.running:
            try:
                message = input("> ").strip()
                if message.lower() == "quit":
                    self.running = False
                elif message:
                    self.send_message(message)
            except KeyboardInterrupt:
                self.running = False
            except EOFError:
                self.running = False

        # Cleanup
        with self.lock:
            if self.connected and self.pipe:
                win32file.CloseHandle(self.pipe)
        log.info("Pipe server shutting down...")

def main():
    parser = argparse.ArgumentParser(description="Connect to an existing named pipe.")

    server = PipeServerBlocking(PIPE)
    server.run()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()