# Copyright (C) 2024 enzok
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import logging
import os
import sys
import time
from ctypes import windll
from pathlib import Path

import wx
import wx.adv

CAPESOLO_ROOT = os.path.dirname(__file__)
sys.path.append(CAPESOLO_ROOT)
os.chdir(CAPESOLO_ROOT)

from classes.main_frame import MainFrame
from classes.splash_screen import SplashScreen
from utils.update_yara import update_yara


log = logging.getLogger(__name__)
for handler in log.handlers[:]:
    log.removeHandler(handler)

ANALYSIS_CONF = os.path.join(CAPESOLO_ROOT, "analysis_conf")


class CapesoloApp(wx.App):
    def OnInit(self):
        hWnd = windll.kernel32.GetConsoleWindow()
        windll.user32.ShowWindow(hWnd, 6)
        splash = SplashScreen(CAPESOLO_ROOT)
        splash.Show()
        time.sleep(2)
        screenWidth, screenHeight = wx.DisplaySize()
        frameWidth = int(screenWidth * 0.3)
        frameHeight = int(screenHeight * 0.75)
        if frameWidth < 460:
            frameWidth = 460
        frame = MainFrame(
            rootDir=CAPESOLO_ROOT, parent=None, size=(frameWidth, frameHeight)
        )
        frameX = int(screenWidth * 0.01)
        frameY = int(screenHeight * 0.02)
        frame.SetPosition((frameX, frameY))
        frame.Show()
        return True


def main():
    parser = argparse.ArgumentParser(description="Capesolo utility functions.")
    parser.add_argument(
        "--update_yara",
        help="Update yara rules from CAPEv2 and community",
        action="store_true",
    )

    args = parser.parse_args()

    if args.update_yara:
        update_yara(Path(CAPESOLO_ROOT))
    else:
        app = CapesoloApp()
        app.MainLoop()


if __name__ == "__main__":
    main()
