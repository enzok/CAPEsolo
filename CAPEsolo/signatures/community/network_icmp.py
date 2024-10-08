# Copyright (C) 2013 David Maciejak
#
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

from CAPEsolo.capelib.signatures import Signature


class NetworkICMP(Signature):
    name = "network_icmp"
    description = "Generates some ICMP traffic"
    severity = 3
    categories = ["network"]
    authors = ["David Maciejak"]
    minimum = "1.0"
    ttps = ["T1095"]  # MITRE v6,7,8
    mbcs = ["OC0006", "C0014"]  # micro-behaviour

    def run(self):
        if "network" in self.results:
            if "icmp" in self.results["network"]:
                for icmp in self.results["network"]["icmp"]:
                    # ignore dest unreachable
                    if icmp["type"] not in [0, 3]:
                        self.data.append({"ip": icmp["dst"]})

        if len(self.data) > 0:
            return True
        else:
            return False
