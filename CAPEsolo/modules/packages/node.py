from lib.common.abstracts import Package
from lib.common.common import check_file_extension

class Node(Package):
    """Node analysis package."""

    PATHS = [
        ("ProgramFiles", "nodejs", "node.exe"),
    ]
    summary = "Runs javascript with nodejs."
    description = """Uses node.exe to run the supplied javascript file."""

    def start(self, path):
        node = self.get_path("node.exe")
        path = check_file_extension(path, ".js")
        return self.execute(node, f"{path}", path)
