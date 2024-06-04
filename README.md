Python GUI to run capemon in standalone VM.

* Create a VM that's suitable for running malware, see CAPE guest guide for details.
* Install python in VM, must be 32-bit 3.11, and add to path.
* Download package file from Releases.
* Download gevent wheel file from extras.
* pip install capesolo-[version]-py3-none.any.whl
* pip install gevent-[version].whl
* Snapshot your VM.

Quick Start 
* Open an administrator command window.
* Type capesolo <return> to run.

Alternatively, create a shortcut to CAPEsolo.exe, which will be in the same location as your python.exe file.
* Under Advanced, check 'Run as administrator'

Analysis results are found in C:\Users\Public\CAPEsolo\analysis.
* Can be configured in python-path\site-packages\CAPEsolo\cfg.ini

Revert the VM after each analysis.