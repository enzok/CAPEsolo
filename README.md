Python GUI to run capemon in standalone VM.

* Create a Windows 10 VM that's suitable for running malware.
  * Use the CAPEv2 guest guide for configuration details.
  * https://capev2.readthedocs.io/en/latest/installation/guest/index.html
* Install python in VM, tested on versions 3.11 and 3.12 (64-bit), and add to path.
* Download and install Microsoft Visual C++ Redistributable.
  * https://aka.ms/vs/17/release/vc_redist.x86.exe
  * https://aka.ms/vs/17/release/vc_redist.x64.exe
* Download package file from Releases.
  * pip install capesolo-[version]-py3-none.any.whl
* Snapshot your VM.

Quick Start 
* Open an administrator command window.
* Type capesolo <return> to run.

Alternatively, create a shortcut to CAPEsolo.exe, 
which will be in the Scripts subdirectory of same location as your python.exe file. 
* Under Advanced, check 'Run as administrator'
* An icon file is available in the CAPEsolo install folder under site-packages.

Analysis results are found in C:\Users\Public\CAPEsolo\analysis.
* Can be configured in python-path\site-packages\CAPEsolo\cfg.ini

Revert the VM after each analysis.