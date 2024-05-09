Python GUI to run capemon in standalone VM.

* Create a VM that's suitable for running malware, see CAPE guest guide for details.
* Install python in VM, must be 32-bit, and add to path.
* Install MS Build Tools (C++) which is required to build gevent on Windows.
* Download package file from Releases.
* pip install capesolo-[version]-py3-none.any.whl
* Copy bin\libmagic.dll and bin\magic.mgc to Windows syswow64 directory.
