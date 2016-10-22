rule PyInstaller_Binary
  {
meta:
    author = "Nicholas Albright, ThreatStream"
    desc = "Generic rule to identify PyInstaller Compiled Binaries"
    reference = "https://blog.anomali.com/crushing-python-malware"
strings:
    $string0 = "zout00-PYZ.pyz"
    $string1 = "python"
    $string2 = "Python DLL"
    $string3 = "Py_OptimizeFlag"
    $string4 = "pyi_carchive"
    $string5 = ".manifest"
condition:
    all of them // and new_file
}