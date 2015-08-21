import os
import re

def mkdir_p(path):
  if not os.path.exists(path):
    os.makedirs(path)

def GetSymbolFileName(libName):
  # Guess the name of the .sym file on disk
  if libName[-4:] == ".pdb":
    return re.sub(r"\.[^\.]+$", ".sym", libName)
  return libName + ".sym"

