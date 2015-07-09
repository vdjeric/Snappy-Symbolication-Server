import sys
import threading
import time
import logging
import os.path
import os
import tempfile
from logging.handlers import RotatingFileHandler

gLog = None

# Whether to pause and launch debugger at CheckDebug breakpoints
gDebug = False

def mkdir_p(path):
  if not os.path.exists(path):
    os.makedirs(path)

def SetLoggingOptions(logOptions):
  global gLog

  fmt = logging.Formatter('%(asctime)s\t%(levelname)s\t%(message)s')
  streamHandler = logging.StreamHandler()
  streamHandler.setFormatter(fmt)
  gLog = logging.getLogger("Snappy")
  gLog.addHandler(streamHandler)

  filepath = logOptions.get('logPath', tempfile.gettempdir())

  try:
    mkdir_p(filepath)
    rotatingHandler = \
      RotatingFileHandler(
        filename=os.path.join(filepath, 'snappy.log'),
        mode='a',
        maxBytes=int(logOptions.get("maxFileSize", 1024*1024)),
        backupCount=int(logOptions.get("maxFiles", 10)))

    rotatingHandler.setFormatter(fmt)
    gLog.addHandler(rotatingHandler)
  except OSError as exc:
    gLog.error("Invalid path '%s': %s.", filepath, exc)
    gLog.error("Logging on screen only.")
  except IOError as exc:
    gLog.error("Could not configure file logger: %s", exc)
    gLog.error("Check the log path '%s'. Logging on screen only.", filepath)

  logLevel = getattr(logging, logOptions.get("logLevel", "INFO"))
  gLog.setLevel(logLevel)

def doLog(dbgLevel, string):
    threadName = threading.currentThread().getName().ljust(12)
    gLog.log(dbgLevel, "%s\t%s", threadName, string)

def LogDebug(string):
  if gLog.isEnabledFor(logging.DEBUG):
    doLog(logging.DEBUG, string)

def LogError(string):
  if gLog.isEnabledFor(logging.ERROR):
    doLog(logging.ERROR, string)

def LogMessage(string):
  if gLog.isEnabledFor(logging.INFO):
    doLog(logging.INFO, string)

def SetDebug(isEnabled):
  global gDebug
  gDebug = isEnabled

def CheckDebug():
  global gDebug
  if not gDebug:
    return

  # launch debug console
  LogMessage("Stopping server, starting debug console!")
  import pdb
  pdb.set_trace()
  LogMessage("Exited debug console, resuming server")

