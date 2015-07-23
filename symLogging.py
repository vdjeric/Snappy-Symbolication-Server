import sys
import time
import logging
import os
import tempfile
from logging.handlers import RotatingFileHandler
from symUtil import mkdir_p

gLog = None

# Whether to pause and launch debugger at CheckDebug breakpoints
gDebug = False

def SetLoggingOptions(logOptions):
  global gLog

  gLog = logging.getLogger("tornado.application")

  fmt = logging.Formatter('%(asctime)s\t%(levelname)s\t%(message)s')
  streamHandler = logging.StreamHandler()
  streamHandler.setFormatter(fmt)
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

def doLog(dbgLevel, string, remoteIp):
  pid = os.getpid()
  gLog.log(
    dbgLevel,
    "%d\t%s%s",
    pid,
    string,
    " IP=" + remoteIp if remoteIp else '')

def LogDebug(string, remoteIp=None):
  if gLog.isEnabledFor(logging.DEBUG):
    doLog(logging.DEBUG, string, remoteIp)

def LogError(string, remoteIp=None):
  if gLog.isEnabledFor(logging.ERROR):
    doLog(logging.ERROR, string, remoteIp)

def LogMessage(string, remoteIp=None):
  if gLog.isEnabledFor(logging.INFO):
    doLog(logging.INFO, string, remoteIp)

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

