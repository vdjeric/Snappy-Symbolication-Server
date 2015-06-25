import sys
import threading
import time

gEnableTracing = False

# Whether to pause and launch debugger at CheckDebug breakpoints
gDebug = False

def SetTracingEnabled(isEnabled):
  global gEnableTracing
  gEnableTracing = isEnabled

def LogTrace(string):
  global gEnableTracing
  if gEnableTracing:
    threadName = threading.currentThread().getName().ljust(12)
    print >> sys.stdout, time.asctime() + " " + threadName + " TRACE " + string

def LogError(string):
  threadName = threading.currentThread().getName().ljust(12)
  print >> sys.stderr, time.asctime() + " " + threadName + " ERROR " + string

def LogMessage(string):
  threadName = threading.currentThread().getName().ljust(12)
  print >> sys.stdout, time.asctime() + " " + threadName + "       " + string

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

