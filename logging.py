import sys
import threading
import time

gEnableTracing = False

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
