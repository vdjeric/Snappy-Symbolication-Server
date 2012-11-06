from logging import LogTrace, LogError, LogMessage, SetTracingEnabled
from symFileManager import SymFileManager
from symbolicationRequest import SymbolicationRequest

import sys
import os
import time
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import json
import re

# Timeout (in seconds) for reading in a request from a client connection
SOCKET_READ_TIMEOUT = 10.0

# .SYM cache manager
gSymFileManager = None

gOptions = {
  # IP address to listen on
  "hostname": "0.0.0.0",
  # TCP port to listen on
  "portNumber": 80,
  # Location of Firefox library symbols
  "firefoxSymbolsPath": os.getcwd() + os.sep + "symbols_ffx" + os.sep,
  # Location of Windows (and other) library symbols
  "osSymbolsPath": os.getcwd() + os.sep + "symbols_os" + os.sep,
  # Fallback server if symbol is not found locally
  "remoteSymbolServer": "",
  # Maximum number of symbol files to keep in memory
  # "maxCacheEntries": 10 * 1000 * 1000,
  "maxCacheEntries": 100,
  # Frequency of checking for recent symbols to cache (in hours)
  "prefetchInterval": 12,
  # Oldest file age to prefetch (in hours)
  "prefetchThreshold": 48,
  # Maximum number of library versions to pre-fetch per library
  "prefetchMaxSymbolsPerLib": 3,
  # Trace-level logging (verbose)
  "enableTracing": 0
}

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
  pass

class RequestHandler(BaseHTTPRequestHandler):
  # suppress most built-in logging
  def log_request(self, code='-', size='-'): pass
  def log_message(self, formats, *args): pass
  def log_error(self, *args):
    LogError(args[0] % tuple(args[1:]))

  def sendHeaders(self, errorCode):
    self.send_response(errorCode)
    self.send_header("Content-type", "application/json")
    self.end_headers()

  def do_HEAD(self):
    self.sendHeaders(200)

  def do_GET(self):
    return self.do_POST()

  def do_POST(self):
    LogTrace("Received request: " + self.path + " on thread " + threading.currentThread().getName())

    try:
      length = int(self.headers["Content-Length"])
      # Read in the request body without blocking
      self.connection.settimeout(SOCKET_READ_TIMEOUT)
      requestBody = self.rfile.read(length)
      # Put the connection back into blocking mode so rfile/wfile can be used safely
      self.connection.settimeout(None)

      if len(requestBody) < length:
        # This could be a broken connection, writing an error message into it could be a bad idea
        # See http://bugs.python.org/issue14574
        LogTrace("Read " + str(len(requestBody)) + " bytes but Content-Length is " + str(length))
        return

      LogTrace("Request body: " + requestBody)
      rawRequest = json.loads(requestBody)

      request = SymbolicationRequest(gSymFileManager, rawRequest)
      if not request.isValidRequest:
        LogTrace("Unable to parse request")
        self.sendHeaders(400)
        return
    except Exception as e:
      LogTrace("Unable to parse request body: " + str(e))
      # Ensure connection is back in blocking mode so rfile/wfile can be used safely
      self.connection.settimeout(None)
      self.sendHeaders(400)
      return

    try:
      self.sendHeaders(200)

      response = []
      for stackIndex in range(len(request.stacks)):
        symbolicatedStack = request.Symbolicate(stackIndex)

        # Free up memory ASAP
        request.stacks[stackIndex] = []

        response.append(symbolicatedStack)
      request.Reset()

      LogTrace("Response: " + json.dumps(response))
      self.wfile.write(json.dumps(response))
    except Exception as e:
      LogTrace("Exception in do_POST: " + str(e))

def ReadConfigFile():
  configFileData = []
  if len(sys.argv) > 2:
    LogError("Usage: symbolicationWebService.py [<config file>]")
    return False
  elif len(sys.argv) == 2:
    try:
      configFile = open(sys.argv[1], "r")
      configFileData = configFile.read()
      configFileData = configFileData.split("\n")
      configFile.close()
    except:
      LogError("Unable to open config file " + sys.argv[1])
      return False

  # Parse configuration file, if any
  lineNumber = 0
  for line in configFileData:
    lineNumber += 1

    # Skip over comments and blank lines
    if re.match(r"\s*#", line) or re.match(r"\s*$", line):
      continue

    # Config lines have key = value format
    matches = re.match(r"\s*(\S*)\s*=\s*(\S*)\s*$", line)
    if not matches or len(matches.groups()) != 2:
      LogError("Couldn't parse config line " + str(lineNumber) + ": " + line)
      return False
    (configKey, configValue) = matches.groups()

    if configKey not in gOptions:
      LogError("Unknown config option '" + configKey + "' on line " + str(lineNumber))
      return False
    elif type(gOptions[configKey]) == int:
      try:
        configValue = int(configValue)
      except ValueError:
        LogError("Integer value expected for config option '" + configKey + "'")
        return False

    gOptions[configKey] = configValue

  return True

def Main():
  global gSymFileManager, gOptions

  if not ReadConfigFile():
    return 1

  SetTracingEnabled(gOptions["enableTracing"] > 0)

  # Create the .SYM cache manager singleton
  gSymFileManager = SymFileManager(gOptions)

  # Prefetch recent symbols + start the periodic prefetch callbacks
  gSymFileManager.PrefetchRecentSymbolFiles()

  LogMessage("Starting server with the following options:\n" + str(gOptions))

  # Start the Web service
  httpd = ThreadedHTTPServer((gOptions['hostname'], gOptions['portNumber']), RequestHandler)
  LogMessage("Server started - " + gOptions['hostname'] + ":" + str(gOptions['portNumber']))

  try:
    httpd.serve_forever()
  except KeyboardInterrupt:
    LogMessage("Received SIGINT, stopping...")

  gSymFileManager.StopPrefetchTimer()

  httpd.server_close()
  LogMessage("Server stopped - " + gOptions['hostname'] + ":" + str(gOptions['portNumber']))
  return 0

sys.exit(Main())
