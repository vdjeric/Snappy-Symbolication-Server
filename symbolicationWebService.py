#!/usr/bin/env python

from symLogging import LogDebug, LogError, LogMessage, SetLoggingOptions, SetDebug, CheckDebug
from symFileManager import SymFileManager
from symbolicationRequest import SymbolicationRequest
from concurrent.futures import ProcessPoolExecutor as Pool

import sys
import os
import json
import signal
import tempfile
import ConfigParser
from collections import OrderedDict as _default_dict
import tornado.gen
from tornado.ioloop import IOLoop, PeriodicCallback
from tornado.web import Application, RequestHandler, url

# Report errors while symLogging is not configured yet
import logging

# .SYM cache manager
gSymFileManager = None

# Pool of symbolication workers
gPool = None

# Default config options
gOptions = {
  # IP address to listen on
  "hostname": "0.0.0.0",
  # TCP port to listen on
  "portNumber": 80,
  # Trace-level logging (verbose)
  "enableTracing": 0,
  # Fallback server if symbol is not found locally
  "remoteSymbolServer": "",
  # Maximum number of symbol files to keep in memory
  # "maxCacheEntries": 10 * 1000 * 1000,
  "maxCacheEntries": 100,
  # File in which to persist the list of most-recently-used symbols.
  "mruSymbolStateFile": os.path.join(tempfile.gettempdir(), "snappy-mru-symbols.json"),
  # Maximum number of symbol files to persist in the state file between runs.
  "maxMRUSymbolsPersist": 10,
  # Paths to .SYM files
  "symbolPaths": [
    # Default to empty so users don't have to list anything in their config
    # file to override the defaults.
  ],
  # URLs to symbol stores
  "symbolURLs": [
  ]
}

# Use a new class to make defaults case-sensitive
class CaseSensitiveConfigParser(ConfigParser.SafeConfigParser):
  superClass = ConfigParser.SafeConfigParser
  def __init__(self, defaults=None, dict_type=_default_dict,
                allow_no_value=False):
    self.optionxform = str
    self.superClass.__init__(self, defaults, dict_type, allow_no_value)

  def items(self, section, raw=False, vars=None):
    defaults = self.defaults()
    if vars is not None:
      defaults.update(vars)

    # Remove default items from the result
    return filter(
              lambda item: item[0] not in defaults,
              self.superClass.items(self, section, raw, vars))

def initializeSubprocess(options):
  global gSymFileManager

  # Ignore ctrl-c in the subprocess
  signal.signal(signal.SIGINT, signal.SIG_IGN)

  # Setup logging in the child process
  SetLoggingOptions(options["Log"])

  # Create the .SYM cache manager singleton
  gSymFileManager = SymFileManager(options)

  # Prefetch recent symbols
  gSymFileManager.PrefetchRecentSymbolFiles()


def processSymbolicationRequest(rawRequest, remoteIp):
  decodedRequest = json.loads(rawRequest)
  request = SymbolicationRequest(gSymFileManager, decodedRequest, remoteIp)
  if not request.isValidRequest:
    LogDebug("Unable to parse request", remoteIp)
    return None

  response = { 'symbolicatedStacks': [] }
  for stackIndex in range(len(request.stacks)):
    symbolicatedStack = request.Symbolicate(stackIndex)

    # Free up memory ASAP
    request.stacks[stackIndex] = []

    response['symbolicatedStacks'].append(symbolicatedStack)

  response['knownModules'] = request.knownModules[:]
  if not request.includeKnownModulesInResponse:
    response = response['symbolicatedStacks']

  request.Reset()

  return json.dumps(response)

class DebugHandler(RequestHandler):
  def get(self, path):
    self.post(path)

  def post(self, path):
    if self.request.remote_ip == "127.0.0.1":
      SetDebug(path == "debug")
      self.set_status(200)
      self.set_header("Content-type", "application/json")

class SymbolHandler(RequestHandler):
  def LogDebug(self, string):
    LogDebug(string, self.remoteIp)

  def LogMessage(self, string):
    LogMessage(string, self.remoteIp)

  def LogError(self, string):
    LogError(string, self.remoteIp)

  def sendHeaders(self, errorCode):
    self.set_status(errorCode)
    self.set_header("Content-type", "application/json")

  def prepare(self):
    xForwardIp = self.request.headers.get("X-Forwarded-For")
    self.remoteIp = self.request.remote_ip if not xForwardIp else xForwardIp

  def head(self):
    self.sendHeaders(200)

  def get(self, path):
    return self.post(path)

  @tornado.gen.coroutine
  def post(self, path):
    self.LogDebug("Received request with path '{}'".format(path))

    try:
      CheckDebug()
      requestBody = self.request.body

      # vdjeric: temporary hack to stop a spammy request
      if "\"Bolt\"" in requestBody:
        self.sendHeaders(400)
        return

      self.LogDebug("Request body: " + requestBody)

      response = yield gPool.submit(
                  processSymbolicationRequest,
                  requestBody,
                  self.remoteIp)

      if response is None:
        self.LogDebug("Unable to parse request")
        self.sendHeaders(400)
        return
    except Exception as e:
      self.LogDebug("Unable to parse request body: " + str(e))
      # Ensure connection is back in blocking mode so rfile/wfile can be used safely
      self.sendHeaders(400)
      return

    try:
      self.sendHeaders(200)
      self.LogDebug("Response: " + response)
      self.write(response)
    except Exception as e:
      self.LogError("Exception in post: " + str(e))

def ReadConfigFile():
  if len(sys.argv) == 1:
    return True
  elif len(sys.argv) > 2:
    logging.error("Usage: symbolicationWebService.py [<config file>]")
    return False
  elif len(sys.argv) == 2:
    try:
      # ConfigParser uses the pattern %(<variable>)<type> for variable substitution,
      # so '%' found in environment variable values will raise an error. We replace
      # '%' by '%%' to make the parser understand it is literal character.
      environ = {key:value.replace(r"%", r"%%") for key, value in os.environ.iteritems()}

      configParser = CaseSensitiveConfigParser(environ)
      configFile = open(sys.argv[1], "r")
      configParser.readfp(configFile)
      configFile.close()
    except ConfigParser.Error as e:
      logging.error("Unable to parse config file %s: %s", sys.argv[1], e)
    except Exception as e:
      logging.error("Unable to open config file %s: %s", sys.argv[1], e)
      return False

  # Check for section names
  if not set(["General", "Log"]).issubset(set(configParser.sections())):
    logging.error("'General' and 'Log' sections are mandatory in the config file")
    return False

  generalSectionOptions = configParser.items("General")
  for (option, value) in generalSectionOptions:
    if option not in gOptions:
      logging.error("Unknown config option '" + option + "' in the 'General' section of config file")
      return False
    elif type(gOptions[option]) == int:
      try:
        value = int(value)
      except ValueError:
        logging.error("Integer value expected for config option '" + option + "'")
        return False
    gOptions[option] = value

  # Get the list of symbol paths from the config file
  if configParser.has_section("SymbolPaths"):
    configPaths = configParser.items("SymbolPaths")
    if configPaths:
      # Drop defaults if config file entries exist
      gOptions["symbolPaths"] = [path for name, path in configPaths]

  # Get the list of symbol URLs from the config file
  if configParser.has_section("SymbolURLs"):
    configURLs = configParser.items("SymbolURLs")
    if configURLs:
      gOptions["symbolURLs"] = [url for name, url in configURLs if name not in environ]

  gOptions["Log"] = dict(configParser.items("Log"))

  return True

def Main():
  global gSymFileManager, gOptions, gPool

  if not ReadConfigFile():
    return 1

  # In a perfect world, we could create a process per cpu core.
  # But then we'd have to deal with cache sharing
  gPool = Pool(1)
  gPool.submit(initializeSubprocess, gOptions)

  # Setup logging in the parent process.
  # Ensure this is called after the call to initializeSubprocess to
  # avoid duplicate messages in Unix systems.
  SetLoggingOptions(gOptions["Log"])

  LogMessage("Starting server with the following options:\n" + str(gOptions))

  app = Application([
    url(r'/(debug)', DebugHandler),
    url(r'/(nodebug)', DebugHandler),
    url(r"(.*)", SymbolHandler)])

  app.listen(gOptions['portNumber'], gOptions['hostname'])

  try:
    # select on Windows doesn't return on ctrl-c, add a periodic
    # callback to make ctrl-c responsive
    if sys.platform == 'win32':
        PeriodicCallback(lambda: None, 100).start()
    IOLoop.current().start()
  except KeyboardInterrupt:
    LogMessage("Received SIGINT, stopping...")

  gPool.shutdown()
  LogMessage("Server stopped - " + gOptions['hostname'] + ":" + str(gOptions['portNumber']))
  return 0

if __name__ == '__main__':
  sys.exit(Main())
