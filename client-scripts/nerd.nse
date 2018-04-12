local http = require "http"
local ipOps = require "ipOps"
local io = require "io"
local stdnse = require "stdnse"
local json = require "json"


description = [[
Looks up info about the target in the NERD system.
]]

---
-- @args nerd Takes the following optional argument:
-- * <code>nerd.apifile=file</code> Path to file with NERD API key, default is ./nerdapifile.
-- @usage
-- # Basic usage:
-- nmap target --script nerd
-- nmap target --script nerd --script-args nerd.apifile=/home/user/apifile
--
-- @output
-- Host script results:
-- |_nerd: IP not found in NERD
--
-- Host script results:
-- |_nerd: {"asn": [], "bgppref": "", "bl": [], "geo": {"ctry": "CZ"}, "hostname": "ns.cesnet.cz", "ip": "195.113.144.194", "ipblock": "", "rep": 0.2, "tags": []}

author = "Tomas Cejka <cejkat@cesnet.cz>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"external"}

hostrule = function( host )
  local is_private, err = ipOps.isPrivate( host.ip )
  if is_private == nil then
    stdnse.debug1("Error in Hostrule: %s.", err)
    return false
  end
  return not is_private
end

function load_key()
   local file = nil
   local apifile = stdnse.get_script_args('nerd.apifile')
   if type( apifile ) ~= "string" or apifile == "" then
      apifile = "nerdapifile"
   end
   file = io.input(apifile)

   if file then
      local content = file:read "l"
      file:close()
      return content
   else
      return nil
   end
end

action = function( host )
   local apitoken = load_key()
   local header = {header={Authorization= "token " .. apitoken}}
   local resp = http.get_url("https://nerd.cesnet.cz/nerd/api/v1/ip/" .. host.ip, header)
   local content = resp.body
   local status, parsed = json.parse(content)
   if not(status) or parsed.err_n == 404 then
      return "IP not found in NERD"
   end
   return content
end

