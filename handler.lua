local access = require "kong.plugins.kong-waf.access"

local kongwafHandler = {}
kongwafHandler.PRIORITY = 990
kongwafHandler.VERSION = "1.1.3"


function kongwafHandler:access(conf)
    access.execute(conf)
end

return kongwafHandler
