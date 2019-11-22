local access = require "kong.plugins.kong-waf.access"

local kongwafHandler = {}
kongwaf.PRIORITY = 990
kongwaf.VERSION = "1.1.0"


function kongwafHandler:access(conf)
    access.execute(conf)
end

return kongwafHandler