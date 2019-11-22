local iputils = require "resty.iputils"
local FORBIDDEN = 403
local cache = {}
local kong = kong 
--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

local function cidr_cache(cidr_tab)
    local cidr_tab_len = #cidr_tab
    local parsed_cidrs = kong.table.new(cidr_tab_len, 0) 
    for i = 1, cidr_tab_len do
      local cidr        = cidr_tab[i]
      local parsed_cidr = cache[cidr]  
      if parsed_cidr then
        parsed_cidrs[i] = parsed_cidr  
      else
        local lower, upper = iputils.parse_cidr(cidr)  
        cache[cidr] = { lower, upper }
        parsed_cidrs[i] = cache[cidr]
      end
    end  
    return parsed_cidrs
end

--Get the client user agent
local function get_user_agent()
    USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
       USER_AGENT = "unknown"
    end
    return USER_AGENT
end

--Get WAF rule
local function get_rule(rulefilename)
    local io = require 'io'
    local RULE_PATH = "/usr/local/share/lua/5.1/kong/plugins/kong-waf/wafconf"
    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename,"r")
    if RULE_FILE == nil then
        return
    end
    RULE_TABLE = {}
    for line in RULE_FILE:lines() do
        table.insert(RULE_TABLE,line)
    end
    RULE_FILE:close()
    return(RULE_TABLE)
end

--WAF log record for json,(use logstash codec => json)
local function log_record(method,url,data,ruletag,conf)
    local cjson = require("cjson")
    local io = require 'io'
    local LOG_PATH = conf.log_dir
    local CLIENT_IP = ngx.var.binary_remote_addr
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()
    local log_json_obj = {
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 user_agent = USER_AGENT,
                 attack_method = method,
                 req_url = url,
                 req_data = data,
                 rule_tag = ruletag,
              }
    local LOG_LINE = cjson.encode(log_json_obj)
    local LOG_NAME = LOG_PATH..'/'..ngx.today().."_waf.log"
    local file = io.open(LOG_NAME,"a")
    if file == nil then
        return
    end
    file:write(LOG_LINE.."\n")
    file:flush()
    file:close()
end

--WAF return
local function waf_output(conf)
    if conf.waf_redirect then
        ngx.redirect("www.baidu.com", 301)
    else
        ngx.header.content_type = "text/html"
        local binary_remote_addr = ngx.var.binary_remote_addr
        ngx.status = ngx.HTTP_FORBIDDEN
        local config_output_html=[[
            <html xmlns="http://www.w3.org/1999/xhtml"><head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
            <title>网站防火墙</title>
            <style>
            p {
                line-height:20px;
            }
            ul{ list-style-type:none;}
            li{ list-style-type:none;}
            </style>
            </head>
            <body style=" padding:0; margin:0; font:14px/1.5 Microsoft Yahei, 宋体,sans-serif; color:#555;">
            <div style="margin: 0 auto; width:1000px; padding-top:70px; overflow:hidden;">
              <div style="width:600px; float:left;">
              <div style=" height:40px; line-height:40px; color:#fff; font-size:16px; overflow:hidden; background:#6bb3f6; padding-left:20px;">网站防火墙 </div>
                <div style="border:1px dashed #cdcece; border-top:none; font-size:14px; background:#fff; color:#555; line-height:24px; height:220px; padding:20px 20px 0 20px; overflow-y:auto;background:#f3f7f9;">
            <p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600; color:#fc4f03;">您的请求带有不合法参数，已被网站管理员设置拦截！</span></p>
            <p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">可能原因：您提交的内容包含危险的攻击请求</p>
            <p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:1; text-indent:0px;">您的IP为: %s</p>
            <ul style="margin-top: 0px; margin-bottom: 0px; margin-left: 0px; margin-right: 0px; -qt-list-indent: 1;"><li style=" margin-top:12px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">1）检查提交内容；</li>
            <li style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">3）请联系网站管理员；</li></ul>
                </div>
              </div>
            </div>
            </body></html>
        ]]       
        ngx.say(string.format(config_output_html, binary_remote_addr))
        ngx.exit(ngx.status)
    end
end

local function ip_check(conf)
    local block = false
    local binary_remote_addr = ngx.var.binary_remote_addr
  
    if not binary_remote_addr then
      return kong.response.exit(FORBIDDEN, { message = "Cannot identify the client IP address, unix domain sockets are not supported." })
    end
  
    if conf.blacklist and #conf.blacklist > 0 then
      block = iputils.binip_in_cidrs(binary_remote_addr, cidr_cache(conf.blacklist))
    end
  
    if conf.whitelist and #conf.whitelist > 0 then
      block = not iputils.binip_in_cidrs(binary_remote_addr, cidr_cache(conf.whitelist))
    end
  
    if block then
      return kong.response.exit(FORBIDDEN, { message = "Your IP address is not allowed" })
    end
end

--allow white url
local function white_url_check(conf)
    if conf.white_url_check then
        local URL_WHITE_RULES = get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jo") then
                    return true
                end
            end
        end
    end
end

--deny cookie
local function cookie_attack_check(conf)
    if conf.cookie_check then
        local COOKIE_RULES = get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jo") then
                    log_record('Deny_Cookie',ngx.var.request_uri,"-",rule,conf)
                    if conf.waf_enable then
                        waf_output()
                        return true
                    end
                end
             end
	 end
    end
    return false
end

--deny url
local function url_attack_check(conf)
    if conf.url_check  then
        local URL_RULES = get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jo") then
                log_record('Deny_URL',REQ_URI,"-",rule,conf)
                if conf.waf_enable then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny url args
local function url_args_attack_check(conf)
    if conf.url_args_check  then
        local ARGS_RULES = get_rule('args.rule')
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"jo") then
                    log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule,conf)
                    if conf.waf_enable then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny user agent
local function user_agent_attack_check(conf)
    if conf.user_agent_check then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"jo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule,conf)
                    if conf.waf_enable then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny post
local function post_attack_check(conf)
    if conf.post_check  then
        ngx.req.read_body()
        local POST_RULES = get_rule('post.rule')
        for _,rule in pairs(POST_RULES) do
            local POST_ARGS = ngx.req.get_post_args() or {}
            for k, v in pairs(POST_ARGS) do
                local post_data = ""
                if type(v) == "table" then
                    post_data = table.concat(v, ", ")
                elseif type(v) == "boolean" then
                    post_data = k
                else
                    post_data = v
                end
                if rule ~= "" and rulematch(post_data, rule, "jo") then
                    log_record('Post_Attack', post_data, "-", rule,conf)
                    if conf.waf_enable  then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end            
    return false
end

local _M = {}


function _M.execute(conf)
    if ip_check(conf) then
    elseif user_agent_attack_check(conf) then
    elseif cookie_attack_check(conf) then
    elseif white_url_check(conf) then
    elseif url_attack_check(conf) then
    elseif url_args_attack_check(conf) then
    elseif post_attack_check(conf) then
    else
        return
    end
end


return _M

