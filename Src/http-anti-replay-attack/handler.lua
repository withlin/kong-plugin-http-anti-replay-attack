local responses = require "kong.tools.responses"
local policies = require "kong.plugins.http-anti-replay-attack.policies"

local BasePlugin = require "kong.plugins.base_plugin"
local ERR_MSG = "Not a valid X-Ca-Nonce! Specified signature nonce war used already";

local HttpReplayPreventHandler = BasePlugin:extend()

local function get_identifier(conf)
    local identifier

    -- Consumer is identified by ip address or authenticated_credential id
    if conf.limit_by == "consumer" then
        identifier = ngx.ctx.authenticated_consumer and ngx.ctx.authenticated_consumer.id
        if not identifier and ngx.ctx.authenticated_credential then -- Fallback on credential
        identifier = ngx.ctx.authenticated_credential.id
        end
    elseif conf.limit_by == "credential" then
        identifier = ngx.ctx.authenticated_credential and ngx.ctx.authenticated_credential.id
    end

    if not identifier then
        identifier = ngx.var.remote_addr
    end

    return identifier
end

function HttpReplayPreventHandler:new()
    HttpReplayPreventHandler.super.new(self, "http-replay-prevent")
end

local function check_signatureNonce(conf, api_id, identifier, signatureNonce)
    local nonce_timestamp, err = policies[conf.policy].query_nonce(conf, api_id, identifier, signatureNonce)
    if not nonce_timestamp then
        return false, err
    end

    return true
end

function HttpReplayPreventHandler:access(conf)
    HttpReplayPreventHandler.super.access(self)
    local headers = ngx.req.get_headers()
    local signatureNonce = headers[conf.signature_nonce_key]
    local identifier = get_identifier(conf)
    local api_id = ngx.ctx.api.id
    if signatureNonce then
        ngx.log(ngx.ERR, "signatureNonce="..signatureNonce)
        local nonce_timestamp,err = policies[conf.policy].query_nonce(conf, api_id, identifier, signatureNonce)
        --exist NoncKey or not exist NonceKey
        if err~=nil then
          return
          -- body
        else
          return responses.send(403, ERR_MSG)
        end

    else
        return
      end

end

HttpReplayPreventHandler.PRIORITY = 902
HttpReplayPreventHandler.VERSION = "0.1.0"

return HttpReplayPreventHandler
