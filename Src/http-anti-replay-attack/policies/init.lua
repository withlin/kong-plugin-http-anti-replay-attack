local ngx_log = ngx.log
local redis = require "resty.redis"
local timestamp = require "kong.tools.timestamp"
local fmt = string.format

local format_nonce_key = function(api_id, identifier, nonce)
    return fmt("knonce:%s:%s:%s", api_id, identifier, nonce)
end




return {
    ["redis"] = {
        query_nonce = function(conf, api_id, identifier, signatureNonce)
            -- create redis connection
            local red = redis:new()
            red:set_timeout(conf.redis_timeout)
            local ok, err = red:connect(conf.redis_host, conf.redis_port)
            if not ok then
                ngx_log(ngx.ERR, "failed to connect to Redis: ", err)
                return nil,err
            end

            if conf.redis_password ~=nil then
              -- body
               local res, err = red:auth(conf.redis_password)
               if not res then
                ngx_log("failed to authenticate: ", err)
               return nil,err
               end
            end


            if conf.redis_database ~= nil and conf.redis_database > 0 then
                local ok, err = red:select(conf.redis_database)
                if not ok then
                    ngx_log(ngx.ERR, "failed to change Redis database: ", err)
                    return nil, err
                end
            end

            -- deal with something
            local current_timestamp = timestamp.get_utc()

            local cache_nonce_key = format_nonce_key(api_id, identifier, signatureNonce)
            local nonce_timestamp, err = red:get(cache_nonce_key)
            -- store redis key=knonce:apiId:userId:nonce, value=nonce_timestamp
            if err then
                -- when reids is err, retun nil
                ngx_log(ngx.ERR, "redis happened Exception!", err)
                return nil, err
            end

            -- store NonceKey value
            if nonce_timestamp and nonce_timestamp ~= ngx.null then
              local errMsg ="Specified signature nonce war used already!"..nonce_timestamp;
                ngx_log(ngx.ERR, signatureNonce .. errMsg, nonce_timestamp)
                return errMsg
            end

            -- when redis is no  NonceKey,which 
            red:init_pipeline()
            red:set(cache_nonce_key, current_timestamp)
            red:expire(cache_nonce_key, conf.time_period)
            local _, err = red:commit_pipeline()
            if err then
                ngx_log(ngx.ERR, "failed to commit pipeline in Redis: ", err)
                return nil , current_timestamp
            end

            local ok, err = red:set_keepalive(10000, 100)
            if not ok then
                ngx_log(ngx.ERR, "failed to set Redis keepalive: ", err)
                return nil, err
            end

            -- return
        end
    }
}
