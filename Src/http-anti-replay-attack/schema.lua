local Errors = require "kong.dao.errors"

local REDIS = "redis"

return {
    fields = {
        policy = { type = "string", enum = {REDIS}, default = REDIS },
        time_period = {type = "number", default = 60*15},
        signature_nonce_key = {type = "string", default = "APiNonceKey"},
        redis_host = { type = "string" },
        redis_port = { type = "number", default = 6379 },
        redis_password = { type = "string" },
        redis_timeout = { type = "number", default = 2000 },
        redis_database = { type = "number", default = 0 }
    },
    self_check = function(schema, plugin_t, dao, is_update)
        local invalid_value
        if plugin_t.time_period <= 0 then
            invalid_value = "Value for time_period must be greater than zero"
        end

        if plugin_t.time_period >= 3600 then
            invalid_value = "Value for time_period must be smaller than 3600"
        end
        if invalid_value then
            return false, Errors.schema(invalid_value)
        end

        if plugin_t.policy == REDIS then
            if not plugin_t.redis_host then
                return false, Errors.schema "You need to specify a Redis host"
            elseif not plugin_t.redis_port then
                return false, Errors.schema "You need to specify a Redis port"
            elseif not plugin_t.redis_timeout then
                return false, Errors.schema "You need to specify a Redis timeout"
            end
        end

        return true
    end
}


