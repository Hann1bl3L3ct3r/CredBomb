import redis

def check_redis(ip, port=6379, timeout=5):
    try:
        r = redis.StrictRedis(host=ip, port=port, socket_timeout=timeout)
        pong = r.ping()  # Will raise an exception if auth is required or connection fails
        if pong:
            info = r.info(section="server")
            return {
                "service": "Redis",
                "issue": "Unauthenticated access allowed",
                "info": {
                    "redis_version": info.get("redis_version"),
                    "os": info.get("os"),
                    "arch_bits": info.get("arch_bits"),
                    "process_id": info.get("process_id")
                }
            }
    except redis.AuthenticationError:
        return None
    except Exception:
        return None

    return None
