from upstash_redis import Redis
from app.config import settings

def get_upstash_redis() -> Redis:
    if not settings.upstash_redis_rest_url or not settings.upstash_redis_rest_token:
        raise ValueError("Upstash Redis credentials not configured")
    return Redis(url=settings.upstash_redis_rest_url, token=settings.upstash_redis_rest_token)

upstash_redis = None

def init_upstash_redis():
    global upstash_redis
    if settings.upstash_redis_rest_url and settings.upstash_redis_rest_token:
        upstash_redis = Redis(url=settings.upstash_redis_rest_url, token=settings.upstash_redis_rest_token)
    return upstash_redis