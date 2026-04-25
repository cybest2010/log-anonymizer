from enum import Enum
from pydantic import BaseModel, Field, model_validator


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    WARNING = "WARNING"
    ERROR = "ERROR"
    FATAL = "FATAL"
    UNKNOWN = "UNKNOWN"


class LogModel(BaseModel):
    time: str = Field(default="1970-01-01 00:00:00")
    level: str = Field(default=LogLevel.UNKNOWN)
    service: str = Field(default="unknown")
    msg: str = Field(default="")

    @model_validator(mode="before")
    @classmethod
    def map_fields(cls, v: dict) -> dict:
        if not isinstance(v, dict):
            return v
        level_raw = v.get("level", v.get("severity", v.get("loglevel", "UNKNOWN")))
        try:
            level = LogLevel(str(level_raw).upper()).value
        except ValueError:
            level = LogLevel.UNKNOWN.value
        return {
            "time": v.get("time", v.get("@timestamp", v.get("timestamp", "1970-01-01 00:00:00"))),
            "level": level,
            "service": v.get("service", v.get("app", v.get("logger", "unknown"))),
            "msg": v.get("msg", v.get("message", v.get("log", str(v)))),
        }
