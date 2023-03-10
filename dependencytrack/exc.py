from requests import exceptions as http_exc


class BaseDTException(http_exc.HTTPError):
    def __init__(self, *args, **kwargs) -> None:
        """Initialize BaseDTException with `request` and `response` objects."""
        self.status = kwargs.pop("status")
        self.detail = kwargs.pop("detail", None)
        self.instance = kwargs.pop("instance", None)
        http_exc.HTTPError.__init__(self, *args, **kwargs)


class NotFound(BaseDTException):
    pass


class Conflict(BaseDTException):
    pass


class BadRequest(BaseDTException):
    pass


class InternalServerError(BaseDTException):
    pass
