from django.apps import AppConfig
from django.core.checks import Tags, register


class DjangoAPIGuardConfig(AppConfig):
    name = "djangoapi_guard"

    def ready(self) -> None:
        from djangoapi_guard._declared_path_params import check_declared_path_params

        register(check_declared_path_params, Tags.urls)
