from django.http import HttpRequest, JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from advanced_app.models import message_response
from advanced_app.security import guard
from djangoapi_guard import BehaviorRule


@require_GET
@guard.usage_monitor(max_calls=10, window=300, action="log")
def monitor_usage_patterns(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        message_response(
            "Usage monitoring active",
            details={"monitoring": "10 calls per 5 minutes"},
        )
    )


@require_GET
@guard.return_monitor(pattern="status:404", max_occurrences=3, window=60, action="ban")
def monitor_return_patterns(request: HttpRequest, status_code: int) -> JsonResponse:
    if status_code == 404:
        return JsonResponse({"detail": "Not found"}, status=404)
    return JsonResponse(message_response(f"Status code: {status_code}"))


@require_GET
@guard.suspicious_frequency(max_frequency=0.5, window=10, action="throttle")
def detect_suspicious_frequency(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        message_response(
            "Frequency monitoring active",
            details={
                "max_frequency": "1 request per 2 seconds",
            },
        )
    )


@csrf_exempt
@require_POST
@guard.behavior_analysis(
    [
        BehaviorRule(
            rule_type="frequency",
            threshold=10,
            window=60,
            action="throttle",
        ),
        BehaviorRule(
            rule_type="return_pattern",
            pattern="status:404",
            threshold=5,
            window=60,
            action="ban",
        ),
    ]
)
def complex_behavior_analysis(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        message_response(
            "Complex behavior analysis active",
            details={"rules": ["frequency", "return_pattern"]},
        )
    )


urlpatterns = [
    path("usage-monitor", monitor_usage_patterns),
    path("return-monitor/<int:status_code>", monitor_return_patterns),
    path("suspicious-frequency", detect_suspicious_frequency),
    path("behavior-rules", complex_behavior_analysis),
]
