# Detection Engine Performance Tuning Guide

## Performance Metrics

```python
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
patterns = sus_patterns_manager_for(config)

stats = patterns.get_performance_stats()
print(f"Average execution time: {stats['summary']['avg_execution_time']}s")
print(f"Timeout rate: {stats['summary']['timeout_rate'] * 100}%")
print(f"Slow patterns: {len(stats['slow_patterns'])}")
```

## Performance Benchmarks

| Scenario | Target Response Time | Acceptable Timeout Rate |
|----------|---------------------|------------------------|
| API Gateway | < 10ms | < 0.1% |
| Web Application | < 50ms | < 1% |
| High Security | < 100ms | < 2% |

These are targets for your deployment, not engine guarantees. For scale, the engine's own detection on guard-core 5.0.0 (Python 3.11.18, arm64, sync tree) takes 4.7 ms of CPU at the median and 6.7 ms at the 99th percentile for a 200-character benign value, 2.3 ms (p99 3.3 ms) for a value that carries an attack, and 18.1 ms (p99 26.5 ms) for a 10,000-character benign value. Across 1,000 pattern executions the performance monitor reported an average of 119 µs per pattern, a slowest of 15.2 ms and a timeout rate of 0%. Reproduce with `PYTHONPATH=. python -m perf_gate.detection_components latency --tree sync` from a checkout of guard-core 5.0.0.

## Optimization Strategies

### 1. Pattern Optimization

Identify and optimize slow patterns. Non-capturing groups do not make a pattern faster by themselves: on `(SELECT|INSERT|UPDATE).*(FROM|INTO)` the CPU ratio of `(?:...)` to `(...)` is 1.001 at 10,000 characters, against 1.001 for the same pattern measured twice (`PYTHONPATH=. python -m perf_gate.detection_components tuning --tree sync`).

### 2. Content Preprocessing

Adjust `detection_max_content_length` based on your typical request size.

### 3. Semantic Analysis Tuning

Adjust `detection_semantic_threshold` for your performance vs. security trade-off.

### 4. Timeout Configuration

Set `detection_compiler_timeout` based on endpoint criticality.

## Performance Checklist

- [ ] Average execution time < 50ms
- [ ] Timeout rate < 1%
- [ ] No patterns with > 100ms average execution
- [ ] Memory usage stable over 24 hours
- [ ] Tested with 10x expected traffic

## Next Steps

- Implement [Custom Patterns](../custom-patterns.md)
- Configure [Monitoring Dashboard](../monitoring.md)
- Review [Architecture Guide](architecture.md)
