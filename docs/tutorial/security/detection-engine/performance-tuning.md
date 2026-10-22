# Detection Engine Performance Tuning Guide

## Performance Metrics

```python
from djangoapi_guard import sus_patterns_handler

stats = sus_patterns_handler.get_performance_stats()
print(f"Average execution time: {stats['summary']['average_time']}s")
print(f"Timeout rate: {stats['summary']['timeout_rate'] * 100}%")
print(f"Slow patterns: {len(stats['slow_patterns'])}")
```

## Performance Benchmarks

| Scenario | Target Response Time | Acceptable Timeout Rate |
|----------|---------------------|------------------------|
| API Gateway | < 10ms | < 0.1% |
| Web Application | < 50ms | < 1% |
| High Security | < 100ms | < 2% |

## Optimization Strategies

### 1. Pattern Optimization

Identify and optimize slow patterns. Use non-capturing groups for better performance.

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
