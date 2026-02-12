"""
Latency Benchmark Script for Phishing Detection API

This script measures the performance of the /api/v1/predict endpoint by:
1. Sending 100 requests (50 phishing + 50 legitimate emails)
2. Measuring response times for each request
3. Calculating key latency metrics (average, median, P95, P99)
4. Generating a visual ASCII chart
5. Saving results to JSON
6. Determining PASS/FAIL based on P95 < 200ms target

What is P95 Latency?
--------------------
P95 (95th percentile) latency means that 95% of requests complete faster than this value.

Example: If P95 = 180ms, then:
- 95% of requests took ≤ 180ms
- Only 5% of requests took > 180ms (these are the slowest outliers)

Why P95 Matters:
----------------
1. **User Experience**: Average can be misleading if there are slow outliers
   - Average = 100ms might hide that some users wait 2000ms
   - P95 = 180ms guarantees 95% of users have good experience

2. **Production Reality**: In real systems, some requests will always be slower
   - Network issues, database locks, garbage collection
   - P95 accounts for this reality while filtering extreme outliers

3. **SLA Commitments**: Most services promise P95/P99, not average
   - "95% of requests under 200ms" is better than "average 100ms"

4. **Capacity Planning**: Helps identify when you need to scale
   - If P95 increases over time → system degrading
   - P95 > target → need more resources

Target: P95 < 200ms
-------------------
This ensures that 95% of users get a response within 200ms,
which is fast enough for interactive applications.
"""

import requests
import time
import json
import statistics
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import sys

# API configuration
API_URL = "http://localhost:8000/api/v1/predict"
TARGET_P95_MS = 200  # Target: 95% of requests should be under 200ms

# Sample directories
PHISHING_DIR = Path("demo/phishing_samples")
LEGIT_DIR = Path("demo/legit_samples")
OUTPUT_DIR = Path("outputs/metrics")


def load_email_samples() -> tuple[List[str], List[str]]:
    """
    Load email samples from demo folders.
    
    Returns:
    --------
    phishing_samples : List[str]
        List of phishing email texts
    legit_samples : List[str]
        List of legitimate email texts
    """
    phishing_samples = []
    legit_samples = []
    
    # Load phishing samples
    for file_path in sorted(PHISHING_DIR.glob("*.txt")):
        phishing_samples.append(file_path.read_text(encoding='utf-8'))
    
    # Load legitimate samples
    for file_path in sorted(LEGIT_DIR.glob("*.txt")):
        legit_samples.append(file_path.read_text(encoding='utf-8'))
    
    print(f"📧 Loaded {len(phishing_samples)} phishing samples")
    print(f"📧 Loaded {len(legit_samples)} legitimate samples")
    
    return phishing_samples, legit_samples


def send_prediction_request(email_text: str) -> tuple[float, bool]:
    """
    Send a single prediction request and measure latency.
    
    Parameters:
    -----------
    email_text : str
        Email content to classify
        
    Returns:
    --------
    latency_ms : float
        Response time in milliseconds
    success : bool
        Whether request succeeded
    """
    start_time = time.perf_counter()
    
    try:
        response = requests.post(
            API_URL,
            json={"email_text": email_text},
            timeout=10
        )
        
        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000  # Convert to ms
        
        return latency_ms, response.status_code == 200
        
    except Exception as e:
        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000
        print(f"❌ Request failed: {str(e)}")
        return latency_ms, False


def calculate_metrics(latencies: List[float]) -> Dict:
    """
    Calculate comprehensive latency metrics.
    
    Parameters:
    -----------
    latencies : List[float]
        List of latency measurements in milliseconds
        
    Returns:
    --------
    metrics : dict
        Dictionary containing all calculated metrics
    """
    sorted_latencies = sorted(latencies)
    n = len(sorted_latencies)
    
    # Calculate percentiles
    p50 = statistics.median(sorted_latencies)  # Median
    p95_index = int(n * 0.95)
    p99_index = int(n * 0.99)
    p95 = sorted_latencies[p95_index] if p95_index < n else sorted_latencies[-1]
    p99 = sorted_latencies[p99_index] if p99_index < n else sorted_latencies[-1]
    
    # Calculate other metrics
    avg = statistics.mean(sorted_latencies)
    min_latency = min(sorted_latencies)
    max_latency = max(sorted_latencies)
    
    # Requests per second (based on average latency)
    rps = 1000 / avg if avg > 0 else 0
    
    # Percentage under 200ms
    under_200ms = sum(1 for l in sorted_latencies if l < 200)
    pct_under_200ms = (under_200ms / n) * 100 if n > 0 else 0
    
    return {
        'total_requests': n,
        'average_ms': round(avg, 2),
        'median_ms': round(p50, 2),
        'p95_ms': round(p95, 2),
        'p99_ms': round(p99, 2),
        'min_ms': round(min_latency, 2),
        'max_ms': round(max_latency, 2),
        'requests_per_second': round(rps, 2),
        'pct_under_200ms': round(pct_under_200ms, 2),
        'raw_latencies': [round(l, 2) for l in sorted_latencies]
    }


def print_ascii_chart(latencies: List[float], bins: int = 20):
    """
    Print ASCII histogram of latency distribution.
    
    Parameters:
    -----------
    latencies : List[float]
        List of latency measurements
    bins : int
        Number of histogram bins
    """
    sorted_latencies = sorted(latencies)
    min_lat = min(sorted_latencies)
    max_lat = max(sorted_latencies)
    
    # Create bins
    bin_size = (max_lat - min_lat) / bins
    if bin_size == 0:
        bin_size = 1
    
    histogram = [0] * bins
    
    for latency in sorted_latencies:
        bin_index = int((latency - min_lat) / bin_size)
        if bin_index >= bins:
            bin_index = bins - 1
        histogram[bin_index] += 1
    
    # Find max count for scaling
    max_count = max(histogram) if histogram else 1
    
    print("\n" + "="*60)
    print("LATENCY DISTRIBUTION (ms)")
    print("="*60)
    
    for i, count in enumerate(histogram):
        bin_start = min_lat + i * bin_size
        bin_end = bin_start + bin_size
        
        # Scale to 50 characters max
        bar_length = int((count / max_count) * 50) if max_count > 0 else 0
        bar = "█" * bar_length
        
        print(f"{bin_start:6.1f} - {bin_end:6.1f} ms | {bar} ({count})")
    
    print("="*60)


def print_results(metrics: Dict, success_rate: float):
    """
    Print formatted benchmark results.
    
    Parameters:
    -----------
    metrics : dict
        Calculated metrics
    success_rate : float
        Percentage of successful requests
    """
    print("\n" + "="*60)
    print("LATENCY BENCHMARK RESULTS")
    print("="*60)
    
    print(f"\n📊 Request Statistics:")
    print(f"  Total Requests:     {metrics['total_requests']}")
    print(f"  Success Rate:       {success_rate:.1f}%")
    print(f"  Requests/Second:    {metrics['requests_per_second']:.2f}")
    
    print(f"\n⏱️  Latency Metrics:")
    print(f"  Average:            {metrics['average_ms']:.2f} ms")
    print(f"  Median (P50):       {metrics['median_ms']:.2f} ms")
    print(f"  P95:                {metrics['p95_ms']:.2f} ms  {'✅' if metrics['p95_ms'] < TARGET_P95_MS else '❌'}")
    print(f"  P99:                {metrics['p99_ms']:.2f} ms")
    print(f"  Min:                {metrics['min_ms']:.2f} ms")
    print(f"  Max:                {metrics['max_ms']:.2f} ms")
    
    print(f"\n🎯 Performance:")
    print(f"  < 200ms:            {metrics['pct_under_200ms']:.1f}%")
    print(f"  < 500ms:            {sum(1 for l in metrics['raw_latencies'] if l < 500) / len(metrics['raw_latencies']) * 100:.1f}%")
    
    # PASS/FAIL determination
    print(f"\n{'='*60}")
    if metrics['p95_ms'] < TARGET_P95_MS:
        print(f"✅ PASS: P95 latency ({metrics['p95_ms']:.2f}ms) < {TARGET_P95_MS}ms target")
    else:
        print(f"❌ FAIL: P95 latency ({metrics['p95_ms']:.2f}ms) > {TARGET_P95_MS}ms target")
        print(f"   Action needed: Optimize performance or increase resources")
    print("="*60 + "\n")


def save_results(metrics: Dict, success_rate: float):
    """
    Save benchmark results to JSON file.
    
    Parameters:
    -----------
    metrics : dict
        Calculated metrics
    success_rate : float
        Success rate percentage
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'api_url': API_URL,
        'target_p95_ms': TARGET_P95_MS,
        'success_rate': success_rate,
        'metrics': metrics,
        'pass': metrics['p95_ms'] < TARGET_P95_MS
    }
    
    output_path = OUTPUT_DIR / "latency_report.json"
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"💾 Results saved to: {output_path}")


def run_benchmark():
    """
    Run the complete latency benchmark.
    """
    print("\n" + "="*60)
    print("PHISHING DETECTION API - LATENCY BENCHMARK")
    print("="*60 + "\n")
    
    # 1. Load samples
    try:
        phishing_samples, legit_samples = load_email_samples()
    except Exception as e:
        print(f"❌ Error loading samples: {str(e)}")
        print("   Make sure demo/phishing_samples/ and demo/legit_samples/ exist")
        sys.exit(1)
    
    if len(phishing_samples) < 50 or len(legit_samples) < 50:
        print(f"❌ Need at least 50 samples of each type")
        print(f"   Found: {len(phishing_samples)} phishing, {len(legit_samples)} legitimate")
        sys.exit(1)
    
    # 2. Prepare requests (50 phishing + 50 legitimate)
    test_samples = phishing_samples[:50] + legit_samples[:50]
    total_requests = len(test_samples)
    
    print(f"\n🚀 Starting benchmark: {total_requests} requests to {API_URL}")
    print(f"⏱️  Target: P95 < {TARGET_P95_MS}ms\n")
    
    # 3. Send requests and measure latency
    latencies = []
    successes = 0
    
    start_time = time.time()
    
    for i, email_text in enumerate(test_samples, 1):
        latency_ms, success = send_prediction_request(email_text)
        latencies.append(latency_ms)
        
        if success:
            successes += 1
        
        # Progress indicator
        if i % 10 == 0:
            print(f"  Progress: {i}/{total_requests} requests ({i/total_requests*100:.0f}%)")
    
    total_time = time.time() - start_time
    success_rate = (successes / total_requests) * 100
    
    print(f"\n✅ Benchmark completed in {total_time:.2f} seconds")
    print(f"   Success rate: {success_rate:.1f}%\n")
    
    # 4. Calculate metrics
    if not latencies:
        print("❌ No latency data collected")
        sys.exit(1)
    
    metrics = calculate_metrics(latencies)
    
    # 5. Print results
    print_results(metrics, success_rate)
    
    # 6. Show ASCII chart
    print_ascii_chart(latencies)
    
    # 7. Save to JSON
    save_results(metrics, success_rate)
    
    # 8. Exit with appropriate code
    if metrics['p95_ms'] < TARGET_P95_MS:
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # Failure


if __name__ == "__main__":
    try:
        run_benchmark()
    except KeyboardInterrupt:
        print("\n\n⚠️  Benchmark interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Benchmark failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
