# Benchmark baseline results

Generated with:

```
load.sh [-h] [-r n] [-c n] [-m n] [-q n] [-o csv|gnuplot] -- program to test synthetic load on observatorium gateway and report results.

where:
    -h  show this help text
    -r  set number of seconds to run (default: 300)
    -c  set number of cluster to simulate (default: 5000)
    -m  set number of machines per cluster to simulate (default: 2)
    -q  set number of concurrent queries to execute (default: 10)
    -o  set the output format (default: csv. options: csv, gnuplot)
```

```
./test/load.sh -r 300 -c 5000 -m 1 -q 5 -o gnuplot
```

## CPU Usage

![./loadtests/cpu.png](./loadtests/cpu.png)

## Memory Usage

![./loadtests/mem.png](./loadtests/mem.png)

## Number of Goroutines

![./loadtests/goroutines.png](./loadtests/goroutines.png)

## Write Latency Qunatiles

### 99th

![./loadtests/write_dur_99.png](./loadtests/write_dur_99.png)

### 50th

![./loadtests/write_dur_50.png](./loadtests/write_dur_50.png)

### Average

![./loadtests/write_dur_avg.png](./loadtests/write_dur_avg.png)

## Query Latency Qunatiles

### 99th

![./loadtests/query_dur_99.png](./loadtests/query_dur_99.png)

### 50th

![./loadtests/query_dur_50.png](./loadtests/query_dur_50.png)

### Average

![./loadtests/query_dur_avg.png](./loadtests/query_dur_avg.png)
