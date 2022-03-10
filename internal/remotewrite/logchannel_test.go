package remotewrite

import (
	"testing"
	"time"

	"github.com/observatorium/observatorium/internal"
)

func getTimePointer(d time.Duration) *time.Time {
	testTime := time.Now().Add(-d)
	return &testTime
}

func TestCheckLog(t *testing.T) {
	caseList := []struct {
		name                       string
		counter                    *logCounter
		key                        string
		expected_logKey            string
		expected_reducedLog        bool
		expected_logTimeStampsSize int
		expected_logNumber         int64
	}{
		{
			name: "different log event",
			counter: &logCounter{
				logKey:        "key",
				reducedLog:    true,
				LogTimestamps: []time.Time{time.Now()},
			},
			key:                        "other_key",
			expected_logKey:            "other_key",
			expected_reducedLog:        false,
			expected_logTimeStampsSize: 1,
			expected_logNumber:         int64(0),
		},
		{
			name: "reduce log",
			counter: &logCounter{
				logKey:        "key",
				reducedLog:    true,
				LogTimestamps: []time.Time{},
				logStartTime:  getTimePointer(logInterval),
				logNumber:     100,
			},
			key:                        "key",
			expected_logKey:            "key",
			expected_reducedLog:        true,
			expected_logTimeStampsSize: 0,
			expected_logNumber:         int64(0),
		},
		{
			name: "cancel reduce log",
			counter: &logCounter{
				logKey:        "key",
				reducedLog:    true,
				LogTimestamps: []time.Time{},
				logStartTime:  getTimePointer(logInterval),
				logNumber:     1,
			},
			key:                        "key",
			expected_logKey:            "key",
			expected_reducedLog:        false,
			expected_logTimeStampsSize: 0,
			expected_logNumber:         int64(1),
		},
		{
			name: "log event plus one",
			counter: &logCounter{
				logKey:        "key",
				reducedLog:    true,
				LogTimestamps: []time.Time{},
				logStartTime:  getTimePointer(100 * time.Second),
				logNumber:     100,
			},
			key:                        "key",
			expected_logKey:            "key",
			expected_reducedLog:        true,
			expected_logTimeStampsSize: 0,
			expected_logNumber:         int64(101),
		},
		{
			name: "log timestamps plus one",
			counter: &logCounter{
				logKey:        "key",
				reducedLog:    false,
				LogTimestamps: []time.Time{time.Now()},
				logStartTime:  nil,
				logNumber:     0,
			},
			key:                        "key",
			expected_logKey:            "key",
			expected_reducedLog:        false,
			expected_logTimeStampsSize: 2,
			expected_logNumber:         int64(0),
		},
		{
			name: "enable reduce log",
			counter: &logCounter{
				logKey:        "key",
				reducedLog:    false,
				LogTimestamps: []time.Time{time.Now(), time.Now(), time.Now()},
				logStartTime:  nil,
				logNumber:     0,
			},
			key:                        "key",
			expected_logKey:            "key",
			expected_reducedLog:        true,
			expected_logTimeStampsSize: 0,
			expected_logNumber:         int64(1),
		},
		{
			name: "reset log timestamps",
			counter: &logCounter{
				logKey:        "key",
				reducedLog:    false,
				LogTimestamps: []time.Time{time.Now().Add(-700 * time.Second), time.Now(), time.Now()},
				logStartTime:  nil,
				logNumber:     0,
			},
			key:                        "key",
			expected_logKey:            "key",
			expected_reducedLog:        false,
			expected_logTimeStampsSize: 3,
			expected_logNumber:         int64(0),
		},
	}

	logger := internal.NewLogger("debug", "", "")
	logMaxCount = int64(3)
	for _, c := range caseList {
		t.Run(c.name, func(t *testing.T) {
			checkLog(logger, c.counter, c.key, []interface{}{"msg", "test"}...)
			if c.counter.logKey != c.expected_logKey {
				t.Errorf("case (%v) logKey: (%v) is not the expected: (%v)", c.name, c.counter.logKey,
					c.expected_logKey)
			} else if c.counter.reducedLog != c.expected_reducedLog {
				t.Errorf("case (%v) reducedLog: (%v) is not the expected: (%v)", c.name, c.counter.reducedLog,
					c.expected_reducedLog)
			} else if c.counter.logNumber != c.expected_logNumber {
				t.Errorf("case (%v) logNumber : (%v) is not the expected: (%v)", c.name, c.counter.logNumber,
					c.expected_logNumber)
			} else if len(c.counter.LogTimestamps) != c.expected_logTimeStampsSize {
				t.Errorf("case (%v) logTimeStampsSize: (%v) is not the expected: (%v)",
					c.name, len(c.counter.LogTimestamps), c.expected_logTimeStampsSize)
			}
		})
	}
}
