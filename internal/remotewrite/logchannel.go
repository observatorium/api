package remotewrite

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

const (
	successWrite = "metrics forwarded successfully"
)

var (
	logMaxCount = int64(10)
	logInterval = 600 * time.Second

	LogChannels = []chan logMessage{}
)

type logMessage struct {
	messageKey string
	keyvals    []interface{}
}

type logCounter struct {
	// key for one log event
	logKey string
	// timestamps for last several log event
	LogTimestamps []time.Time
	// start timestamp of one log interval
	logStartTime *time.Time
	// number of log events in one log interval
	logNumber int64
	// flag for whether reduce the log
	reducedLog bool
}

func revertCounter(counter *logCounter) {
	if counter.reducedLog {
		counter.reducedLog = false
		counter.LogTimestamps = []time.Time{}
	}
}

func InitChannels(logger log.Logger, size int) {
	if os.Getenv("LOG_MAX_COUNT") != "" {
		v, err := strconv.ParseInt(os.Getenv("LOG_MAX_COUNT"), 10, 0)
		if err != nil {
			logMaxCount = v
		}
	}
	if os.Getenv("LOG_INTERVAL") != "" {
		v, err := time.ParseDuration(os.Getenv("LOG_INTERVAL"))
		if err != nil {
			logInterval = v
		}
	}
	for i := 0; i < size; i++ {
		LogChannels = append(LogChannels, make(chan logMessage))
	}
	for i := 0; i < size; i++ {
		j := i
		counter := &logCounter{
			LogTimestamps: []time.Time{},
		}
		go func() {
			for {
				select {
				case message := <-LogChannels[j]:
					if message.messageKey == successWrite {
						revertCounter(counter)
					} else {
						checkLog(logger, counter, message.messageKey, message.keyvals...)
					}
				case <-time.After(logInterval):
					revertCounter(counter)
				}
			}
		}()
	}
}

// checkLog checks the log events and log them
// if same log event occurs logMaxCount times within logInterval, start reduce log for this log event
func checkLog(logger log.Logger, counter *logCounter, key string, keyvals ...interface{}) {
	// got different log event, start to count from zero
	if key != counter.logKey {
		counter.logKey = key
		counter.LogTimestamps = []time.Time{time.Now()}
		counter.reducedLog = false
		level.Error(logger).Log(keyvals...)
		return
	}
	if counter.reducedLog {
		if time.Since(*counter.logStartTime) >= logInterval {
			// log the summary info in last interval
			message := fmt.Sprintf("Error occurred %d times in last %d seconds: %s",
				counter.logNumber, int(time.Since(*counter.logStartTime).Seconds()), key)
			keyvals[1] = message
			level.Error(logger).Log(keyvals...)
			if counter.logNumber < logMaxCount { // if same log events number less than c, stop reduce log
				counter.reducedLog = false
				counter.LogTimestamps = []time.Time{}
			} else { // start to count log event number in a new interval
				counter.logNumber = 0
				now := time.Now()
				counter.logStartTime = &now
			}
		} else {
			counter.logNumber = counter.logNumber + 1
		}
	} else {
		if int64(len(counter.LogTimestamps)) == logMaxCount {
			// if same log events number equals to logMaxCount within logInterval, start to reduce log
			if time.Since(counter.LogTimestamps[0]) <= logInterval {
				counter.reducedLog = true
				counter.LogTimestamps = []time.Time{}
				counter.logNumber = 1
				now := time.Now()
				counter.logStartTime = &now
			} else {
				counter.LogTimestamps[0] = time.Time{}
				counter.LogTimestamps = counter.LogTimestamps[1:]
				counter.LogTimestamps = append(counter.LogTimestamps, time.Now())
				level.Error(logger).Log(keyvals...)
			}
		} else {
			counter.LogTimestamps = append(counter.LogTimestamps, time.Now())
			level.Error(logger).Log(keyvals...)
		}
	}
}
