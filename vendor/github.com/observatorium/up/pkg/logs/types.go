package logs

type queryResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string   `json:"resultType"`
		Result     []stream `json:"result"`
	} `json:"data"`
}

// PushRequest reprents the payload to push logs to Loki.
type PushRequest struct {
	Streams []stream `json:"streams"`
}

type stream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}
