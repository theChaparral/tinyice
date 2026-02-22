package server

import (
	"fmt"
	"strings"
)

// MetricType defines the type of Prometheus metric
type MetricType string

const (
	// Counter is a monotonically increasing value
	Counter MetricType = "counter"
	// Gauge is a numerical value that can go up and down
	Gauge MetricType = "gauge"
)

// Metric represents a single Prometheus metric point
type Metric struct {
	Name   string
	Help   string
	Type   MetricType
	Labels map[string]string
	Value  interface{}
}

// PrometheusRegistry handles collection and formatting of Prometheus metrics
type PrometheusRegistry struct {
	metrics []Metric
}

// NewPrometheusRegistry creates a new registry instance
func NewPrometheusRegistry() *PrometheusRegistry {
	return &PrometheusRegistry{
		metrics: make([]Metric, 0),
	}
}

// Add appends a new metric to the registry
func (r *PrometheusRegistry) Add(name, help string, mtype MetricType, labels map[string]string, value interface{}) {
	r.metrics = append(r.metrics, Metric{
		Name:   name,
		Help:   help,
		Type:   mtype,
		Labels: labels,
		Value:  value,
	})
}

// Render returns the Prometheus text-based presentation format
func (r *PrometheusRegistry) Render() string {
	var sb strings.Builder

	type metricGroup struct {
		help  string
		mtype MetricType
		items []Metric
	}

	groups := make(map[string]*metricGroup)
	var order []string

	for _, m := range r.metrics {
		if _, ok := groups[m.Name]; !ok {
			groups[m.Name] = &metricGroup{
				help:  m.Help,
				mtype: m.Type,
			}
			order = append(order, m.Name)
		}
		groups[m.Name].items = append(groups[m.Name].items, m)
	}

	for _, name := range order {
		g := groups[name]
		if g.help != "" {
			sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, g.help))
		}
		if g.mtype != "" {
			sb.WriteString(fmt.Sprintf("# TYPE %s %s\n", name, string(g.mtype)))
		}

		for _, m := range g.items {
			sb.WriteString(name)
			if len(m.Labels) > 0 {
				sb.WriteString("{")
				var labelParts []string
				for k, v := range m.Labels {
					// Basic escaping for label values
					escaped := strings.NewReplacer(
						`\`, `\\`,
						`"`, `\"`,
						"\n", `\n`,
					).Replace(v)
					labelParts = append(labelParts, fmt.Sprintf("%s=\"%s\"", k, escaped))
				}
				sb.WriteString(strings.Join(labelParts, ","))
				sb.WriteString("}")
			}

			// Format value
			valStr := ""
			switch v := m.Value.(type) {
			case float64:
				valStr = fmt.Sprintf("%g", v)
			case int, int64:
				valStr = fmt.Sprintf("%d", v)
			default:
				valStr = fmt.Sprintf("%v", v)
			}

			sb.WriteString(fmt.Sprintf(" %s\n", valStr))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
