package datadog

import (
	"context"

	"github.com/spf13/viper"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func InitializeDatadog(ctx context.Context) {
	if !IsDataDogEnabled(ctx) {
		return
	}

	// Initialize the Datadog tracer
	tracer.Start(
		tracer.WithService(viper.GetString("datadog.service_name")),
		tracer.WithEnv(viper.GetString("datadog.env")),
		tracer.WithTraceEnabled(viper.GetBool("datadog.tracing.enabled")),
		tracer.WithAgentAddr(viper.GetString("datadog.agent_address")),
	)
}

func IsDataDogEnabled(ctx context.Context) bool {
	return viper.GetBool("datadog.enabled")
}

func NoticeError(ctx context.Context, err error) (tracer.Span, context.Context) {
	return tracer.StartSpanFromContext(ctx, err.Error())
}
