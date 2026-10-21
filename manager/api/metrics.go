package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
)

type metricsService struct{ s *Server }

func (m *metricsService) GetCrowdSecMetrics(ctx context.Context, req *connect.Request[apiv1.GetCrowdSecMetricsRequest]) (*connect.Response[apiv1.GetCrowdSecMetricsResponse], error) {
	if m.s.cfg.Metrics == nil || !m.s.cfg.Metrics.Configured() {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no CrowdSec metrics endpoint is configured"))
	}
	res, err := m.s.cfg.Metrics.Get(ctx, req.Msg.GetEndpoint())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(res), nil
}
