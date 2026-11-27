import prometheus_client

from ..views import BaseHandler


class Metrics(BaseHandler):
    async def get(self):
        if self.get_argument('view', None) == 'public':
            self._write_public()
            return
        self.application.purge_offline_worker_metrics()
        self.write(prometheus_client.generate_latest())
        self.set_header("Content-Type", "text/plain")

    def _write_public(self):
        metrics = self.application.events.state.metrics
        self.write(metrics.public.render())
        self.set_header("Content-Type", prometheus_client.CONTENT_TYPE_LATEST)


class PublicMetrics(Metrics):
    async def get(self):
        self._write_public()


class Healthcheck(BaseHandler):
    async def get(self):
        self.write("OK")
