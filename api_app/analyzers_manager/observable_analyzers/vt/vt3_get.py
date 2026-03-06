# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.mixins import VirusTotalv3AnalyzerMixin


class VirusTotalv3(ObservableAnalyzer, VirusTotalv3AnalyzerMixin):
    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        result = self._vt_get_report(
            self.observable_classification,
            self.observable_name,
        )
        return result

    def _update_data_model(self, data_model) -> None:
        super()._update_data_model(data_model)
        report = self.report.report
        attributes = report.get("data", {}).get("attributes", {})
        data_model.additional_info = {
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "tags": attributes.get("tags"),
            "categories": attributes.get("categories"),
        }
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            data_model.evaluation = self.EVALUATIONS.MALICIOUS.value
            data_model.reliability = min(malicious, 10)
        elif stats.get("harmless", 0) > 0:
            data_model.evaluation = self.EVALUATIONS.TRUSTED.value
            data_model.reliability = 7
