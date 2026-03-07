from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.choices import ReportStatus
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)

logger = getLogger(__name__)


class IPReputationServices(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    @visualizable_error_handler_with_params("AbuseIPDB")
    def _abuseipdb(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="AbuseIPDB")
        except AnalyzerReport.DoesNotExist:
            logger.warning("AbuseIPDB report does not exist")
        else:
            report_data = analyzer_report.report.get("data", {})
            abuse_confidence_score = report_data.get("abuseConfidenceScore", None)
            abuse_report = self.VList(
                name=self.Base(
                    value="AbuseIPDB",
                    disable=not (
                        analyzer_report.status == ReportStatus.SUCCESS and abuse_confidence_score is not None
                    ),
                ),
                value=[
                    self.Base(
                        value="AbuseIPDB Meta",
                        description=(
                            "AbuseIPDB is a service where users can report malicious IP addresses attacking "
                            + "their infrastructure."
                        ),
                    ),
                    self.Base(
                        value=f"Confidence Score: {abuse_confidence_score}",
                    ),
                    self.VList(
                        name=self.Base(
                            value="AbuseIPDB Categories",
                            disable=not bool(analyzer_report.report.get("categories_found", {})),
                        ),
                        value=[
                            self.Base(value=cat)
                            for cat in analyzer_report.report.get("categories_found", {}).keys()
                        ],
                        disable=not bool(analyzer_report.report.get("categories_found", {})),
                        start_open=False,
                    ),
                ],
                disable=not (
                    analyzer_report.status == ReportStatus.SUCCESS and abuse_confidence_score is not None
                ),
            )
            return abuse_report

    @visualizable_error_handler_with_params("VirusTotal v3")
    def _vt3(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="VirusTotal_v3_Get_Observable")
        except AnalyzerReport.DoesNotExist:
            logger.warning("VirusTotal_v3_Get_Observable report does not exist")
        else:
            attributes = analyzer_report.report.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            vt3_report = self.Bool(
                value="VirusTotal v3",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and malicious_count > 0),
            )
            return vt3_report

    @visualizable_error_handler_with_params("GreedyBear")
    def _greedybear(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="GreedyBear")
        except AnalyzerReport.DoesNotExist:
            logger.warning("GreedyBear report does not exist")
        else:
            found = analyzer_report.report.get("found", False)
            greedybear_report = self.Bool(
                value="GreedyBear",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and found),
            )
            return greedybear_report

    @visualizable_error_handler_with_params("GreyNoise Community")
    def _greynoise_community(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="GreyNoiseCommunity")
        except AnalyzerReport.DoesNotExist:
            logger.warning("GreyNoiseCommunity report does not exist")
        else:
            noise = analyzer_report.report.get("noise", False)
            greynoise_community_report = self.Bool(
                value="GreyNoise Community",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and noise),
            )
            return greynoise_community_report

    @visualizable_error_handler_with_params("Crowdsec")
    def _crowdsec(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Crowdsec")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Crowdsec report does not exist")
        else:
            found = analyzer_report.report.get("found", False)
            crowdsec_report = self.Bool(
                value="Crowdsec",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and found),
            )
            return crowdsec_report

    @visualizable_error_handler_with_params("ThreatFox")
    def _threatfox(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="ThreatFox")
        except AnalyzerReport.DoesNotExist:
            logger.warning("ThreatFox report does not exist")
        else:
            query_status = analyzer_report.report.get("query_status", "")
            threatfox_report = self.Bool(
                value="ThreatFox",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and query_status == "ok"),
            )
            return threatfox_report

    @visualizable_error_handler_with_params("URLhaus")
    def _urlhaus(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="URLhaus")
        except AnalyzerReport.DoesNotExist:
            logger.warning("URLhaus report does not exist")
        else:
            query_status = analyzer_report.report.get("query_status", "")
            urlhaus_report = self.Bool(
                value="URLhaus",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and query_status == "ok"),
            )
            return urlhaus_report

    @visualizable_error_handler_with_params("InQuest REPdb")
    def _inquest(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="InQuest_REPdb")
        except AnalyzerReport.DoesNotExist:
            logger.warning("InQuest_REPdb report does not exist")
        else:
            found = analyzer_report.report.get("found", False)
            inquest_report = self.Bool(
                value="InQuest REPdb",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and found),
            )
            return inquest_report

    @visualizable_error_handler_with_params("Tor Project")
    def _tor(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="TorProject")
        except AnalyzerReport.DoesNotExist:
            logger.warning("TorProject report does not exist")
        else:
            is_exit_node = analyzer_report.report.get("is_exit_node", False)
            tor_report = self.Bool(
                value="Tor Project",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and is_exit_node),
            )
            return tor_report

    @visualizable_error_handler_with_params("OTXQuery")
    def _otxquery(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="OTXQuery")
        except AnalyzerReport.DoesNotExist:
            logger.warning("OTXQuery report does not exist")
        else:
            pulses = analyzer_report.report.get("pulses", [])
            otxquery_report = self.Bool(
                value="OTXQuery",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and len(pulses) > 0),
            )
            return otxquery_report

    @visualizable_error_handler_with_params("Talos Reputation")
    def _talos(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="TalosReputation")
        except AnalyzerReport.DoesNotExist:
            logger.warning("TalosReputation report does not exist")
        else:
            found = analyzer_report.report.get("found", False)
            talos_report = self.Bool(
                value="Talos Reputation",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and found),
            )
            return talos_report

    def run(self) -> List[Dict]:
        first_level_elements = []
        second_level_elements = []
        third_level_elements = []

        first_level_elements.append(self._vt3())
        first_level_elements.append(self._greedybear())
        first_level_elements.append(self._greynoise_community())
        first_level_elements.append(self._crowdsec())
        first_level_elements.append(self._threatfox())
        first_level_elements.append(self._urlhaus())
        first_level_elements.append(self._inquest())
        first_level_elements.append(self._tor())
        second_level_elements.append(self._abuseipdb())
        second_level_elements.append(self._otxquery())
        third_level_elements.append(self._talos())

        page = self.Page(name="Reputation")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=first_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=second_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=third_level_elements),
            )
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
