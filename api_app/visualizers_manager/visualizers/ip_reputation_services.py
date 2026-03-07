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
    @visualizable_error_handler_with_params("VirusTotal")
    def _vt3(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="VirusTotal_v3_Get_Observable")
        except AnalyzerReport.DoesNotExist:
            logger.warning("VirusTotal_v3_Get_Observable report does not exist")
        else:
            stats = (
                analyzer_report.report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            )
            malicious_count = stats.get("malicious", 0)
            vt3_report = self.Bool(
                value="VirusTotal v3",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and malicious_count > 0),
            )
            return vt3_report

    @visualizable_error_handler_with_params("Greynoise")
    def _greynoise(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="GreyNoiseCommunity")
        except AnalyzerReport.DoesNotExist:
            logger.warning("GreynoiseCommunity report does not exist")
        else:
            classification = analyzer_report.report.get("classification", "")
            greynoise_report = self.Bool(
                value="Greynoise Community",
                disable=not (
                    analyzer_report.status == ReportStatus.SUCCESS
                    and classification in ["malicious", "unknown"]
                ),
            )
            return greynoise_report

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

    @visualizable_error_handler_with_params("ThreatFox")
    def _threatfox(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="ThreatFox")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Threatfox report does not exist")
        else:
            query_status = analyzer_report.report.get("query_status", "")
            threatfox_report = self.Bool(
                value="ThreatFox",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and query_status == "ok"),
            )
            return threatfox_report

    @visualizable_error_handler_with_params("InQuest")
    def _inquest_repdb(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="InQuest_REPdb")
        except AnalyzerReport.DoesNotExist:
            logger.warning("InQuest_REPdb report does not exist")
        else:
            data = analyzer_report.report.get("data", [])
            has_malicious = any(item.get("reputation") == "malicious" for item in data)
            inquest_report = self.Bool(
                value="InQuest",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and has_malicious),
            )
            return inquest_report

    @visualizable_error_handler_with_params("AbuseIPDB")
    def _abuseipdb(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="AbuseIPDB")
        except AnalyzerReport.DoesNotExist:
            logger.warning("AbuseIPDB report does not exist")
        else:
            report_data = analyzer_report.report.get("data", {})
            abuse_score = report_data.get("abuseConfidenceScore", 0)
            is_whitelisted = report_data.get("isWhitelisted", False)
            abuse_report = self.Bool(
                value="AbuseIPDB",
                disable=not (
                    analyzer_report.status == ReportStatus.SUCCESS and abuse_score > 0 and not is_whitelisted
                ),
            )
            return abuse_report

    @visualizable_error_handler_with_params("GreedyBear Honeypots")
    def _greedybear(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="GreedyBear")
        except AnalyzerReport.DoesNotExist:
            logger.warning("GreedyBear report does not exist")
        else:
            found = analyzer_report.report.get("found", False)
            gb_report = self.Bool(
                value="GreedyBear Honeypots",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and found),
            )
            return gb_report

    @visualizable_error_handler_with_params("Crowdsec")
    def _crowdsec(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Crowdsec")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Crowdsec report does not exist")
        else:
            classifications = analyzer_report.report.get("classifications", {})
            has_class = bool(classifications.get("classifications") or classifications.get("false_positives"))
            crowdsec_report = self.Bool(
                value="Crowdsec",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and has_class),
            )
            return crowdsec_report

    @visualizable_error_handler_with_params("OTX Alienvault")
    def _otxquery(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="OTXQuery")
        except AnalyzerReport.DoesNotExist:
            logger.warning("OTXQuery report does not exist")
        else:
            pulses = analyzer_report.report.get("pulses", [])
            otx_report = self.Bool(
                value="OTX Alienvault",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and pulses),
            )
            return otx_report

    @visualizable_error_handler_with_params("FireHol")
    def _firehol(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="FireHol_IPList")
        except AnalyzerReport.DoesNotExist:
            logger.warning("FireHol_IPList report does not exist")
        else:
            found_in_lists = any(found for report, found in analyzer_report.report.items())
            firehol_report = self.Bool(
                value="FireHol",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and found_in_lists),
            )
            return firehol_report

    @visualizable_error_handler_with_params("Tor Exit Node")
    def _tor(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="TorProject")
        except AnalyzerReport.DoesNotExist:
            logger.warning("TorProject report does not exist")
        else:
            found = analyzer_report.report.get("found", False)
            tor_report = self.Bool(
                value="Tor Exit Node",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and found),
            )
            return tor_report

    @visualizable_error_handler_with_params("Talos Reputation")
    def _talos(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="TalosReputation")
        except AnalyzerReport.DoesNotExist:
            logger.warning("TalosReputation report does not exist")
        else:
            email_score = analyzer_report.report.get("email_score", "unknown")
            web_score = analyzer_report.report.get("web_score", "unknown")
            has_bad_rep = any(score in ["poor", "neutral"] for score in [email_score, web_score])
            talos_report = self.Bool(
                value="Talos Reputation",
                disable=not (analyzer_report.status == ReportStatus.SUCCESS and has_bad_rep),
            )
            return talos_report

    def run(self) -> List[Dict]:
        first_level_elements = []
        second_level_elements = []
        third_level_elements = []

        first_level_elements.append(self._vt3())
        first_level_elements.append(self._greedybear())
        first_level_elements.append(self._greynoise())
        first_level_elements.append(self._crowdsec())
        first_level_elements.append(self._threatfox())
        first_level_elements.append(self._urlhaus())
        first_level_elements.append(self._inquest_repdb())
        first_level_elements.append(self._tor())
        second_level_elements.append(self._abuseipdb())
        second_level_elements.append(self._otxquery())
        third_level_elements.append(self._firehol())
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
