# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.test import TestCase

from api_app.choices import Classification
from api_app.helpers import calculate_json_fingerprint, normalize_dict


class HelperTests(TestCase):
    def test_normalize_dict(self):
        data = {"b": 2, "a": 1, "c": {"z": 26, "y": 25}}
        expected = {"a": 1, "b": 2, "c": {"y": 25, "z": 26}}
        self.assertEqual(normalize_dict(data), expected)
        self.assertEqual(list(normalize_dict(data).keys()), ["a", "b", "c"])
        self.assertEqual(list(normalize_dict(data)["c"].keys()), ["y", "z"])

    def test_calculate_json_fingerprint(self):
        data1 = {"a": 1, "b": {"x": 10, "y": 20}}
        data2 = {"b": {"y": 20, "x": 10}, "a": 1}
        fp1 = calculate_json_fingerprint(data1)
        fp2 = calculate_json_fingerprint(data2)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)

    def test_accept_defanged_domains(self):
        observable = "www\.test\.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

        observable = "www[.]test[.]com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

    def test_calculate_observable_classification(self):
        observable = "7.7.7.7"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.IP)

        observable = "www.test.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

        observable = ".www.test.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

        observable = "ftp://www.test.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.URL)

        observable = "b318ff1839771c22e50d316af613dc70"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.HASH)

        observable = "iammeia"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.GENERIC)
