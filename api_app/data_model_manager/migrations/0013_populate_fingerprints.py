import hashlib
import json
import logging
from django.db import migrations

logger = logging.getLogger(__name__)

def normalize_dict(obj):
    if isinstance(obj, dict):
        return {k: normalize_dict(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [normalize_dict(i) for i in obj]
    return obj

def generate_fingerprint_from_instance(instance):
    data = {}
    for field in instance._meta.fields:
        name = field.name
        if name in ["id", "date", "fingerprint"]:
            continue
        value = getattr(instance, name)
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        data[name] = value
    normalized_data = normalize_dict(data)
    encoded_data = json.dumps(normalized_data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded_data).hexdigest()

def populate_fingerprints(apps, schema_editor):
    for model_name in ["IPDataModel", "DomainDataModel", "FileDataModel"]:
        Model = apps.get_model("data_model_manager", model_name)
        for instance in Model.objects.filter(fingerprint="").iterator():
            instance.fingerprint = generate_fingerprint_from_instance(instance)
            instance.save(update_fields=["fingerprint"])

def reverse_populate_fingerprints(apps, schema_editor):
    pass

class Migration(migrations.Migration):

    dependencies = [
        ('data_model_manager', '0012_domaindatamodel_fingerprint_and_more'),
    ]

    operations = [
        migrations.RunPython(populate_fingerprints, reverse_populate_fingerprints),
    ]
