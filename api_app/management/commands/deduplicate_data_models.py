from django.core.management.base import BaseCommand
from django.db import transaction
from api_app.data_model_manager.models import IPDataModel, DomainDataModel, FileDataModel
from django.contrib.contenttypes.models import ContentType
from api_app.analyzers_manager.models import AnalyzerReport
from api_app.models import Job
from api_app.user_events_manager.models import UserAnalyzableEvent
from django.db.models import Count
import json
import hashlib
import datetime
import uuid

def normalize_dict(data):
    if isinstance(data, dict):
        return {k: normalize_dict(v) for k, v in sorted(data.items())}
    if isinstance(data, list):
        try:
            return sorted(
                [normalize_dict(v) for v in data],
                key=lambda x: json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x)
            )
        except TypeError:
            return [normalize_dict(v) for v in data]
    if isinstance(data, (datetime.datetime, datetime.date)):
        return data.isoformat()
    if isinstance(data, uuid.UUID):
        return str(data)
    return data

def calculate_fingerprint(obj, model_class):
    excluded = {"id", "date", "fingerprint", "analyzers_report", "jobs", "user_events"}
    data = {}
    for field in model_class._meta.get_fields():
        if field.name in excluded or (field.is_relation and not field.many_to_many):
            continue
        val = getattr(obj, field.name)
        if field.many_to_many:
            rel = list(val.all().values())
            if rel:
                for o in rel: o.pop("id", None)
                data[field.name] = rel
        elif val:
            data[field.name] = val
    normalized = normalize_dict(data)
    json_str = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()

class Command(BaseCommand):
    help = 'Deduplicate existing data models with identical fingerprints'

    def handle(self, *args, **options):
        models = [IPDataModel, DomainDataModel, FileDataModel]
        for Model in models:
            self.stdout.write(f"Processing {Model.__name__}...")
            
            # 1. Backfill fingerprints for records that don't have one
            for obj in Model.objects.filter(fingerprint__isnull=True):
                obj.fingerprint = calculate_fingerprint(obj, Model)
                obj.save(update_fields=['fingerprint'])
            
            # 2. Identify and merge duplicates
            duplicates = (
                Model.objects.values('fingerprint')
                .annotate(count=Count('id'))
                .filter(count__gt=1, fingerprint__isnull=False)
            )
            for dup in duplicates:
                fp = dup['fingerprint']
                all_records = list(Model.objects.filter(fingerprint=fp).order_by('date'))
                canonical = all_records[0]
                to_delete = all_records[1:]
                self.stdout.write(f"  Merging {len(to_delete)} duplicates into canonical ID {canonical.id}")
                with transaction.atomic():
                    ct = ContentType.objects.get_for_model(Model)
                    for duplicate in to_delete:
                        AnalyzerReport.objects.filter(data_model_content_type=ct, data_model_object_id=duplicate.id).update(data_model_object_id=canonical.id)
                        Job.objects.filter(data_model_content_type=ct, data_model_object_id=duplicate.id).update(data_model_object_id=canonical.id)
                        UserAnalyzableEvent.objects.filter(data_model_content_type=ct, data_model_object_id=duplicate.id).update(data_model_object_id=canonical.id)
                        duplicate.delete()
            self.stdout.write(self.style.SUCCESS(f"Finished {Model.__name__}"))
