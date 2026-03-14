from django.core.management.base import BaseCommand
from django.db import transaction, IntegrityError
from django.db.models import Count
from django.contrib.contenttypes.models import ContentType
from api_app.data_model_manager.models import IPDataModel, DomainDataModel, FileDataModel
from api_app.analyzers_manager.models import AnalyzerReport
from api_app.models import Job
from api_app.user_events_manager.models import UserAnalyzableEvent
from api_app.helpers import calculate_json_fingerprint

class Command(BaseCommand):
    help = "Deduplicate existing data models with identical fingerprints"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be merged without making changes",
        )

    def calculate_obj_fingerprint(self, obj, model_class):
        excluded = {"id", "date", "fingerprint", "analyzers_report", "jobs", "user_events"}
        data = {}
        for field in model_class._meta.get_fields():
            if field.name in excluded or (field.is_relation and not field.many_to_many):
                continue
            try:
                val = getattr(obj, field.name)
            except AttributeError:
                continue
            if field.many_to_many:
                rel = list(val.all().values())
                if rel:
                    for o in rel:
                        o.pop("id", None)
                    data[field.name] = rel
            elif val is not None and val != "" and val != [] and val != {}:
                data[field.name] = val
        return calculate_json_fingerprint(data)

    def merge_records(self, Model, canonical, duplicate):
        ct = ContentType.objects.get_for_model(Model)
        AnalyzerReport.objects.filter(
            data_model_content_type=ct, data_model_object_id=duplicate.id
        ).update(data_model_object_id=canonical.id)
        Job.objects.filter(
            data_model_content_type=ct, data_model_object_id=duplicate.id
        ).update(data_model_object_id=canonical.id)
        UserAnalyzableEvent.objects.filter(
            data_model_content_type=ct, data_model_object_id=duplicate.id
        ).update(data_model_object_id=canonical.id)
        duplicate.delete()

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN: No changes will be saved."))
        models = [IPDataModel, DomainDataModel, FileDataModel]
        for Model in models:
            self.stdout.write(f"Processing {Model.__name__}...")
            records_to_fingerprint = Model.objects.filter(fingerprint__isnull=True)
            self.stdout.write(f"  Backfilling fingerprints for {records_to_fingerprint.count()} records...")
            for obj in records_to_fingerprint:
                fp = self.calculate_obj_fingerprint(obj, Model)
                if dry_run:
                    continue
                try:
                    with transaction.atomic():
                        obj.fingerprint = fp
                        obj.save(update_fields=["fingerprint"])
                except IntegrityError:
                    canonical = Model.objects.get(fingerprint=fp)
                    self.stdout.write(f"    Merging duplicate ID {obj.id} into existing ID {canonical.id}")
                    self.merge_records(Model, canonical, obj)
            duplicates = (
                Model.objects.values("fingerprint")
                .annotate(count=Count("id"))
                .filter(count__gt=1, fingerprint__isnull=False)
            )
            for dup in duplicates:
                fp = dup["fingerprint"]
                all_records = list(Model.objects.filter(fingerprint=fp).order_by("date"))
                canonical = all_records[0]
                to_delete = all_records[1:]
                self.stdout.write(
                    f"  Merging {len(to_delete)} duplicates into canonical ID {canonical.id} (FP: {fp[:8]}...)"
                )
                if not dry_run:
                    with transaction.atomic():
                        for duplicate in to_delete:
                            self.merge_records(Model, canonical, duplicate)
            self.stdout.write(self.style.SUCCESS(f"Finished processing {Model.__name__}"))
