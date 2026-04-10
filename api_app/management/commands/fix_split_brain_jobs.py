# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.core.management.base import BaseCommand
from django.db import connection, transaction
from django.db.models import Count

from api_app.models import Job


class Command(BaseCommand):
    help = "Fixes Split-Brain scenarios in Jobs by merging duplicate path entries."

    def handle(self, *args, **options):
        duplicates = Job.objects.values("path").annotate(path_count=Count("id")).filter(path_count__gt=1)

        if not duplicates:
            self.stdout.write(self.style.SUCCESS("No split-brain jobs found."))
            return

        self.stdout.write(self.style.WARNING(f"Found {len(duplicates)} duplicate paths."))

        for entry in duplicates:
            path = entry["path"]
            jobs = list(Job.objects.filter(path=path).order_by("id"))

            winner = jobs[0]
            losers = jobs[1:]

            self.stdout.write(f"\nMerging into winner Job PK={winner.pk} (path='{path}')")

            with transaction.atomic():
                for loser in losers:
                    self.stdout.write(f"  Processing loser Job PK={loser.pk}...")

                    tags = list(loser.tags.all())
                    if tags:
                        winner.tags.add(*tags)
                        self.stdout.write(f"    Moved {len(tags)} tags")

                    for report_type in [
                        "analyzerreports",
                        "connectorreports",
                        "visualizerreports",
                        "pivotreports",
                        "ingestorreports",
                    ]:
                        if hasattr(loser, report_type):
                            reports_count = getattr(loser, report_type).update(job=winner)
                            if reports_count:
                                self.stdout.write(f"    Moved {reports_count} {report_type}")

                    try:
                        comment_count = loser.comments.update(job=winner)
                        self.stdout.write(f"    Moved {comment_count} comments")
                    except Exception:
                        pass

                    if not winner.investigation and loser.investigation:
                        winner.investigation = loser.investigation
                        winner.save()
                        self.stdout.write("    Transferred investigation")

                    loser_id = loser.pk
                    with connection.cursor() as cursor:
                        cursor.execute("DELETE FROM api_app_job WHERE id = %s", [loser_id])
                    self.stdout.write(self.style.SUCCESS(f"  Deleted ghost Job PK={loser_id}"))

        self.stdout.write(self.style.SUCCESS("\nCleanup complete."))
