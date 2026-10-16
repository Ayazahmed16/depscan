from django.core.management.base import BaseCommand
from pyspark.sql import SparkSession


class Command(BaseCommand):
    def handle(self, *args, **options):
        SparkSession.builder.getOrCreate()
