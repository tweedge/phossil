from pathlib import Path

import aws_cdk as cdk
from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_lambda_event_sources as event_sources
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sqs as sqs

from phossil.bundling import bundled_lambda_code

LAMBDAS_DIR = Path(__file__).resolve().parent.parent / "lambdas"


class PhossilStack(Stack):
    def __init__(self, scope, construct_id, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        removal_policy = (
            RemovalPolicy.DESTROY
            if self.node.try_get_context("removalPolicy") != "retain"
            else RemovalPolicy.RETAIN
        )
        log_retention = logs.RetentionDays.THREE_MONTHS

        known_urls_table = dynamodb.Table(
            self,
            "KnownPhishingURLs",
            table_name="phossil-known-phishing-urls",
            partition_key=dynamodb.Attribute(
                name="phishing_url", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=removal_policy,
        )

        url_relationships_table = dynamodb.Table(
            self,
            "URLRelationships",
            table_name="phossil-url-relationships",
            partition_key=dynamodb.Attribute(
                name="relationship_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=removal_policy,
        )

        archive_relationships_table = dynamodb.Table(
            self,
            "ArchiveRelationships",
            table_name="phossil-archive-relationships",
            partition_key=dynamodb.Attribute(
                name="relationship_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=removal_policy,
        )

        archive_bucket = s3.Bucket(
            self,
            "ArchiveBucket",
            bucket_name_prefix="phossil-archive",
            bucket_namespace=s3.BucketNamespace.ACCOUNT_REGIONAL,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=removal_policy,
            auto_delete_objects=(removal_policy == RemovalPolicy.DESTROY),
        )

        url_fetch_dlq = sqs.Queue(
            self,
            "URLFetchDLQ",
            queue_name="phossil-url-fetch-dlq.fifo",
            fifo=True,
            retention_period=Duration.days(14),
            removal_policy=removal_policy,
        )

        download_dlq = sqs.Queue(
            self,
            "DownloadDLQ",
            queue_name="phossil-download-dlq.fifo",
            fifo=True,
            retention_period=Duration.days(14),
            removal_policy=removal_policy,
        )

        url_fetch_queue = sqs.Queue(
            self,
            "URLFetchQueue",
            queue_name="phossil-url-fetch-queue.fifo",
            fifo=True,
            content_based_deduplication=True,
            visibility_timeout=Duration.seconds(360),
            retention_period=Duration.days(8),
            dead_letter_queue=sqs.DeadLetterQueue(
                queue=url_fetch_dlq, max_receive_count=3
            ),
            removal_policy=removal_policy,
        )

        download_queue = sqs.Queue(
            self,
            "DownloadQueue",
            queue_name="phossil-download-queue.fifo",
            fifo=True,
            content_based_deduplication=True,
            visibility_timeout=Duration.seconds(1080),
            retention_period=Duration.days(8),
            dead_letter_queue=sqs.DeadLetterQueue(queue=download_dlq, max_receive_count=3),
            removal_policy=removal_policy,
        )

        ingress_function = lambda_.Function(
            self,
            "IngressPhishTank",
            function_name="phossil-ingress-phishtank",
            description="Fetches verified phishing URLs from PhishTank, deduplicates them, and queues phishing sites to scan",
            runtime=lambda_.Runtime.PYTHON_3_14,
            architecture=lambda_.Architecture.ARM_64,
            code=bundled_lambda_code(LAMBDAS_DIR / "phossil-ingress-phishtank", lambda_.Runtime.PYTHON_3_14),
            handler="lambda_function.lambda_handler",
            memory_size=1024,
            timeout=Duration.seconds(300),
            environment={
                "PHOSSIL_KNOWN_URLS_TABLE": known_urls_table.table_name,
                "PHOSSIL_URL_FETCH_QUEUE_URL": url_fetch_queue.queue_url,
            },
            log_retention=log_retention,
        )
        known_urls_table.grant_read_write_data(ingress_function)
        url_fetch_queue.grant_send_messages(ingress_function)

        url_fetch_function = lambda_.Function(
            self,
            "URLFetch",
            function_name="phossil-url-fetch",
            description="Fetches queued phishing sites, records href relationships, and queues worthwhile downloads",
            runtime=lambda_.Runtime.PYTHON_3_14,
            architecture=lambda_.Architecture.ARM_64,
            code=bundled_lambda_code(LAMBDAS_DIR / "phossil-url-fetch", lambda_.Runtime.PYTHON_3_14),
            handler="lambda_function.lambda_handler",
            memory_size=256,
            timeout=Duration.seconds(300),
            environment={
                "PHOSSIL_URL_RELATIONSHIPS_TABLE": url_relationships_table.table_name,
                "PHOSSIL_DOWNLOAD_QUEUE_URL": download_queue.queue_url,
            },
            log_retention=log_retention,
        )
        url_relationships_table.grant_write_data(url_fetch_function)
        download_queue.grant_send_messages(url_fetch_function)
        url_fetch_function.add_event_source(
            event_sources.SqsEventSource(url_fetch_queue, batch_size=1)
        )

        download_function = lambda_.Function(
            self,
            "DownloadAndArchive",
            function_name="phossil-download-and-archive",
            description="Downloads queued files from phishing sites, hashes them, and archives unique files to S3",
            runtime=lambda_.Runtime.PYTHON_3_14,
            architecture=lambda_.Architecture.ARM_64,
            code=bundled_lambda_code(LAMBDAS_DIR / "phossil-download-and-archive", lambda_.Runtime.PYTHON_3_14),
            handler="lambda_function.lambda_handler",
            memory_size=256,
            timeout=Duration.seconds(900),
            environment={
                "PHOSSIL_ARCHIVE_RELATIONSHIPS_TABLE": archive_relationships_table.table_name,
                "PHOSSIL_ARCHIVE_BUCKET": archive_bucket.bucket_name,
            },
            log_retention=log_retention,
        )
        archive_relationships_table.grant_write_data(download_function)
        archive_bucket.grant_read_write(download_function)
        download_function.add_event_source(
            event_sources.SqsEventSource(download_queue, batch_size=1)
        )

        events.Rule(
            self,
            "IngressSchedule",
            rule_name="phossil-ingress-phishtank",
            description="PhishTank data updates hourly at the top of the hour",
            schedule=events.Schedule.cron(minute="7"),
        ).add_target(
            targets.LambdaFunction(
                ingress_function,
                retry_attempts=2,
                max_event_age=Duration.hours(2),
            )
        )
