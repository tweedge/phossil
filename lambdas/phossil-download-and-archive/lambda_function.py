import boto3
import json
from botocore.exceptions import ClientError
import requests
import requests_random_user_agent
from pprint import pprint
import hashlib
import filetype

incoming_file_path = "/tmp/incoming"
incoming_data_buffer_size = 65536

ddb_client = boto3.client("dynamodb")
sqs_client = boto3.client("sqs")
s3_client = boto3.client("s3")


def lambda_handler(event, context):
    ddb_table_log_source_url = "phossil-archive-relationships"
    s3_bucket_archive = "phossil-archive"

    download = json.loads(event["Records"][0]["body"])
    download_url = download["download"]
    expected_extension = download["filetype"]

    print(f"Streaming download for: {download_url}")
    connect_timeout = 5
    request_timeout = 65
    try:
        request = requests.get(
            download_url, stream=True, timeout=(connect_timeout, request_timeout)
        )

        incoming_file = open(incoming_file_path, "wb")
        for chunk in request.iter_content(chunk_size=incoming_data_buffer_size):
            incoming_file.write(chunk)
        incoming_file.close()
        print(f"Download completed!")
    except Exception as e:
        return {"statusCode": 408, "body": f"Fetch failed: {e}"}

    if request.status_code != 200:
        return {"statusCode": 412, "body": f"Fetch returned HTTP {request.status_code}"}

    kind = filetype.guess(incoming_file_path)
    if kind is None:
        print("Could not infer filetype - may or may not be a problem")
        inferred_extension = "Unknown"
        inferred_mime_type = "Unknown"
    else:
        print(f"Inferred extension is {kind.extension} (expected {expected_extension})")
        inferred_extension = kind.extension
        inferred_mime_type = kind.mime

    print("Hashing file to determine uniqueness")
    sha256 = hashlib.sha256()
    with open(incoming_file_path, "rb") as f:
        while True:
            data = f.read(incoming_data_buffer_size)
            if not data:
                break
            sha256.update(data)
    digest = sha256.hexdigest()
    print(f"SHA256 hash of file determined to be {digest}")

    errors = 0
    try:
        relationship_id = hashlib.sha256((download_url + digest).encode("utf-8"))
        ddb_client.put_item(
            TableName=ddb_table_log_source_url,
            Item={
                "relationship_id": {"S": relationship_id.hexdigest()},
                "source_url": {"S": download_url},
                "digest": {"S": digest},
                "category": {"S": download["category"]},
                "extension": {"S": download["filetype"]},
                "inferred_extension": {"S": inferred_extension},
                "inferred_mime_type": {"S": inferred_mime_type},
            },
        )
        print("Logged URL->digest relationship in DynamoDB")
    except ClientError as e:
        print(f"DynamoDB PUT ERROR: {e.response['Error']['Message']}")
        errors += 1
    except Exception as e:
        print(f"Unknown PUT ERROR: {e}")
        errors += 1

    print("Ensuring no duplicates exist before upload")
    try:
        s3_client.head_object(Bucket=s3_bucket_archive, Key=digest)
    except ClientError:
        # Not found
        print(f"Starting upload of {digest} to S3")
        s3_client.upload_file(
            Filename=incoming_file_path,
            Bucket=s3_bucket_archive,
            Key=digest,
        )
        print(f"Completed upload of {digest} to S3")

    if errors == 0:
        return {"statusCode": 200, "body": "Completed successfully."}
    else:
        return {"statusCode": 500, "body": f"Got {errors} exceptions - check logs"}


test_record = {
    "Records": [
        {
            "body": json.dumps(
                {
                    "protocol": "https://",
                    "fqdn": "chris.partridge.tech",
                    "download": "https://chris.partridge.tech/2021/rockyou2021.txt-a-short-summary/rockyou2021.torrent",
                    "category": "Test",
                    "filetype": ".torrent",
                }
            )
        },
    ]
}

if __name__ == "__main__":
    pprint(lambda_handler(test_record, {}))
