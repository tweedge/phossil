import boto3
import json
import random
import requests
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, timezone
from pprint import pprint

ddb_client = boto3.client("dynamodb")
sqs_client = boto3.client("sqs")


def source_urls_phishtank():
    phishtank_data = "https://data.phishtank.com/data/online-valid.json"
    headers = {"User-Agent": "phossil-ingress-phishtank"}

    request = requests.get(phishtank_data, headers)
    if request.status_code != 200:
        raise Exception(f"PhishTank returned bad HTTP code: {request.status_code}")

    response = request.json()
    if len(response) < 10:
        raise Exception(f"PhishTank returned too little data ...")

    urls = []
    for phish in response:
        if phish["verified"] == "yes":
            phish_verified_str = phish["verification_time"]
            phish_verified_obj = datetime.fromisoformat(phish_verified_str)
            now_obj = datetime.now(timezone.utc)

            # TODO: parameterize
            if now_obj - timedelta(days=2) > phish_verified_obj:
                # not verified recently enough, toss it
                continue

            url = build_internal_url_representation(phish["url"])
            if url:
                urls.append(url)

    return urls


def lambda_handler(event, context):
    ddb_table_phishing_urls = "phossil-known-phishing-urls"
    sqs_queue_scanner = "phossil-url-fetch-queue.fifo"
    errors = 0

    print("Fetching phishing URLs from PhishTank and formatting")
    try:
        urls = source_urls_phishtank()
    except Exception as e:
        return {"statusCode": 500, "body": e}

    print(f"Deduplicating {len(urls)} phishing URLs using DynamoDB")
    new_urls = []
    for url in urls:
        original_url = url["original"]
        # check in DynamoDB if the phishing URL is known
        try:
            dynamo_get = ddb_client.get_item(
                TableName=ddb_table_phishing_urls,
                Key={"phishing_url": {"S": original_url}},
            )
        except ClientError as e:
            print(f"DynamoDB GET ERROR: {e.response['Error']['Message']}")
            errors = 0
            # we don't know if we've scanned this, so let's skip it
            continue

        # we've confidently scanned this, skip it
        if "Item" in dynamo_get:
            continue

        try:
            # TODO: could/should this store more data from PhishTank or other sources?
            ddb_client.put_item(
                TableName=ddb_table_phishing_urls,
                Item={"phishing_url": {"S": original_url}},
            )
        except ClientError as e:
            print(f"DynamoDB PUT ERROR: {e.response['Error']['Message']}")
            errors = 0
            # we don't know if we've saved this, so let's skip it
            continue
        except Exception as e:
            print(f"Unknown PUT ERROR: {e}")
            errors = 0
            # we don't know if we've saved this, so let's skip it
            continue

        new_urls.append(url.copy())
    del urls

    print(f"Expanding {len(new_urls)} URLs to analyze the phishing sites")
    new_urls_to_scan = []
    for url in new_urls:
        for new_scan in expand_initial_url_set(url):
            new_urls_to_scan.append(new_scan)
    del new_urls
    random.shuffle(new_urls_to_scan)

    # TODO: make fast https://www.foxy.io/blog/we-love-aws-lambda-but-its-concurrency-handling-with-sqs-is-silly/
    print(f"Queueing {len(new_urls_to_scan)} new fetches to SQS for scanner")
    for url in new_urls_to_scan:
        try:
            queue_url = sqs_client.get_queue_url(QueueName=sqs_queue_scanner)
            response = sqs_client.send_message(
                QueueUrl=queue_url["QueueUrl"],
                MessageGroupId="Ingress",
                MessageBody=json.dumps(url),
            )
            # TODO: does response need to be checked?
        except ClientError as e:
            print(f"SQS Publish ERROR: {e.response['Error']['Message']}")
            errors += 1
        except Exception as e:
            print(f"Unknown Publish ERROR: {e}")
            errors += 1

    if errors == 0:
        return {"statusCode": 200, "body": "Completed successfully."}
    else:
        return {"statusCode": 500, "body": f"Got {errors} exceptions - check logs"}


def build_internal_url_representation(original):
    acceptable_protocols = ["http://", "https://"]

    for protocol in acceptable_protocols:
        if original.startswith(protocol):
            fqdn_and_url = original[len(protocol) :]
            first_slash = fqdn_and_url.find("/")

            if first_slash == -1:
                fqdn = fqdn_and_url
                url = "/"
            else:
                fqdn = fqdn_and_url[:first_slash]
                url = fqdn_and_url[first_slash:]

            phish_data = {
                "protocol": protocol,
                "fqdn": fqdn,
                "url": url,
                "original": original,
            }
            return phish_data

    return False


def expand_initial_url_set(url):
    if url["url"] == "/":
        return [url]

    new_urls = []
    components_to_origin = url["url"].strip("/").split("/")
    components_to_origin.insert(0, "")

    for component_ctr in range(0, len(components_to_origin) + 1):
        new_url = url.copy()

        this_url_components = []
        for this_url_component_ctr in range(0, component_ctr):
            this_url_components.append(components_to_origin[this_url_component_ctr])
        this_url_components.append("")

        new_url["url"] = "/".join(this_url_components)
        if new_url["url"] == "":
            continue
        if component_ctr >= len(components_to_origin) and len(new_url["url"]) > 1:
            new_url["url"] = new_url["url"].rstrip("/")

        new_urls.append(new_url)

    return new_urls


if __name__ == "__main__":
    pprint(lambda_handler({}, {}))
