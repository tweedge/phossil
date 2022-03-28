import boto3
import json
from botocore.exceptions import ClientError
from bs4 import BeautifulSoup
import requests
import requests_random_user_agent
from pprint import pprint
import hashlib


suffixes_worth_downloading = {
    "Archives": [".zip", ".7z", ".gz", ".tar", ".rar", ".xz"],
    "Executables": [
        ".exe",
        ".jar",
        ".out",
        ".elf",
    ],
    "Installers": [".apk", ".msi", ".app", ".dmg", ".pkg"],
    "Scripts": [".sh", ".vbs", ".ps1", ".bat"],
    "Documents": [
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".ppt",
        ".pptx",
    ],
    "Environment": [".env", ".pub"],
}

acceptable_protocols = ["http://", "https://"]

ddb_client = boto3.client("dynamodb")
sqs_client = boto3.client("sqs")


def lambda_handler(event, context):
    ddb_table_url_relationships = "phossil-url-relationships"
    sqs_queue_scanner = "phossil-download-queue.fifo"

    url = json.loads(event["Records"][0]["body"])
    reconstructed_url = url["protocol"] + url["fqdn"] + url["url"]
    original_url = url["original"]

    print(f"Fetching: {reconstructed_url}")
    connect_timeout = 5
    request_timeout = 10
    try:
        request = requests.get(
            reconstructed_url, timeout=(connect_timeout, request_timeout)
        )
    except Exception as e:
        return {"statusCode": 408, "body": f"Fetch failed: {e}"}

    if request.status_code != 200:
        return {"statusCode": 412, "body": f"Fetch returned HTTP {request.status_code}"}

    response = request.text
    if len(response) < 10:
        return {"statusCode": 412, "body": f"Fetch returned miniscule or no HTML"}

    soup = BeautifulSoup(response, "html5lib")

    links = []
    for link in soup.findAll("a"):
        if link.get("href"):  # not all 'a' have 'href'
            links.append(link.get("href"))

    links = list(dict.fromkeys(links))
    errors = 0

    for link in links:
        absolute_link = assemble_absolute_url(url, link)
        if not absolute_link:
            continue
        print(f"Found href to: {absolute_link}")

        try:
            relationship_id = hashlib.sha256(
                (reconstructed_url + original_url + absolute_link).encode("utf-8")
            )
            ddb_client.put_item(
                TableName=ddb_table_url_relationships,
                Item={
                    "relationship_id": {"S": relationship_id.hexdigest()},
                    "fetched_url": {"S": reconstructed_url},
                    "original_url": {"S": original_url},
                    "referenced_url": {"S": absolute_link},
                },
            )
        except ClientError as e:
            errors += 1
            print(f"DynamoDB PUT ERROR: {e.response['Error']['Message']}")
        except Exception as e:
            errors += 1
            print(f"Unknown PUT ERROR: {e}")

        assessment = assess_file(url, absolute_link)
        if assessment["Worth"]:
            print(f"Queueing {absolute_link} for download")
            try:
                queue_url = sqs_client.get_queue_url(QueueName=sqs_queue_scanner)
                response = sqs_client.send_message(
                    QueueUrl=queue_url["QueueUrl"],
                    MessageGroupId="Ingress",
                    MessageBody=json.dumps(
                        {
                            "protocol": url["protocol"],
                            "fqdn": url["fqdn"],
                            "download": absolute_link,
                            "category": assessment["Category"],
                            "filetype": assessment["Filetype"],
                        }
                    ),
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


def assemble_absolute_url(phossil_url, new_link):
    for protocol in acceptable_protocols:
        if new_link.lower().startswith(protocol):
            return new_link

    special_protocols = ["mailto:"]  # TODO: should be fleshed out
    for protocol in special_protocols:
        if new_link.lower().startswith(protocol):
            return new_link

    non_link_protocols = ["javascript:"]  # TODO: should be fleshed out
    for protocol in non_link_protocols:
        if new_link.lower().startswith(protocol):
            return False

    if new_link.startswith("/"):
        url_root = phossil_url["protocol"] + phossil_url["fqdn"]
        return url_root.rstrip("/") + new_link
    else:
        url_prefix = phossil_url["protocol"] + phossil_url["fqdn"] + phossil_url["url"]
        return url_prefix.rstrip("/") + "/" + new_link


def assess_file(phossil_url, new_link):
    at_least_one_proto_match = False
    for protocol in acceptable_protocols:
        same_domain_any_proto = protocol + phossil_url["fqdn"]
        if new_link.startswith(same_domain_any_proto):
            at_least_one_proto_match = True

    if not at_least_one_proto_match:
        return {"Worth": False}  # don't download anything off-domain

    for category, filetypes in suffixes_worth_downloading.items():
        for filetype in filetypes:
            if new_link.lower().endswith(filetype):
                return {"Worth": True, "Category": category, "Filetype": filetype}

    return {"Worth": False}  # default deny


test_record = {
    "Records": [
        {
            "body": json.dumps(
                {
                    "protocol": "https://",
                    "fqdn": "chris.partridge.tech",
                    "url": "/",
                    "original": "https://chris.partridge.tech/2021/prestige/",
                }
            )
        },
    ]
}

if __name__ == "__main__":
    pprint(lambda_handler(test_record, {}))
