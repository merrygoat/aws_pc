from typing import Type

import boto3
import botocore.client
import botocore.exceptions


def get_or_create_bucket(s3_client: Type[botocore.client.BaseClient], bucket_name: str, region: str = "eu-west-2"):
    """Create bucket with `bucket_name`."""
    try:
        location = {'LocationConstraint': region}
        s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration=location)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "BucketAlreadyOwnedByYou":
            raise e


def delete_all_buckets ():
    # DANGER!
    # This function irrevocably deletes the contents of all buckets in the named account without confirmation.
    session = boto3.Session(profile_name="hrds-SWB-Dev-Main")
    client = session.client('s3')
    buckets = client.list_buckets()
    bucket_names = [bucket["Name"] for bucket in buckets["Buckets"]]

    for name in bucket_names:
        paginator = client.get_paginator('list_object_versions')
        response_iterator = paginator.paginate(Bucket=name, MaxKeys=10000)
        for response in response_iterator:
            versions = response.get('Versions', [])
            versions.extend(response.get('DeleteMarkers', []))
        if len(versions) > 999:
            print(f"Bucket {name} has many objects, delete through the console.")
        else:
            for version in versions:
                if version["VersionId"] != "null":
                    client.delete_object(Bucket=name, Key=version["Key"], VersionId=version["VersionId"])
            client.delete_bucket(Bucket=name)
