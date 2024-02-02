from __future__ import annotations

import json
import pathlib
from typing import Type, Optional
import re

import botocore.client
import botocore.exceptions
import dill

import aws_pc.s3 as s3

POLICY_DETAILS_CACHE: dict[str, PolicyDetails] = {}
ATTACHMENT_TYPES = ["Group", "User", "Inline", "Role"]
CACHE_NAME = "policy_cache.bin"
LOCAL_CACHE_PATH = pathlib.Path(".") / CACHE_NAME


class PolicySummary:
    """A Policy is an IAM object which can be attached to an identity to control what access it has to resources.

    :ivar arn: The Amazon Resource Name of the policy.
    :ivar sanitized_arn: The ARN with invalid CSS selector characters removed.
    :ivar attachment_type: Whether the policy is attached to a group, a user or inline.
    :ivar aws_managed: Whether the policy is a standard AWS provided one, or a custom one.
    """
    def __init__(self, arn: str, attachment_type: str):
        if attachment_type not in ATTACHMENT_TYPES:
            raise SyntaxError(f"Invalid attachment type '{attachment_type}' when instantiating policy")

        self.arn: str = arn
        self.sanitized_arn = re.sub("[:/]", "", arn)
        self.attachment_type: str = attachment_type
        if self.arn.startswith("arn:aws:iam::aws:policy"):
            self.aws_managed = True
        else:
            self.aws_managed = False

    def __repr__(self):
        return f"{self.arn}"

    def get_policy_details(self, iam_client: Type[botocore.client.BaseClient],
                           s3_client: Type[botocore.client.BaseClient],
                           remote_bucket_name: Optional[str] = None) -> PolicyDetails:
        """Get details for the policy.

        Policy details are not downloaded with the get_account_authorization_details API request,
        since there is a lot of duplication. Policy details are instead downloaded once for each policy and cached.
        """
        policy_details_cache = load_policy_cache(s3_client, remote_bucket_name)

        policy_details = PolicyDetails()

        if self.arn in policy_details_cache:
            return POLICY_DETAILS_CACHE[self.arn]
        else:
            policy = iam_client.get_policy(PolicyArn=self.arn)["Policy"]
            policy_details.name = policy["PolicyName"]
            policy_details.version = policy["DefaultVersionId"]
            if "Description" in policy:
                policy_details.description = policy["Description"]
            policy_text = iam_client.get_policy_version(PolicyArn=self.arn, VersionId=policy_details.version)
            policy_details.text = json.dumps(policy_text["PolicyVersion"]["Document"], indent=2).replace("\n", "<br>")
            policy_details_cache[self.arn] = policy_details
            save_policy_cache(s3_client, remote_bucket_name)
            return policy_details


class PolicyDetails:
    """Contains the name, description and policy text of a policy.

    :ivar name: The friendly name of the policy
    :ivar text: The wording of the policy.
    :ivar version: The version of the policy.
    :ivar description: A textual description of the policy.
    """

    def __init__(self):
        self.name: str = ""
        self.text: str = ""
        self.version: str = ""
        self.description: str = ""

    def hash(self):
        return hash(self.text)


def load_policy_cache(s3_client: Type[botocore.client.BaseClient], remote_bucket_name: str):
    """Load the policy cache if there is not a cache in memory."""
    global POLICY_DETAILS_CACHE

    if POLICY_DETAILS_CACHE:
        return POLICY_DETAILS_CACHE

    if remote_bucket_name:
        # load remote cache
        try:
            response = s3_client.get_object(Bucket=remote_bucket_name, Key=CACHE_NAME)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                return POLICY_DETAILS_CACHE
            else:
                raise e
        else:
            POLICY_DETAILS_CACHE = dill.load(response["Body"])
    else:
        # load local cache
        cache_path = pathlib.Path(LOCAL_CACHE_PATH)
        if cache_path.exists():
            with open(cache_path, 'rb') as input_file:
                POLICY_DETAILS_CACHE = dill.load(input_file)

    return POLICY_DETAILS_CACHE


def save_policy_cache(s3_client: Type[botocore.client.BaseClient], remote_bucket_name: str):
    """Save the policy cache that is in memory."""
    with open(LOCAL_CACHE_PATH, 'wb') as output_file:
        dill.dump(POLICY_DETAILS_CACHE, output_file)

    if remote_bucket_name:
        # if running as lambda then move cache to S3
        s3.get_or_create_bucket(s3_client, remote_bucket_name)
        with open(LOCAL_CACHE_PATH, 'rb') as input_file:
            s3_client.upload_fileobj(input_file, remote_bucket_name, CACHE_NAME)


def get_group_policies(user_details: dict, group_details: dict) -> list[PolicySummary]:
    """Return a list of `Policy` representing policies attached to groups the user is in."""
    group_policies = []
    for group_name in user_details["GroupList"]:
        group_policies.extend([policy['PolicyArn'] for policy in group_details[group_name]['AttachedManagedPolicies']])
    return [PolicySummary(arn, "Group") for arn in group_policies]
