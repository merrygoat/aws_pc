from __future__ import annotations

import json
import os
from datetime import datetime
from typing import TYPE_CHECKING, Type, Optional

import boto3
import botocore.client
import botocore.exceptions

from aws_pc.policy import get_group_policies, Policy

if TYPE_CHECKING:
    from sso import Group, Assignment


class NoAccessException(Exception):
    pass


class AccessDeniedException(Exception):
    """Raised when an entity tries to adopt a role that it does not have permission for."""
    pass


class IAMUser:
    """An object describing an IAM user.

    :ivar groups: A list of `Group`s that a user is a member of.
    :ivar policies: A list of `Policy` objects representing policies that are attached to the user or to groups that
      the user is a member of.
    """
    def __init__(self, username: str, account_details: dict):
        self.username: str = username

        user_details = account_details["Users"][self.username]
        self.groups: list[Group] = user_details["GroupList"]

        self.policies: list[Policy] = [Policy(policy["PolicyArn"], "User") for
                                                policy in user_details["AttachedManagedPolicies"]]
        self.policies.extend(get_group_policies(user_details, account_details["Groups"]))


class Account:
    """An object representing an AWS account.

    :ivar name: The friendly name of the Account.
    :ivar id: The numerical account ID.
    :ivar iam_users: A list of `IAMUser`s within the account.
    :ivar assignments: A list of `assignments` which list which identities policies are applied to.
    :ivar num_permission_sets: A count of the total number of SSO permission sets in the account.
    :ivar access_error: True if it is not possible to read account details.
    """
    def __init__(self, name: str, account_id: str, account_details: Optional[dict]):
        self.name: str = name
        self.id: str = account_id
        self.iam_users: list[IAMUser] = []
        self.assignments: list[Assignment] = []
        self.num_permission_sets: int = 0
        self.access_error = False

        if account_details:
            self.iam_users = [(IAMUser(username, account_details)) for username in account_details["Users"]]
        else:
            self.access_error = True

    def __repr__(self):
        return f"{self.name} - {self.id}"


def get_account_details(iam_client: Type[botocore.client.BaseClient]) -> dict[str, dict]:
    """Get IAM information about an account.

    Uses the `get_account_authorization_details` API method to collect information and then repacks it into
    a dictionary for ease of use.
    """
    details = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": []}
    # noinspection PyArgumentList
    paginator = iam_client.get_paginator('get_account_authorization_details')
    page_iterator = paginator.paginate(Filter=['User', 'Role', 'Group'])
    try:
        for page in page_iterator:
            for item in details:
                details[item].extend(page[item])
    except botocore.exceptions.ClientError:
        raise NoAccessException
    # Unpack lists of items into dicts
    details["Users"] = {user["UserName"]: user for user in details.pop("UserDetailList")}
    details["Groups"] = {group["GroupName"]: group for group in details.pop("GroupDetailList")}
    details["Roles"] = {role["RoleName"]: role for role in details.pop("RoleDetailList")}

    return details


def get_role_based_client(session: boto3.Session, role_arn: str, session_name: str,
                          client_type: str, region_name=None) -> Type[botocore.client.BaseClient]:
    """Get a boto3 client with an assumed role.

    :param session: The boto3 session for the account assuming the role.
    :param role_arn: The arn of the role to assume
    :param session_name: A descriptor of what will be done with the returned client
    :param client_type: The type of client to generate.
    :param region_name: The name of the region where the client operates. Some clients do not need to specify a region.
    """
    if "AWS_EXECUTION_ENV" in os.environ:
        sts_client = boto3.client('sts')
    else:
        sts_client = session.client('sts')

    try:
        role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            raise AccessDeniedException
        else:
            raise e

    access_key = role['Credentials']['AccessKeyId']
    secret_key = role['Credentials']['SecretAccessKey']
    session_token = role['Credentials']['SessionToken']

    # Create service client using the assumed role credentials
    return boto3.client(client_type, aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                        aws_session_token=session_token, region_name=region_name)


def attach_policy(iam_client: Type[botocore.client.BaseClient], role_name: str, policy_arn: str):
    """Attaches a policy to a role.

    If a policy is already attached the function will not fail or attach the policy twice.
    """
    iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)


def add_role(iam_client: Type[botocore.client.BaseClient], role_name: str, role_trust_policy: str,
             role_description: str, ignore_existing: bool = True):
    """Create role in account.

    :param iam_client: iam client for the account where the role will be added.
    :param role_name: Name of the role to be added.
    :param role_trust_policy: Trust policy for the role.
    :param role_description: Description of the role.
    :param ignore_existing: If True, do not raise an exception if a role with this name already exists.
    """
    try:
        iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=role_trust_policy,
                               Description=role_description)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists" and ignore_existing:
            raise e


def add_policy(iam_client: Type[botocore.client.BaseClient], policy_name: str, policy_text: str,
               update_text) -> str:
    """Add a policy to an account. Returns the policy arn.

    The get_policy function only allows fetching existing policies by ARN so list_policies must be used to
    search by name.

    :param iam_client: iam client for the account where the policy will be added.
    :param policy_name: Name of the policy to be added.
    :param policy_text: Text of the policy.
    :param update_text: If True and policy already exists then replaces existing policy text with `policy_text`.
    """
    # Get all customer managed policies and check the names
    policy_arn = None
    policies = get_policies(iam_client)
    for policy in policies:
        if policy["PolicyName"] == policy_name:
            policy_arn = policy["Arn"]
            policy_version = policy["DefaultVersionId"]
            if update_text is True:
                update_policy(iam_client, policy_arn, policy_version, policy_text)
            return policy_arn

    # Create policy if it doesn't exist
    policy_response = iam_client.create_policy(PolicyName=policy_name, PolicyDocument=policy_text)
    return policy_response["Policy"]["Arn"]


def delete_role(iam_client, role_name):
    """Delete the role with the name `role_name`"""
    inline_policies = iam_client.list_role_policies(RoleName=role_name)
    for name in inline_policies["PolicyNames"]:
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam_client.delete_role(RoleName=role_name)


def delete_policy(iam_client: Type[botocore.client.BaseClient], policy_arn: str):
    """Deletes the policy with the specified `policy_arn`"""
    # First detach the policy from any entity it is attached to.
    entities = iam_client.list_entities_for_policy(PolicyArn=policy_arn)
    for role in entities["PolicyRoles"]:
        iam_client.detach_role_policy(RoleName=role["RoleName"], PolicyArn=policy_arn)
    # Then delete all non-current versions of the policy
    policy_versions = iam_client.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    for version in policy_versions:
        if not version["IsDefaultVersion"]:
            iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=version["VersionId"])
    # Then delete the policy
    iam_client.delete_policy(PolicyArn=policy_arn)


def update_policy(iam_client: Type[botocore.client.BaseClient], policy_arn: str, policy_version: str, policy_text: str):
    """Adds a new policy version to `policy_arn` with `policy_text` as the text."""
    current_policy = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)
    current_policy_text = current_policy["PolicyVersion"]["Document"]
    # AWS gives policy text as decoded JSON so need to load policy string from JSON to compare.
    new_policy_text = json.loads(policy_text)
    if current_policy_text == new_policy_text:
        # If the current version of the policy matches the text then there is no need to update.
        return policy_arn

    policy_versions = iam_client.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    if len(policy_versions) == 5:
        delete_oldest_policy(iam_client, policy_arn, policy_versions)

    iam_client.create_policy_version(PolicyArn=policy_arn, PolicyDocument=policy_text, SetAsDefault=True)


def delete_oldest_policy(iam_client: Type[botocore.client.BaseClient], policy_arn: str, policy_versions: list[dict]):
    """Delete the oldest version of the policy specified by `policy_arn`"""
    oldest_policy_version = ""
    oldest_policy_time = datetime.now()
    for policy in policy_versions:
        if policy["CreateDate"] < oldest_policy_time:
            oldest_policy_version = policy["VersionID"]
            oldest_policy_time = policy["CreateDate"]
    iam_client.delete_policy_version(PolicyArn=policy_arn, VersionID=oldest_policy_version)


def get_roles(iam_client: Type[botocore.client.BaseClient]) -> list[dict]:
    """Get a list of roles in the account using a paginator."""
    roles = []
    # noinspection PyArgumentList
    paginator = iam_client.get_paginator('list_roles')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        roles.extend(page["Roles"])
    return roles


def get_policies(iam_client: Type[botocore.client.BaseClient]) -> list[dict]:
    """Get a list of user managed policies in the account using a paginator."""
    policies = []
    # noinspection PyArgumentList
    paginator = iam_client.get_paginator('list_policies')
    page_iterator = paginator.paginate(Scope="Local")
    for page in page_iterator:
        policies.extend(page["Policies"])
    return policies


def get_account_password_policy(iam_client: Type[botocore.client.BaseClient]):
    """Get the password policy for IAM users."""
    return iam_client.get_account_password_policy()


def update_account_password_policy(iam_client: Type[botocore.client.BaseClient], minimum_password_length: int,
                                   require_symbols: bool, require_numbers: bool, require_uppercase: bool,
                                   require_lowercase: bool, allow_password_change: bool, max_password_age,
                                   password_reuse_prevention, hard_expiry: bool):
    """Set the password policy for IAM users."""
    if max_password_age == 0:
        return iam_client.update_account_password_policy(MinimumPasswordLength=minimum_password_length,
                                                         RequireSymbols=require_symbols,
                                                         RequireNumbers=require_numbers,
                                                         RequireUppercaseCharacters=require_uppercase,
                                                         RequireLowercaseCharacters=require_lowercase,
                                                         AllowUsersToChangePassword=allow_password_change,
                                                         PasswordReusePrevention=password_reuse_prevention,
                                                         HardExpiry=hard_expiry)
    else:
        return iam_client.update_account_password_policy(MinimumPasswordLength=minimum_password_length,
                                                         RequireSymbols=require_symbols,
                                                         RequireNumbers=require_numbers,
                                                         RequireUppercaseCharacters=require_uppercase,
                                                         RequireLowercaseCharacters=require_lowercase,
                                                         AllowUsersToChangePassword=allow_password_change,
                                                         MaxPasswordAge=max_password_age,
                                                         PasswordReusePrevention=password_reuse_prevention,
                                                         HardExpiry=hard_expiry)
