from typing import Optional, Type

import boto3
import botocore.client
import botocore.exceptions

from aws_pc import iam, organization


def delete_policy_and_role(sso_profile_name: str, policy_names: list[str], role_name: str):
    """Loop through all accounts in profile trying to delete a policy."""

    session = boto3.Session(profile_name=sso_profile_name)
    org_client = session.client('organizations')
    accounts = organization.get_organisation_accounts(org_client, include_suspended=False)

    for account in accounts:
        try:
            iam_client = get_iam_client(session, account["Id"])
        except iam.AccessDeniedException:
            print(f"Unable to assume ControlTowerExecution role in account {account['Name']}.")
            continue
        for name in policy_names:
            policy_arn = get_policy_arn(iam_client, name)
            if policy_arn:
                try:
                    iam.delete_policy(iam_client, policy_arn)
                except botocore.exceptions.ClientError:
                    print(f"Unable to delete policy for account {account['Name']} due to permissions.")
        # This will only work if all the attached policies have been detached.
        try:
            iam.delete_role(iam_client, role_name)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                print(f"Role not found in {account['Name']}")
            else:
                raise e


def get_policy_arn(iam_client, policy_name: str) -> Optional[str]:
    """Get the ARN of the policy with the name `policy_name`. Return None if the policy is not found."""
    policies = iam.get_policies(iam_client)
    for policy in policies:
        if policy["PolicyName"] == policy_name:
            return policy["Arn"]
    return None


def get_iam_client(session: boto3.Session, account_id: str) -> Optional[Type[botocore.client.BaseClient]]:
    """Get an IAM client under the AWSControlTowerExecution assumed role."""
    role_arn = f"arn:aws:iam::{account_id}:role/AWSControlTowerExecution"
    return iam.get_role_based_client(session, role_arn, "access_audit_lambda_function", "iam")


if __name__ == "__main__":
    POLICY_NAME = ["Audit_IAM_Users"]
    ROLE_NAME = "Audit_IAM_Users"

    delete_policy_and_role("management-hrds", POLICY_NAME, ROLE_NAME)
