import json

import boto3
import botocore.client
import botocore.exceptions

from aws_pc import iam, organization


def add_role_and_policy(sso_profile_name: str, role_name: str, role_trust_policy: str, role_description,
                        policy_name: str, policy_text: str, update_policy_text: bool = False):
    """Loop through all accounts in profile trying to add a role."""

    session = boto3.Session(profile_name=sso_profile_name)
    org_client = session.client('organizations')
    accounts = organization.get_organisation_accounts(org_client, include_suspended=False)

    for account in accounts:
        try:
            iam_client = iam.get_role_based_client(session,
                                                   f"arn:aws:iam::{account['Id']}:role/AWSControlTowerExecution",
                                                   "access_audit_lambda_function", "iam")
        except iam.AccessDeniedException:
            print(f"Unable to assume ControlTowerExecution role in account {account['Name']}.")
            continue
        else:
            try:
                iam.add_role(iam_client, role_name, role_trust_policy, role_description)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'PermissionsDenied':
                    print(f"Unable to add role for account {account['Name']} due to permissions.")
                    continue
                else:
                    raise e
            policy_arn = iam.add_policy(iam_client, policy_name, policy_text, update_policy_text)

            # Check if policy is attached to role and if not attach it.
            iam.attach_policy(iam_client, role_name, policy_arn)


if __name__ == "__main__":
    ROLE_NAME = "Audit_IAM_Users"
    POLICY_NAME = 'Audit_IAM_Users'
    ROLE_DESCRIPTION = "Role used for Auditing IAM users and roles and their access."

    with open("policy.txt", 'r') as input_file:
        POLICY_TEXT = json.dumps(json.load(input_file))

    with open("role_trust_policy.txt", 'r') as input_file:
        ROLE_TRUST_POLICY = json.dumps(json.load(input_file))

    add_role_and_policy("management-hrds", ROLE_NAME, ROLE_TRUST_POLICY, ROLE_DESCRIPTION, POLICY_NAME, POLICY_TEXT,
                        True)
