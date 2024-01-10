from typing import Type

import boto3
import botocore.client
import yaml

from aws_pc import organization


def audit_alternate_contact(account_client: Type[botocore.client.BaseClient],
                            management_account_id: str, account_id: str, contact_type: str):
    if account_id != management_account_id:
        return account_client.get_contact_information(AccountId='string')
    else:
        return account_client.get_contact_information()


def change_contact_details(account_client: Type[botocore.client.BaseClient], management_account_id: str,
                           account_id: str, contact_details: dict):
    if account_id != management_account_id:
        account_client.put_contact_information(AccountId=account_id, ContactInformation=contact_details)
    else:
        account_client.put_contact_information(ContactInformation=contact_details)


def loop_over_accounts(sso_profile_name: str):
    """Loop through all accounts in organization updating the contact information."""

    with open("details.yaml", 'r') as input_file:
        contact_details = yaml.safe_load(input_file)

    session = boto3.Session(profile_name=sso_profile_name)
    sts_client = session.client("sts")
    management_account_id = sts_client.get_caller_identity()["Account"]

    org_client = session.client('organizations')
    accounts = organization.get_organisation_accounts(org_client, include_suspended=False)

    account_client = session.client('account')
    accounts = [{"Id": "463829754490"}]
    for account in accounts:
        # change_contact_details(account_client, management_account_id, account["Id"], contact_details)
        details = audit_alternate_contact(account_client, management_account_id, account["Id"], "BILLING")
        print(f"{account['Id']}: {details}")


if __name__ == "__main__":
    loop_over_accounts("management-hrds")

