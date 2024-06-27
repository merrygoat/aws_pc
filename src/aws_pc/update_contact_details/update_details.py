from typing import Type, Optional

import boto3
import botocore.client
import tqdm
import yaml

from aws_pc import organization


def get_alternate_contact_info(account_client: Type[botocore.client.BaseClient], account_id: str,
                               contact_type: str) -> Optional[dict]:
    try:
        response = account_client.get_alternate_contact(AccountId=account_id, AlternateContactType=contact_type)
    except account_client.exceptions.ResourceNotFoundException:
        return None
    return response["AlternateContact"]


def loop_over_accounts(sso_profile_name: str, update_details: bool = False):
    """Loop through all accounts in organization updating the contact information."""

    with open("details.yaml", 'r') as input_file:
        contact_details = yaml.safe_load(input_file)

    session = boto3.Session(profile_name=sso_profile_name)
    sts_client = session.client("sts")
    management_account_id = sts_client.get_caller_identity()["Account"]

    org_client = session.client('organizations')
    accounts = organization.get_organisation_accounts(org_client, include_suspended=False)
    account_client = session.client('account')

    contact_info = {}
    for account in tqdm.tqdm(accounts):
        account_info = {}
        account_id = account["Id"]

        account_info["default"] = account_client.get_contact_information(AccountId=account_id)["ContactInformation"]
        account_info["billing"] = get_alternate_contact_info(account_client, account_id, "BILLING")
        account_info["security"] = get_alternate_contact_info(account_client, account_id, "SECURITY")
        account_info["operations"] = get_alternate_contact_info(account_client, account_id, "OPERATIONS")

        contact_info[account_id] = account_info
        if update_details:
            account_client.put_contact_information(AccountId=account_id, ContactInformation=contact_details)

    with open("contact_details_report.txt", 'w') as output_file:
        output_file.write(f"Report on the contact details of all accounts in the organization managed by the "
                          f"management account id: '{management_account_id}'\n")
        for account_id, account_details in contact_info.items():
            output_file.write(f"Contact info for account: {account_id}\n")
            for contact_type, details in account_details.items():
                output_file.write(f"{contact_type}: {details}\n\n")


if __name__ == "__main__":
    loop_over_accounts("management-hrds", update_details=True)

