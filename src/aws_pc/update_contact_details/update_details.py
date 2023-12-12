import boto3
import yaml

from aws_pc import organization


def add_role_and_policy(sso_profile_name: str):
    """Loop through all accounts in organization updating the contact information."""

    with open("details.yaml", 'r') as input_file:
        contact_details = yaml.safe_load(input_file)

    session = boto3.Session(profile_name=sso_profile_name)
    sts_client = session.client("sts")
    management_account_id = sts_client.get_caller_identity()["Account"]

    org_client = session.client('organizations')
    accounts = organization.get_organisation_accounts(org_client, include_suspended=False)

    account_client = session.client('account')

    for account in accounts:
        if account["Id"] != management_account_id:
            account_client.put_contact_information(AccountId=account['Id'],
                                                   ContactInformation=contact_details)
        else:
            account_client.put_contact_information(ContactInformation=contact_details)


if __name__ == "__main__":
    add_role_and_policy("management-hrds")
