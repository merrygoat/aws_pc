from typing import Type

import botocore.client


def get_organisation_accounts(org_client: Type[botocore.client.BaseClient],
                              include_suspended: bool = True) -> list[dict]:
    """Get a list of accounts in the organisation."""
    response = org_client.list_accounts()
    accounts = response["Accounts"]
    while "NextToken" in response:
        response = org_client.list_accounts(NextToken=response["NextToken"])
        accounts.extend(response["Accounts"])
    if not include_suspended:
        accounts = [account for account in accounts if account["Status"] != "SUSPENDED"]
    return accounts
