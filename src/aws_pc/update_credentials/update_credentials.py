# Get a list of all the accounts in an organisation and add an SSO section to the config ini file for each of them.

# Organization management accounts need to be added manually to the config file with a profile name in the format
# "profile management-x" where x is a name for the account and there is no whitespace in the management-x part of the
# name. All other child accounts of the organization will be added with the name in the format "x-y" where x is
# the name of the corresponding management account and y is the name of the child account.


import boto3
import configparser

from aws_pc import organization, config


def add_accounts_to_profile(accounts: list[dict], config: configparser.ConfigParser, organisation_name: str):
    """Add profiles for all accounts in the organisation to the profile file if they are not already present."""
    # Get a list of the account ids that already have a profile in the config file.
    accounts = {account["Id"]: account for account in accounts if account["Status"] == "ACTIVE"}
    current_profile_ids = [config[section]["sso_account_id"] for section in config.sections()
                           if section.startswith("profile")]
    # Remove any accounts from the to add list if they are already in the config file
    for account_id in current_profile_ids:
        accounts.pop(account_id, None)
    for account in accounts.values():
        account_name = f"{organisation_name}-{account['Name']}"
        if " " in account_name:
            account_name = f"'{account_name}'"
        section_name = f"profile {account_name}"
        config.add_section(section_name)
        config[section_name]["sso_session"] = f"{organisation_name}-sso"
        config[section_name]["sso_account_id"] = account["Id"]
        config[section_name]["sso_role_name"] = "AWSAdministratorAccess"
    return config


def remove_accounts_from_profile(config: configparser.ConfigParser, organisation_name: str) -> configparser.ConfigParser:
    """Remove any previous profiles in the config that are associated with the `organisation_name` profile."""
    management_sso_session = config[f"profile management-{organisation_name}"]["sso_session"]
    for section in config.sections():
        if section.startswith(f"profile-{organisation_name}") and section != f"profile-management{organisation_name}":
            # Only remove accounts with an SSO session matching the management account.
            if config[section]["sso_session"] == management_sso_session:
                config.remove_section(section)
    return config


def update_credentials(sso_profile_name: str):
    session = boto3.Session(profile_name=sso_profile_name)
    organisation_name = sso_profile_name.lstrip("management-")
    config_data = config.read_config()
    accounts = organization.get_organisation_accounts(session, include_suspended=False)
    config_data = remove_accounts_from_profile(config_data, organisation_name)
    config_data = add_accounts_to_profile(accounts, config_data , organisation_name)
    config.write_config(config_data)


if __name__ == "__main__":
    update_credentials("management-hrds")