select
    minimum_password_length,
    require_symbols,
    require_numbers,
    require_uppercase_characters
from
    aws_iam_account_password_policy
where
    minimum_password_length < 14
or
    require_symbols = false
or
    require_numbers = false
or
    require_uppercase_characters = false;
