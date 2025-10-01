import os

aws_token = os.environ.get("AWS_TOKEN", "")
if aws_token == "":
    aws_token = "AKIALALEMEL33243OLIA"
