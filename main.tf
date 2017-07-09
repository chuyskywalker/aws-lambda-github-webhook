provider "aws" {
  profile = "default"
  region = "${var.region}"
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
}

// this will fetch our account_id, no need to hard code it
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "tf_gh_check_role" {
  name = "tf_gh_check_role"
  assume_role_policy = "${file("policy/lambda-role.json")}"
}

resource "aws_iam_role_policy" "tf_gh_check_iam_role_policy" {
  name = "tf_gh_check_iam_role_policy"
  role = "${aws_iam_role.tf_gh_check_role.id}"
  policy = "${file("policy/policy.json")}"
}

data "archive_file" "lambda" {
  type = "zip"
  source_dir  = "./src"
  output_path = "lambda.zip"
}

resource "aws_lambda_function" "tf_gh_check_function_incoming" {
  filename = "${data.archive_file.lambda.output_path}"
  function_name = "tf_gh_check"
  role = "${aws_iam_role.tf_gh_check_role.arn}"
  handler = "main.incoming"
  runtime = "python2.7"
  source_code_hash = "${data.archive_file.lambda.output_base64sha256}"
  publish = true
  timeout = 5
}

resource "aws_lambda_function" "tf_gh_check_function_secondary" {
  filename = "${data.archive_file.lambda.output_path}"
  function_name = "tf_gh_check_function_secondary"
  role = "${aws_iam_role.tf_gh_check_role.arn}"
  handler = "main.secondary"
  runtime = "python2.7"
  source_code_hash = "${data.archive_file.lambda.output_base64sha256}"
  publish = true
  timeout = 30
}

resource "aws_lambda_permission" "allow_api_gateway" {
  function_name = "${aws_lambda_function.tf_gh_check_function_incoming.arn}"
  statement_id = "AllowExecutionFromApiGateway"
  action = "lambda:InvokeFunction"
  principal = "apigateway.amazonaws.com"
  source_arn = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}/*/${aws_api_gateway_method.tf_gh_check_gateway_method.http_method}${aws_api_gateway_resource.tf_gh_check_gateway_resource.path}"
}

resource "aws_api_gateway_rest_api" "tf_gh_check_gateway_api" {
  name = "tf_gh_check-api"
  description = "Gateway for terraformed gh check"
}

resource "aws_api_gateway_resource" "tf_gh_check_gateway_resource" {
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  parent_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.root_resource_id}"
  path_part = "hook"
}

resource "aws_api_gateway_method" "tf_gh_check_gateway_method" {
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  resource_id = "${aws_api_gateway_resource.tf_gh_check_gateway_resource.id}"
  http_method = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "tf_gh_check_integration" {
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  resource_id = "${aws_api_gateway_resource.tf_gh_check_gateway_resource.id}"
  http_method = "${aws_api_gateway_method.tf_gh_check_gateway_method.http_method}"
  type = "AWS_PROXY"
  uri = "arn:aws:apigateway:${var.region}:lambda:path/2015-03-31/functions/arn:aws:lambda:${var.region}:${data.aws_caller_identity.current.account_id}:function:${aws_lambda_function.tf_gh_check_function_incoming.function_name}/invocations"
  integration_http_method = "POST"
}

resource "aws_cloudwatch_log_group" "tf_gh_check_logs" {
  name = "/aws/lambda/${aws_lambda_function.tf_gh_check_function_incoming.function_name}"
}

resource "aws_api_gateway_deployment" "tf_gh_check_prod" {
  depends_on = [
    "aws_api_gateway_method.tf_gh_check_gateway_method",
    "aws_api_gateway_integration.tf_gh_check_integration"
  ]
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  stage_name = "prod"
}

output "prod_url" {
  value = "https://${aws_api_gateway_deployment.tf_gh_check_prod.rest_api_id}.execute-api.${var.region}.amazonaws.com/${aws_api_gateway_deployment.tf_gh_check_prod.stage_name}${aws_api_gateway_resource.tf_gh_check_gateway_resource.path}"
}