# Github Webhook via AWS Lamba Python

An exploration of leveraging AWS Lamba to produce "serverless" python handling for github webhooks. In addition, the originating repo controls which checks are run through its own `.hooks.yml` file (think `.travis.yml` like system, but with support for _any_ kind of webhook, not just pull requests).

## Deployment

You should be able to deploy this without editing any application code to get a basic check going.

### Things to Install

- [Terraform](https://www.terraform.io/) -- to push code and configuration to AWS
- [Python 2.7](https://www.python.org/downloads/release/python-2713/) -- to build the application

### Credentials to Acquire

1. AWS Access Key
2. AWS Secret Key
3. Github Token
4. Github Webhook Secret

Copy `variables.tf.example.txt` to `variables.tf` and fill in the AWS credentials. 

Create `src/ghtoken.txt` and place the Github token in that file.

Create `src/ghsecret.txt` and put a random, keyboard-smash ascii string in there. You'll use this when setting up the webhook later on.


### Build

This will fetch all the requirements and place them in vendor where `main.py` will seek them out.
```bash
$ pip install -r src/vendor/requirements.txt -t src/vendor 
```

~~If you'd like, you can also locally test the code by running `python src/main.py`.~~ _todo: fix with local event examples_

### Deploy

Now that the application is "built" and all the secrets are in place, you can deploy the whole thing with:

```bash
$ terraform apply 
```

This will package your app (`src/`) into a zip file, upload it as your lamda function and setup all the function, api gateway, and logging AWS configurations to run the code "serverless"ly. At the end of the run, you'll get output that looks like this:

```
prod_url = https://xxxxxxx.execute-api.xxxxxx.amazonaws.com/prod/hook    
```

Keep that for the next step.

### Install Github Webhook

1. Go to the repo you want to try this on and into the "Settings" area. 
2. Open "Webhooks"
3. Click "Add Webhook"
4. Set the "Payload URL" to the `prod_url` from above
5. Change "Content-type" to "application/json"
6. Put the secret from `src/ghsecret.txt` into the "Secret" field
7. Switch the hook to "Let me select individual events" and only check the box for "Pull Requests"
8. Finally, save by pressing "Add webhook"

Once the webhook is in place, you'll need one more thing. This demo will trigger checks based on a file called `.hooks.yml` in your repositories default branch. None of these hooks are currently doing anything other than issuing a rubber stamp status check on pull requests. You can see an example [`.hooks.yml` in this repo](./.hooks.yml).

## Thanks

I used these are references and starting points for this project

Articles:
- [Using Terraform to setup AWS API-Gateway and Lambda](https://andydote.co.uk/2017/03/17/terraform-aws-lambda-api-gateway/) -- Credit where due, most of the terraform states came from this fellow.
- [Terraforming Amazon AWS Lambda function and related API Gateway](http://www.arvinep.com/2016/06/terraforming-amazon-aws-lambda-function.html) -- Helped with a missing cloudwatch log setup

API Docs:
- [boto3](http://boto3.readthedocs.io/)
- [GithubAPI](https://developer.github.com/v3)
- [PyGithub](http://pygithub.readthedocs.io/)
