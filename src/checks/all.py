from . import always_pass
from . import approval_count
from . import yml_validation
from . import hooks_schema


def get_all_checks():
    # Place an instance of each check here
    return {
        always_pass.AlwaysPass.configname: always_pass.AlwaysPass(),
        yml_validation.YmlValidation.configname: yml_validation.YmlValidation(),
        approval_count.ApprovalCount.configname: approval_count.ApprovalCount(),
        hooks_schema.HooksScehma.configname: hooks_schema.HooksScehma(),
    }