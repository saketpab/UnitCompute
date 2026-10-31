"""PostgreSQL history for native projection and recovery boundary regressions."""

from unitcompute.auth import Principal
from unitcompute.db.database import Database

DEP = "dep_" + "b" * 32
PLAN = "plan_" + "c" * 32
SOURCE_JOB = "job_" + "d" * 32
SUCCESS_JOB = "job_" + "e" * 32
ISSUER = "https://old.test"


def seed_history(db: Database, *, native: bool = False) -> None:
    principal = (
        Principal("legacy-subject", "jwt", ISSUER) if native else Principal("dev:legacy", "dev")
    )
    owner = principal.owner_id
    backend = "terraform" if native else "simulated"
    with db.transaction() as c:
        db.ensure_user(c, principal)
        c.execute(
            "INSERT INTO deployments(id,owner_id,cloud_owner_id,name,disk_gib,region,"
            "instance_type,provisioner,status,apply_attempted,created_at,updated_at) "
            "VALUES(%s,%s,'legacy-subject','history',8,'us-east-1','t3.micro',%s,"
            "'recovery_required',1,now(),now())",
            (DEP, owner, backend),
        )
        c.execute(
            "INSERT INTO plans(id,deployment_id,owner_id,kind,status,provisioner,config_hash,"
            "region,state_key,template_version,created_at,preview_json,approved_by,approved_at,"
            "plan_hash,account_id) VALUES(%s,%s,%s,'create','apply_failed',%s,'exact-config-hash',"
            "'us-east-1','unchanged-state-key','ec2-vm/v1',now(),"
            '\'{"changes":[{"action":"create","address":"aws_instance.vm",'
            '"resource_type":"aws_instance","summary":{}}]}\',%s,now(),\'exact-plan-hash\',%s)',
            (PLAN, DEP, owner, backend, owner, "123456789012" if native else None),
        )
        for job, status in ((SOURCE_JOB, "recovery_required"), (SUCCESS_JOB, "succeeded")):
            c.execute(
                "INSERT INTO jobs(id,owner_id,deployment_id,plan_id,kind,status,payload_hash,"
                "created_at) VALUES(%s,%s,%s,%s,'apply',%s,'exact-payload-hash',now())",
                (job, owner, DEP, PLAN, status),
            )
        c.execute(
            "UPDATE deployments SET current_plan_id=%s,instance_id='i-0123456789abcdef0',"
            "root_volume_id='vol-0123456789abcdef0' WHERE id=%s",
            (PLAN, DEP),
        )
        for evidence, discharge in (("uncaptured", False), ("captured", True)):
            c.execute(
                "INSERT INTO recovery_obligations(deployment_id,job_id,plan_id,reason,evidence,"
                "created_at,discharged_at,discharged_by_job_id) VALUES(%s,%s,%s,%s,%s,now(),"
                "CASE WHEN %s THEN now() END,%s)",
                (
                    DEP,
                    SOURCE_JOB,
                    PLAN,
                    "history-" + evidence,
                    evidence,
                    discharge,
                    SUCCESS_JOB if discharge else None,
                ),
            )
        c.execute(
            "INSERT INTO audit_events(occurred_at,actor,action,deployment_id,detail_json) "
            "VALUES(now(),%s,'history.apply',%s,'{\"retained\":true}')",
            (owner, DEP),
        )
        for source in ("launch_output", "terraform_state"):
            c.execute(
                "INSERT INTO deployment_resources VALUES(%s,'volume','vol-0123456789abcdef0',"
                "'i-0123456789abcdef0',%s,now())",
                (DEP, source),
            )
