Add ``--run-scope`` (and the ``run_scope`` and ``run_scope_approved`` core settings) so a run records the environments it
selected and the approvals it holds before tox provisions a newer version. The re-executed tox keeps exactly those
environments - its defaults, ``env_list`` and labels cannot add another one - and checks the record again before
preparing the tox environment and before each project command, so withdrawing an approval while the configuration is
read stops that command with a message saying how to continue. A run that needs no provisioning writes and checks the
same record, and every process appends its arguments, selection and launched command to ``run.scope.plan.ndjson`` next
to ``run.scope.json`` in the work directory.
