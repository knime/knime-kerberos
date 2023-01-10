#!groovy
def BN = (BRANCH_NAME == 'master' || BRANCH_NAME.startsWith('releases/')) ? BRANCH_NAME : 'releases/2023-03'

library "knime-pipeline@$BN"

properties([
    pipelineTriggers([
        upstream('knime-workbench/' + env.BRANCH_NAME.replaceAll('/', '%2F'))
    ]),
    parameters(workflowTests.getConfigurationsAsParameters()),
    buildDiscarder(logRotator(numToKeepStr: '5')),
    disableConcurrentBuilds()
])

try {
    parallel(
        'Tycho Build': {
            knimetools.defaultTychoBuild('org.knime.update.kerberos')
        },
        'Integrated Workflowtests': {
            workflowTests.runIntegratedWorkflowTests(profile: 'test', //
             extraCredentials: [file(credentialsId: 'KNIME_KERBEROS_TEST_CONF', variable: 'KNIME_KERBEROS_TEST_CONF')])
        },
    )

    stage('Sonarqube analysis') {
        env.lastStage = env.STAGE_NAME
        workflowTests.runSonar()
    }
} catch (ex) {
    currentBuild.result = 'FAILURE'
    throw ex
} finally {
    notifications.notifyBuild(currentBuild.result)
}

/* vim: set shiftwidth=4 expandtab smarttab: */
