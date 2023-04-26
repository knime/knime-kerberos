#!groovy
def BN = (BRANCH_NAME == 'master' || BRANCH_NAME.startsWith('releases/')) ? BRANCH_NAME : 'releases/2023-07'

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
                extraCredentials: [file(credentialsId: 'KNIME_KERBEROS_TEST_CONF', variable: 'KNIME_KERBEROS_TEST_CONF')],
                nodeType: 'maven', configurations: workflowTests.DEFAULT_FEATURE_BRANCH_CONFIGURATIONS
             )
        },
    )

    withEnv([ 'KNIME_POSTGRES_USER=knime01', 'KNIME_POSTGRES_PASSWORD=password',
            'KNIME_MSSQL_USER=SA', 'KNIME_MSSQL_PASSWORD=Knime_Password'
      ]) {
    workflowTests.runTests(
      dependencies: [
        repositories: [
          'knime-database',
          'knime-database-proprietary',
          'knime-kerberos',
          'knime-testing-internal',
          'knime-filehandling',
          'knime-jep',
          'knime-chemistry',
          'knime-python',
          'knime-stats',
          'knime-datageneration',
          'knime-pmml-translation',
          'knime-timeseries',
          'knime-distance',
          'knime-jfreechart',
          'knime-virtual',
          'knime-excel',
          'knime-js-base',
          'knime-ensembles',
          'knime-office365',
          'knime-expressions',
          'knime-streaming'
        ],
        ius: [
                    'org.knime.features.database.extensions.sqlserver.driver.feature.group'
                ]
      ],
      sidecarContainers: [
        [ image: "${dockerTools.ECR}/knime/jenkins-workflow-test-kerberos-postgresql:latest", namePrefix: 'POSTGRES', port: 5432,
            envArgs: ['POSTGRES_PASSWORD=password'],
            cExtraArgs: '-h pg.ad.testing.knime'
        ],
        [ image: "${dockerTools.ECR}/knime/jenkins-workflow-test-kerberos-mssql:latest", namePrefix: 'MSSQL', port: 1433,
          cExtraArgs: '-h mssqlserver.ad.testing.knime -p 1433:1433 --dns-search ad.testing.knime --dns 172.29.1.42 --add-host ec2amaz-r27ajvi.ad.testing.knime:172.29.1.42 --add-host ad.testing.knime:172.29.1.42 --add-host testing.knime:172.29.1.42 --add-host ad:172.29.1.42'
        ]
      ]
    )
  }

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
